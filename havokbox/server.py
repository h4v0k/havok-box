"""Dashboard server: a thin Starlette shell over `Handlers`, which holds all the logic so it is
testable without the HTTP layer (Starlette/uvicorn are runtime deps on the Pi only).

Endpoints (all behind the bearer token):
  GET  /api/state
  POST /api/scan    {space, mode?}       -> 202 {job_id} | 200 needs_approval | 409 unavailable
  POST /api/mode    {mode}
  POST /api/approve {task_id, digest}    -> refused unless digest == the command shown
  POST /api/run     {task_id}            -> 409 "approve first" unless a matching approval exists
  GET  /api/jobs/{id}
  GET  /api/console                      -> console URL (enabled + box LAN + TLS only)
  /                                      -> static phone UI

Jobs run on one worker thread per lane (lane = signal space): one radio/NIC job at a time per
space, different spaces concurrently. One process, one worker, so the store stays the single
writer. The dashboard is the ONLY writer of approvals. There is no arbitrary-command endpoint;
the Console is the one explicit, logged escape hatch.
"""
from __future__ import annotations

import collections
import hmac
import os
import subprocess
import threading
import time

from .config import MODES, BoxConfig
from .store import new_id

SPACES = ("wired", "wifi", "ble", "subghz", "sdr", "sdr2", "radio", "mesh", "esp")
WARDRIVE_LANES = ("wifi", "ble", "esp", "sdr", "subghz")


class LaneHeld(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Job runner — one worker per lane
# ---------------------------------------------------------------------------
class Jobs:
    def __init__(self, store, history: int = 30, start: bool = True):
        self.store = store
        self.start = start
        self.lanes: dict[str, collections.deque] = {}
        self.recent = collections.deque(maxlen=history)
        self.running: dict[str, dict] = {}
        self.held: dict[str, str] = {}   # lane -> owner (wardrive, survey, ...)
        self._cv = threading.Condition()

    def hold(self, lanes, owner: str = "wardrive") -> bool:
        """Take lanes for an owner. False if any lane is busy, queued or held by anyone
        (Phase 6 #16: a survey must never share or release wardrive's radios)."""
        with self._cv:
            lanes = set(lanes)
            if any(ln in self.held for ln in lanes):
                return False
            if any(ln in self.running for ln in lanes) or any(self.lanes.get(ln) for ln in lanes):
                return False
            for ln in lanes:
                self.held[ln] = owner
            return True

    def release(self, lanes, owner: str = "wardrive") -> None:
        """Free only the lanes this owner holds."""
        with self._cv:
            for ln in set(lanes):
                if self.held.get(ln) == owner:
                    del self.held[ln]
            self._cv.notify_all()

    def submit(self, label: str, fn, lane: str = "default") -> dict:
        job = {"id": new_id(), "label": label, "lane": lane, "status": "queued",
               "submitted": time.time()}
        with self._cv:
            if lane in self.held:
                raise LaneHeld(lane)
            self.recent.appendleft(job)
            if lane not in self.lanes:
                self.lanes[lane] = collections.deque()
                if self.start:
                    threading.Thread(target=self._loop, args=(lane,), daemon=True,
                                     name=f"havokbox-jobs-{lane}").start()
            self.lanes[lane].append((job, fn))
            self._cv.notify_all()
        return job

    def pending(self) -> int:
        with self._cv:
            return sum(len(q) for q in self.lanes.values())

    def run_one(self, lane: str | None = None) -> bool:
        """Run the next job in `lane` (or any lane). Used by the lane loops and by tests."""
        with self._cv:
            for ln in ([lane] if lane else list(self.lanes)):
                q = self.lanes.get(ln)
                if q and ln in self.held:
                    # queued before a session took the lane: refuse it rather than run it
                    job, _ = q.popleft()
                    job["status"], job["detail"] = "refused", "wardrive running"
                    continue
                if q:
                    job, fn = q.popleft()
                    job["status"] = "running"
                    self.running[ln] = job
                    break
            else:
                return False
        try:
            res = fn() or {}
            job["status"] = res.get("status", "ok")
            job["detail"] = res.get("summary") or res.get("reason") or ""
        except Exception as exc:  # a job crash must not kill the worker
            job["status"], job["detail"] = "error", str(exc)
            self.store.log("error", f"job {job['label']}: {exc}")
        finally:
            job["finished"] = time.time()
            with self._cv:
                self.running.pop(job["lane"], None)
        return True

    def _loop(self, lane: str) -> None:
        while True:
            with self._cv:
                while not self.lanes[lane]:
                    self._cv.wait()
            self.run_one(lane)

    def get(self, job_id: str) -> dict | None:
        with self._cv:
            for j in self.recent:
                if j["id"] == job_id:
                    return dict(j)
        return None

    def snapshot(self) -> dict:
        with self._cv:
            return {"running": [dict(j) for j in self.running.values()],
                    "jobs": [dict(j) for j in self.recent]}


# ---------------------------------------------------------------------------
# Handlers — all the server logic, HTTP-free
# ---------------------------------------------------------------------------
class Handlers:
    def lane_for(self, space: str) -> str:
        """sdr2 is its own lane only with a second dongle; otherwise it IS the main SDR
        (one dongle can't be opened twice; wardrive/survey holds then apply)."""
        if space == "sdr2" and not (self.cfg.hardware().get("sdr2_serial") or ""):
            return "sdr"
        if space == "radio":            # ham/VHF/UHF receive uses the main dongle
            return "sdr"
        return space

    def __init__(self, api, cfg: BoxConfig, jobs: Jobs, publisher=None):
        self.api = api
        self.cfg = cfg
        self.jobs = jobs
        self.publisher = publisher

    # ---- auth -------------------------------------------------------------
    def authorized(self, auth_header: str | None, path: str = "/api/") -> bool:
        """Dashboard token reaches everything; the tablet's guard token only /api/guard/*."""
        if not auth_header or not auth_header.startswith("Bearer "):
            return False
        given = auth_header[7:].encode()
        if self.cfg.token and hmac.compare_digest(given, self.cfg.token.encode()):
            return True
        guard = getattr(self.cfg, "guard_token", "")
        return bool(guard) and path.startswith("/api/guard/") and \
            hmac.compare_digest(given, guard.encode())

    # ---- endpoints --------------------------------------------------------
    def state(self) -> tuple[int, dict]:
        st = self.api.state()
        st.update(self.jobs.snapshot())
        st["console_enabled"] = self.cfg.console_enabled_now()
        st["desktop_enabled"] = self.cfg.desktop_enabled_now()
        st["publish"] = self._publish_state()
        st["wardrive_running"] = bool(self._wd() and self._wd().running())
        return 200, st

    def _publish_state(self) -> dict:
        p = self.publisher
        if p is None or not p.enabled:
            return {"enabled": False}
        s = p.state()
        return {"enabled": True, "viewer_url": p.url + "/", "last_version": s.get("version"),
                "last_at": s.get("at"), "last_sha256": (s.get("sha256") or "")[:16],
                "pending": any(e["kind"] == "publish" for e in self.api.store.pending_queue())}

    def publish(self) -> tuple[int, dict]:
        """Report phase: publish a read-only snapshot. Queued first, so an offline box (or a failed
        push) publishes on reconnect via the drain loop."""
        from .publisher import publish_pending, request_publish
        if self.publisher is None or not self.publisher.enabled:
            return 409, {"status": "error", "reason": "publishing not configured"}
        request_publish(self.api.store)
        job = self.jobs.submit("Publish snapshot", lambda: publish_pending(self.api.store, self.publisher),
                               lane="publish")
        return 202, {"status": "queued", "job_id": job["id"]}

    def scan(self, body: dict) -> tuple[int, dict]:
        body = body or {}
        space = body.get("space")
        mode = body.get("mode") or self.api.mode
        if space not in SPACES:
            return 400, {"status": "error", "reason": f"unknown space: {space!r}"}
        if mode not in MODES:
            return 400, {"status": "error", "reason": f"unknown mode: {mode!r}"}
        action = body.get("action")
        if action is not None and not (isinstance(action, str) and action.isalpha() and len(action) <= 16):
            return 400, {"status": "error", "reason": "bad action"}
        try:
            prep = self.api.prepare_scan(space, mode, action)   # task + mode built HERE, not in the job
        except ValueError as exc:
            return 400, {"status": "error", "reason": str(exc)}
        if prep["status"] == "unavailable":
            return 409, prep
        if prep["status"] == "refused":
            return 403, prep
        if prep["status"] == "needs_approval":
            return 200, prep
        task = prep["task"]
        wd = self._wd()
        try:
            job = self.jobs.submit(f"{task['label']} [{mode}]", lambda: self.api.execute_scan(task),
                                   lane=self.lane_for(space))
        except LaneHeld:
            return 409, {"status": "error", "reason": "wardrive running: this radio is in use"}
        return 202, {"status": "queued", "job_id": job["id"]}

    def mode(self, body: dict) -> tuple[int, dict]:
        mode = (body or {}).get("mode")
        if mode not in MODES:
            return 400, {"status": "error", "reason": f"unknown mode: {mode!r}"}
        self.api.set_mode(mode)
        return 200, {"status": "ok", "mode": mode}

    @staticmethod
    def _str(body, key, maxlen=64) -> str | None:
        v = (body or {}).get(key)
        return v if isinstance(v, str) and 0 < len(v) <= maxlen else None

    def approve(self, body: dict) -> tuple[int, dict]:
        tid = self._str(body, "task_id")
        dg = self._str(body, "digest")
        if not tid or not dg:
            return 400, {"status": "error", "reason": "task_id and digest required"}
        res = self.api.approve(tid, dg)
        return {"not_found": 404, "stale": 409}.get(res["status"], 200), res

    def run(self, body: dict) -> tuple[int, dict]:
        tid = self._str(body, "task_id")
        if not tid:
            return 400, {"status": "error", "reason": "task_id required"}
        t = self.api._find_proposal(tid)
        if t is None:
            return 404, {"status": "not_found"}
        if self.api.needs_approval(t) and not self.api.approval_ok(tid):
            return 409, {"status": "error", "reason": "approve first"}   # nothing queued
        spec = self.api.registry.get(t.get("tool"))
        lane = self.lane_for(getattr(spec, "space", "") or "default")
        try:
            job = self.jobs.submit(t.get("label") or tid[:8], lambda: self.api.run(tid), lane=lane)
        except LaneHeld:
            return 409, {"status": "error", "reason": "wardrive running: this radio is in use"}
        return 202, {"status": "queued", "job_id": job["id"]}

    # ---- wardrive (receive-only) -------------------------------------------
    def _wd(self):
        return getattr(self, "wardrive", None)

    def wardrive_start(self, body: dict) -> tuple[int, dict]:
        wd = self._wd()
        if wd is None:
            return 404, {"status": "disabled"}
        note = (body or {}).get("note") or ""
        if not isinstance(note, str):
            return 400, {"status": "error", "reason": "note must be text"}
        from .wardrive.service import WardriveError
        try:
            sid = wd.start(note[:120])
        except WardriveError as exc:
            return 409, {"status": "error", "reason": str(exc)}
        return 200, {"status": "running", "session": sid}

    def wardrive_stop(self) -> tuple[int, dict]:
        wd = self._wd()
        if wd is None or not wd.running():
            return 409, {"status": "error", "reason": "no session running"}
        threading.Thread(target=wd.stop, daemon=True).start()   # collectors can take ~40 s to wind down
        return 202, {"status": "stopping"}

    def wardrive_ack(self, body: dict) -> tuple[int, dict]:
        wd = self._wd()
        aid = (body or {}).get("alert_id")
        if wd is None or not isinstance(aid, int) or isinstance(aid, bool):
            return 400, {"status": "error", "reason": "alert_id required"}
        wd.db.ack(aid)
        return 200, {"status": "ok"}

    def wardrive_delete(self, body: dict) -> tuple[int, dict]:
        wd = self._wd()
        sid = self._str(body, "session", 32)
        if wd is None or not sid:
            return 400, {"status": "error", "reason": "session required"}
        ok = wd.delete_session(sid)
        return (200, {"status": "deleted"}) if ok else (409, {"status": "error", "reason": "not found or running"})

    def wardrive_state(self, session: str | None = None) -> tuple[int, dict]:
        wd = self._wd()
        if wd is None:
            return 200, {"enabled": False}
        db = wd.db
        sessions = db.query("SELECT id, started, ended, status, distance_m, note, cells FROM "
                            "wardrive_sessions ORDER BY started DESC LIMIT 20")
        sid = session or wd.sid or (sessions[0]["id"] if sessions else None)
        out = {"enabled": True, "running": wd.running(), "session": sid, "sessions": sessions,
               "fix": wd.gps.fix() if wd.running() else None,
               "live_distance_m": wd.live_distance_m(), "notes": list(wd.notes)[:10],
               "rayhunter": getattr(self, "rayhunter", None),
               "exposure": wd.last_exposure,
               "drones": self._drones(wd)}
        if sid:
            track = db.query("SELECT ts, lat, lon, degraded FROM track WHERE session_id=? ORDER BY ts", (sid,))
            step = max(1, len(track) // 500)
            out["track"] = track[::step]
            out["devices"] = db.query(
                "SELECT radio, kind, MAX(name) AS name, MAX(best_rssi) AS best_rssi, COUNT(*) AS cells, "
                "MIN(first_ts) AS first_ts, MAX(last_ts) AS last_ts, AVG(lat) AS lat, AVG(lon) AS lon "
                "FROM device_cells WHERE session_id=? GROUP BY radio, dev_key ORDER BY "
                "CASE WHEN kind IN ('findmy_separated','google_dult','tile','smarttag','chipolo') THEN 0 ELSE 1 END, "
                "best_rssi DESC LIMIT 300", (sid,))
            out["alerts"] = db.query(
                "SELECT a.id, a.ts, a.kind, a.severity, a.dev_plain, a.detail, a.lat, a.lon, "
                "k.acked FROM alerts a LEFT JOIN alert_acks k ON k.alert_id=a.id "
                "WHERE a.session_id=? ORDER BY a.ts DESC LIMIT 200", (sid,))
            out["summary"] = db.query(
                "SELECT radio, COUNT(DISTINCT dev_key) AS devices FROM device_cells WHERE session_id=? "
                "GROUP BY radio", (sid,))
        return 200, out

    @staticmethod
    def _drones(wd) -> list:
        """Live drones without plaintext ids or the pilot's position (resolution #10). The UA id
        is shown only for a drone that raised an alert."""
        out = []
        alerted = set(wd.plain.values()) if wd.plain else set()
        for i, dr in enumerate((wd.drones.drones(time.time()) if wd.drones else [])[:50]):
            show = dr.get("addr") in alerted
            out.append({"label": dr.get("ua_id") if show and dr.get("ua_id") else f"Drone {i + 1}",
                        "lat": dr.get("lat"), "lon": dr.get("lon"), "alt": dr.get("alt"),
                        "speed": dr.get("speed"), "last_seen": dr.get("last_seen"),
                        "operator_known": dr.get("op_lat") is not None, "alerted": show})
        return out

    def wardrive_export(self, session: str | None, fmt: str | None):
        """Returns (code, payload) or (200, (bytes, filename, mimetype))."""
        import os
        import tempfile
        from .wardrive import export
        wd = self._wd()
        if wd is None or fmt not in ("wigle", "kml", "ble"):
            return 400, {"status": "error", "reason": "fmt must be wigle, kml or ble"}
        rows = wd.db.query("SELECT * FROM wardrive_sessions WHERE id=?", (session or "",))
        if not rows:
            return 404, {"status": "not_found"}
        s = rows[0]
        if fmt == "ble":
            cells = wd.db.query("SELECT dev_key AS dev_id, name, kind, kind AS tracker, first_ts AS first_seen, "
                                "last_ts AS last_seen, best_rssi, lat, lon FROM device_cells "
                                "WHERE session_id=? AND radio='ble'", (s["id"],))
            return 200, (export.ble_csv(cells).encode(), f"havokbox-{s['id']}-ble.csv", "text/csv")
        logs = wd.kismet_logs_for(s)      # the Kismet log(s) written during THIS drive
        if not logs:
            return 404, {"status": "error", "reason": "no Kismet log for this drive"}
        import shutil
        tmp = tempfile.mkdtemp(prefix="hbx-")
        try:
            out = os.path.join(tmp, "export")
            argv = export.wigle_argv(logs[0], out) if fmt == "wigle" else export.kml_argv(logs[0], out)
            wd.runner(argv, 120)
            try:
                with open(out, "rb") as fh:
                    data = fh.read()
            except OSError:
                return 500, {"status": "error", "reason": "export tool produced no file"}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)   # no plaintext copy left in /tmp
        name = f"havokbox-{s['id']}." + ("csv" if fmt == "wigle" else "kml")
        return 200, (data, name, "text/csv" if fmt == "wigle" else "application/vnd.google-earth.kml+xml")

    # ---- Kali pack: run any registered tool on a target (gated) --------------
    def run_tool(self, body) -> tuple[int, dict]:
        tool = self._str(body, "tool", 48)
        target = (body or {}).get("target")
        if not tool or (target is not None and not isinstance(target, dict)):
            return 400, {"status": "error", "reason": "tool and target{} required"}
        res = self.api.manual_tool(tool, target or {})
        code = {"unknown_tool": 404, "bad_params": 400, "refused": 403, "ok": 200}.get(res["status"], 400)
        return code, res

    def session_report(self) -> tuple[int, dict]:
        rep = getattr(self, "reporter", None)
        if rep is None:
            return 404, {"status": "disabled"}
        return 200, rep.generate()

    def session_report_latest(self) -> tuple[int, dict]:
        rep = getattr(self, "reporter", None)
        if rep is None:
            return 200, {"status": "disabled"}
        return 200, {"status": "ok", "report": rep.latest()}

    # ---- baseline drift ------------------------------------------------------
    def baseline_learn(self) -> tuple[int, dict]:
        return 200, {"status": "ok", "items": self.api.baseline_learn()}

    def baseline_accept(self, body) -> tuple[int, dict]:
        space = self._str(body, "space", 16)
        key = self._str(body, "key", 80)
        if not space or not key:
            return 400, {"status": "error", "reason": "space and key required"}
        ok = self.api.baseline_accept(space, key)
        return (200, {"status": "ok"}) if ok else (404, {"status": "not_found"})

    def baseline_forget(self) -> tuple[int, dict]:
        self.api.baseline_forget()
        return 200, {"status": "ok"}

    # ---- Wi-Fi site survey (indoor grid-tap, Phase 6 #16) ---------------------
    def survey_start(self, body) -> tuple[int, dict]:
        sv = getattr(self, "survey", None)
        if sv is None:
            return 404, {"status": "disabled"}
        from .survey import SurveyError
        b = body or {}
        name = b.get("name") or "survey"
        bssids = b.get("bssids")
        if not isinstance(name, str) or not isinstance(bssids, list) or \
                not all(isinstance(x, str) for x in bssids):
            return 400, {"status": "error", "reason": "name and bssids[] required"}
        try:
            sid = sv.start(name[:60], bssids, int(b.get("grid_w", 12)), int(b.get("grid_h", 12)))
        except (ValueError, TypeError) as exc:
            return 400, {"status": "error", "reason": str(exc)}
        except SurveyError as exc:
            return 409, {"status": "error", "reason": str(exc)}
        return 200, {"status": "running", "survey": sid}

    def survey_measure(self, body) -> tuple[int, dict]:
        sv = getattr(self, "survey", None)
        if sv is None:
            return 404, {"status": "disabled"}
        from .survey import SurveyError
        try:
            res = sv.measure(int((body or {}).get("x")), int((body or {}).get("y")))
        except (ValueError, TypeError) as exc:
            return 400, {"status": "error", "reason": str(exc)}
        except SurveyError as exc:
            return 409, {"status": "error", "reason": str(exc)}
        return 200, {"status": "ok", "result": res}

    def survey_stop(self) -> tuple[int, dict]:
        sv = getattr(self, "survey", None)
        if sv is None:
            return 404, {"status": "disabled"}
        sv.stop()
        return 200, {"status": "stopped"}

    def survey_state(self, survey_id=None) -> tuple[int, dict]:
        sv = getattr(self, "survey", None)
        if sv is None:
            return 200, {"enabled": False}
        surveys = sv.list()
        sid = survey_id or (surveys[0]["id"] if surveys else None)
        heat = None
        if sid:
            try:
                heat = sv.heatmap(sid)
            except KeyError:
                heat = None
        return 200, {"enabled": True, "surveys": surveys, "survey": sid, "heatmap": heat,
                     "bssids": sorted(self.api.scope.bssids)}

    def survey_delete(self, body) -> tuple[int, dict]:
        sv = getattr(self, "survey", None)
        sid = self._str(body, "survey", 40)
        if sv is None or not sid:
            return 400, {"status": "error", "reason": "survey required"}
        from .survey import SurveyError
        try:
            sv.delete(sid)
        except KeyError:
            return 404, {"status": "not_found"}
        except SurveyError as exc:
            return 409, {"status": "error", "reason": str(exc)}
        return 200, {"status": "deleted"}

    # ---- Drive Guard (tablet) ------------------------------------------------
    def guard_state(self, since) -> tuple[int, dict]:
        from .wardrive.service import phrase_for
        wd = self._wd()
        try:
            since = int(since or 0)
        except (TypeError, ValueError):
            since = 0
        if wd is None:
            return 200, {"mode": "idle", "status": "clear", "fix": {"mode": 0}, "can_touch": True,
                         "stationary_60s": True, "alerts": [], "recent": [], "alpr_near": None,
                         "alpr_session": 0, "offers": [], "server_ts": time.time()}
        fix = wd.gps.fix()
        rows = wd.db.query(
            "SELECT a.id, a.ts, a.kind, a.severity, a.detail, k.acked FROM alerts a "
            "LEFT JOIN alert_acks k ON k.alert_id=a.id WHERE a.session_id=? ORDER BY a.id DESC LIMIT 50",
            (wd.sid or "",)) if wd.sid else []
        def shape(r):
            return {"id": r["id"], "ts": r["ts"], "kind": r["kind"], "severity": r["severity"],
                    "phrase": phrase_for(r["kind"]), "detail": r["detail"], "acked": r["acked"] is not None}
        alerts = [shape(r) for r in rows if r["id"] > since]
        unacked_high = any(r["severity"] == "high" and r["acked"] is None for r in rows)
        near = wd.alpr_near if (wd.alpr_near and wd.mono() - wd.alpr_near["mono"] < 15) else None
        offers = [{"radio": o["radio"], "dev_key": o["dev_key"],
                   "label": "Looks like your car's tire sensor" if o["radio"] == "tpms" else "Your device?"}
                  for o in wd.db.offers()] if wd.can_touch() else []
        mode = wd.mode or "idle"
        return 200, {
            "mode": mode,
            "status": "alert" if unacked_high else ("sentry" if mode == "sentry" else "clear"),
            "fix": {"mode": fix.get("mode") or 0, "speed_mps": fix.get("speed"), "used": fix.get("used")},
            "can_touch": wd.can_touch(), "stationary_60s": wd.stationary_for() >= 60 or wd.no_fix_for() > 60,
            "alerts": alerts, "recent": [shape(r) for r in rows[:3]],
            "alpr_near": {"id": near["id"], "dist_m": near["dist_m"]} if near else None,
            "alpr_session": getattr(wd.alpr_warner, "passes", 0) if wd.alpr_warner else 0,
            "offers": offers, "server_ts": time.time(),
            "rayhunter": (getattr(self, "rayhunter", None) or {}).get("text")}

    def _guard_parked(self):
        wd = self._wd()
        if wd is None:
            return 404, {"status": "disabled"}
        if not wd.can_touch():
            return 409, {"status": "error", "reason": "park first"}   # server-side touch lock
        return None

    def guard_ack(self, body) -> tuple[int, dict]:
        blocked = self._guard_parked()
        if blocked:
            return blocked
        return self.wardrive_ack(body)

    def guard_sentry(self, body) -> tuple[int, dict]:
        blocked = self._guard_parked()
        if blocked:
            return blocked
        arm = (body or {}).get("arm")
        if not isinstance(arm, bool):
            return 400, {"status": "error", "reason": "arm must be true or false"}
        from .wardrive.service import WardriveError
        wd = self._wd()
        try:
            if arm:
                sid = wd.switch_mode("sentry") if wd.running() else wd.start(mode="sentry")
                return 200, {"status": "armed", "session": sid}
            if wd.running() and wd.mode == "sentry":
                threading.Thread(target=wd.stop, daemon=True).start()
            return 202, {"status": "disarming"}
        except WardriveError as exc:
            return 409, {"status": "error", "reason": str(exc)}

    def guard_mine(self, body) -> tuple[int, dict]:
        blocked = self._guard_parked()
        if blocked:
            return blocked
        radio = (body or {}).get("radio")
        key = self._str(body, "dev_key", 40)
        label = (body or {}).get("label") or ""
        if radio not in ("tpms", "ble", "wifi") or not key or not isinstance(label, str):
            return 400, {"status": "error", "reason": "radio, dev_key required"}
        offered = {(o["radio"], o["dev_key"]) for o in self._wd().db.offers()}
        if (radio, key) not in offered:
            return 403, {"status": "error", "reason": "only offered devices can be marked from the tablet"}
        self._wd().db.add_mine(radio, key, label[:60])
        return 200, {"status": "ok"}

    def alpr_refresh(self) -> tuple[int, dict]:
        wd = self._wd()
        if wd is None or not wd.alpr_path:
            return 404, {"status": "disabled"}
        from .wardrive.service import WardriveError
        try:
            n = wd.refresh_alpr()
        except Exception as exc:   # alpr.fetch raises RuntimeError on 3xx/429/oversize
            return 502, {"status": "error", "reason": f"{type(exc).__name__}: {str(exc)[:160]}"}
        return 200, {"status": "ok", "cameras": n}

    def job(self, job_id: str) -> tuple[int, dict]:
        j = self.jobs.get(job_id)
        return (200, j) if j else (404, {"status": "not_found"})

    def console(self, client_ip: str | None) -> tuple[int, dict]:
        if not self.cfg.console_enabled_now():
            return 404, {"status": "disabled"}
        if not self.cfg.on_lan(client_ip):
            self.api.store.log("refused", f"console requested from off-LAN {client_ip}")
            return 403, {"status": "forbidden", "reason": "console is box-LAN only"}
        if not self.cfg.console_password or not self.cfg.tls_ready():
            return 503, {"status": "error", "reason": "console needs console_password and TLS cert"}
        self.api.store.log("console", f"console link issued to {client_ip}")
        return 200, {"status": "ok", "url": f"https://{self.cfg.box_address}:{self.cfg.console_port}/"}

    def hardware(self) -> tuple[int, dict]:
        """Board-by-board check (read-only: lsusb, SDR EEPROM, gpsd, rflib import)."""
        from . import hwcheck
        inv = getattr(self.api, "inventory", None)
        return 200, {"rows": hwcheck.check(missing_tools=inv.missing if inv else None)}

    def desktop(self, client_ip: str | None) -> tuple[int, dict]:
        """Remote desktop (noVNC) link. Same guard posture as the Console: enabled, box-LAN, TLS."""
        if not self.cfg.desktop_enabled_now():
            return 404, {"status": "disabled"}
        if not self.cfg.on_lan(client_ip):
            self.api.store.log("refused", f"desktop requested from off-LAN {client_ip}")
            return 403, {"status": "forbidden", "reason": "desktop is box-LAN only"}
        if not self.cfg.tls_ready():
            return 503, {"status": "error", "reason": "desktop needs the TLS cert (run provision)"}
        if not self.cfg.desktop_password_set_now():
            return 503, {"status": "error",
                         "reason": "set desktop_vnc_password_set once the VNC password is configured"}
        self.api.store.log("desktop", f"desktop link issued to {client_ip}")
        # noVNC's own page prompts for the VNC password; scale=remote fits the Pi desktop to the tab.
        return 200, {"status": "ok",
                     "url": f"https://{self.cfg.box_address}:{self.cfg.desktop_port}/vnc.html"
                            "?autoconnect=true&resize=remote"}


# ---------------------------------------------------------------------------
# Real runner + wiring (Pi only)
# ---------------------------------------------------------------------------
def make_runner(timeout_s: float):
    def runner(cmd: list[str]) -> str:
        # argv list, never a shell string; built only by registered tools.
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
        return out.stdout
    return runner


def build(cfg: BoxConfig | None = None):
    """Wire the real box: store, scope, orchestrator, api, jobs, drainer."""
    from .api import Api
    from .commander import ApiCommander
    from .drain import Drainer
    from .orchestrator import Orchestrator
    from .scope import load_scope
    from .store import Store
    from .tools.registry import default_registry

    cfg = cfg or BoxConfig.load()
    store = Store(cfg.db_path)
    # Fail-closed even when started without the watchdog (manual run, bare systemd unit).
    n = store.void_unconsumed_approvals()
    store.log("server", f"start: voided {n} unconsumed approval(s)")
    scope = load_scope(cfg.scope_path)
    registry = default_registry()
    from .recipes import load_recipes
    from .scope import KNOWN as KNOWN_CATEGORIES
    for name, spec in load_recipes(cfg.recipes_path, KNOWN_CATEGORIES, log=store.log).items():
        registry.setdefault(name, spec)          # a recipe never shadows a built-in tool
    from .inventory import Inventory
    inventory = Inventory(registry)
    if inventory.missing:
        store.log("inventory", f"not installed: {', '.join(inventory.missing)}")
    orch = Orchestrator(scope, store, registry, make_runner(cfg.tool_timeout_s), hw=cfg.hardware())
    api = Api(scope, store, orch, mode=cfg.default_mode, gateway_ip=cfg.lab_gateway or None,
              pinned_static=cfg.pinned_static, inventory=inventory)
    jobs = Jobs(store)
    commander = ApiCommander(cfg.anthropic_api_key, cfg.commander_model,
                             cfg.commander_max_calls_per_day, registry,
                             counter_path=os.path.join(os.path.dirname(cfg.db_path), "commander-cap.json"))
    from .publisher import Publisher
    publisher = Publisher(store, cfg.publish_url, cfg.publish_token,
                          os.path.join(os.path.dirname(cfg.db_path), "publish-state.json"),
                          box=cfg.box_name, scope_name=getattr(scope, "name", ""),
                          evidence_limit=cfg.publish_evidence_limit)
    drainer = Drainer(store, commander, registry, scope, publisher=publisher)
    from .session_report import SessionReporter
    h_reporter = SessionReporter(store, commander)
    threading.Thread(target=drainer.run_forever, args=(cfg.drain_interval_s,),
                     daemon=True, name="havokbox-drain").start()
    h = Handlers(api, cfg, jobs, publisher=publisher)
    from .wardrive.db import WardriveDB, load_key
    from .wardrive.service import WardriveService
    data_dir = os.path.dirname(cfg.db_path)
    wdb = WardriveDB(store, cfg.db_path, load_key(os.path.join(data_dir, "secrets", "wardrive.key")))
    from .wardrive.notify import Discord
    from .mesh import Fanout, MeshOutbox
    # Alerts go to Discord (needs internet) and to your phone's Meshtastic node over LoRa (no internet)
    notifier = Fanout(Discord(cfg.discord_webhook, map_links=cfg.discord_map_links),
                      MeshOutbox(data_dir if cfg.hardware().get("mesh_owner") else None))
    h.reporter = h_reporter
    h.wardrive = WardriveService(wdb, jobs, orch, store, cfg.hardware(), scope=scope,
                                 mine=cfg.wardrive_mine, retention_days=cfg.wardrive_retention_days,
                                 notifier=notifier, alpr_path=cfg.alpr_path,
                                 quiet_zones=cfg.guard_quiet_zones)
    h.wardrive.boot()
    h.wardrive.load_alpr()
    # Rayhunter (fake cell tower detection), read-only poller (Phase 6 #4-#6)
    h.rayhunter = {"status": "off", "text": "Rayhunter not configured"}
    if cfg.rayhunter_url:
        from .rayhunter import RayhunterClient, RayhunterPoller
        try:
            poller = RayhunterPoller(RayhunterClient(cfg.rayhunter_url), time.time)
        except ValueError as exc:
            h.rayhunter = {"status": "error", "text": f"bad rayhunter_url: {exc}"}
            poller = None

        def ray_loop():
            while poller is not None:
                try:
                    res = poller.poll()
                    h.rayhunter = {"status": res.get("status"), "text": poller.status_text(),
                                   "version": res.get("version"), "at": time.time()}
                    wd = h.wardrive
                    for row in res.get("new") or []:
                        if wd.running():
                            sev = "high" if row.get("severity") == "high" else "medium"
                            wd._alert("cell_suspicious", sev,
                                      f"ray:{res.get('entry')}:{row.get('ts')}:{row.get('analyzer')}", None,
                                      f"Rayhunter: {str(row.get('message') or '')[:160]}")
                except Exception as exc:
                    h.rayhunter = {"status": "unreachable", "text": f"Rayhunter unreachable ({type(exc).__name__})"}
                time.sleep(60)
        threading.Thread(target=ray_loop, daemon=True, name="havokbox-rayhunter").start()
    from .survey import SurveyService
    h.survey = SurveyService(store, cfg.db_path, jobs, scope, cfg.hardware(),
                             runner=h.wardrive.runner)
    h.survey.abort_running()
    try:
        h.wardrive.start_gps()      # always-on GPS speed for the touch lock (receive-only)
    except Exception as exc:
        store.log("error", f"gps reader: {exc}")

    def flush_forever():   # phone alerts go out whenever the car hotspot is up (queue in RAM)
        while True:
            try:
                notifier.flush()
            except Exception:
                pass
            time.sleep(15)
    if notifier.enabled:
        threading.Thread(target=flush_forever, daemon=True, name="havokbox-notify").start()
    return h


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
                               "base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app(handlers: Handlers | None = None):
    from pathlib import Path

    from starlette.applications import Starlette
    from starlette.concurrency import run_in_threadpool
    from starlette.middleware import Middleware
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from starlette.staticfiles import StaticFiles

    h = handlers or build()

    class Guard(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.url.path.startswith("/api/") and not h.authorized(
                    request.headers.get("authorization"), request.url.path):
                resp = JSONResponse({"status": "unauthorized"}, status_code=401)
            else:
                resp = await call_next(request)
            resp.headers.update(SECURITY_HEADERS)
            return resp

    async def body(request: Request) -> dict:
        try:
            data = await request.json()
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    def reply(result):
        code, payload = result
        return JSONResponse(payload, status_code=code)

    async def get_state(request):
        return reply(h.state())

    async def post_scan(request):
        return reply(h.scan(await body(request)))

    async def post_mode(request):
        return reply(h.mode(await body(request)))

    async def post_approve(request):
        return reply(h.approve(await body(request)))

    async def post_run(request):
        return reply(h.run(await body(request)))

    async def get_job(request):
        return reply(h.job(request.path_params["job_id"]))

    async def wd_start(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.wardrive_start, b))

    async def wd_stop(request):
        return reply(await run_in_threadpool(h.wardrive_stop))

    async def wd_ack(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.wardrive_ack, b))

    async def wd_delete(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.wardrive_delete, b))

    async def wd_state(request):
        return reply(await run_in_threadpool(h.wardrive_state, request.query_params.get("session")))

    async def wd_export(request):
        from starlette.responses import Response
        code, payload = await run_in_threadpool(h.wardrive_export, request.query_params.get("session"),
                                                request.query_params.get("fmt"))
        if code != 200:
            return JSONResponse(payload, status_code=code)
        data, name, mime = payload
        return Response(data, media_type=mime,
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    async def guard_state(request):
        return reply(await run_in_threadpool(h.guard_state, request.query_params.get("since")))

    async def guard_ack(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.guard_ack, b))

    async def guard_sentry(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.guard_sentry, b))

    async def guard_mine(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.guard_mine, b))

    async def alpr_refresh(request):
        return reply(await run_in_threadpool(h.alpr_refresh))

    async def run_tool(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.run_tool, b))

    async def session_report(request):
        return reply(await run_in_threadpool(h.session_report))

    async def session_report_get(request):
        return reply(await run_in_threadpool(h.session_report_latest))

    async def bl_learn(request):
        return reply(await run_in_threadpool(h.baseline_learn))

    async def bl_accept(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.baseline_accept, b))

    async def bl_forget(request):
        return reply(await run_in_threadpool(h.baseline_forget))

    async def sv_start(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.survey_start, b))

    async def sv_measure(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.survey_measure, b))   # dwells up to 15 s

    async def sv_stop(request):
        return reply(await run_in_threadpool(h.survey_stop))

    async def sv_delete(request):
        b = await body(request)
        return reply(await run_in_threadpool(h.survey_delete, b))

    async def sv_state(request):
        return reply(await run_in_threadpool(h.survey_state, request.query_params.get("survey")))

    async def sv_csv(request):
        from starlette.responses import Response
        sv = getattr(h, "survey", None)
        sid = request.query_params.get("survey") or ""
        try:
            data = await run_in_threadpool(sv.csv, sid)
        except (KeyError, AttributeError):
            return JSONResponse({"status": "not_found"}, status_code=404)
        safe = "".join(c for c in sid if c.isalnum())[:32]
        return Response(data, media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="survey-{safe}.csv"'})

    async def post_publish(request):
        return reply(h.publish())

    async def get_console(request):
        return reply(h.console(request.client.host if request.client else None))

    async def get_hardware(request):
        return reply(await run_in_threadpool(h.hardware))   # shells out; can take ~20 s

    async def get_desktop(request):
        return reply(h.desktop(request.client.host if request.client else None))

    static = Path(__file__).parent / "static"
    routes = [
        Route("/api/state", get_state),
        Route("/api/scan", post_scan, methods=["POST"]),
        Route("/api/mode", post_mode, methods=["POST"]),
        Route("/api/approve", post_approve, methods=["POST"]),
        Route("/api/run", post_run, methods=["POST"]),
        Route("/api/jobs/{job_id}", get_job),
        Route("/api/console", get_console),
        Route("/api/desktop", get_desktop),
        Route("/api/hardware", get_hardware),
        Route("/api/publish", post_publish, methods=["POST"]),
        Route("/api/wardrive/start", wd_start, methods=["POST"]),
        Route("/api/wardrive/stop", wd_stop, methods=["POST"]),
        Route("/api/wardrive/ack", wd_ack, methods=["POST"]),
        Route("/api/wardrive/delete", wd_delete, methods=["POST"]),
        Route("/api/wardrive/state", wd_state),
        Route("/api/wardrive/export", wd_export),
        Route("/api/tool", run_tool, methods=["POST"]),
        Route("/api/session-report", session_report, methods=["POST"]),
        Route("/api/session-report", session_report_get),
        Route("/api/baseline/learn", bl_learn, methods=["POST"]),
        Route("/api/baseline/accept", bl_accept, methods=["POST"]),
        Route("/api/baseline/forget", bl_forget, methods=["POST"]),
        Route("/api/survey/start", sv_start, methods=["POST"]),
        Route("/api/survey/measure", sv_measure, methods=["POST"]),
        Route("/api/survey/stop", sv_stop, methods=["POST"]),
        Route("/api/survey/delete", sv_delete, methods=["POST"]),
        Route("/api/survey/state", sv_state),
        Route("/api/survey/csv", sv_csv),
        Route("/api/guard/state", guard_state),
        Route("/api/guard/ack", guard_ack, methods=["POST"]),
        Route("/api/guard/sentry", guard_sentry, methods=["POST"]),
        Route("/api/guard/mine", guard_mine, methods=["POST"]),
        Route("/api/alpr/refresh", alpr_refresh, methods=["POST"]),
        Mount("/", StaticFiles(directory=static, html=True)),
    ]
    return Starlette(routes=routes, middleware=[Middleware(Guard)])


def tls_args(cfg: BoxConfig) -> dict:
    """TLS fails closed (design-check #5)."""
    if cfg.tls_ready():
        return {"ssl_certfile": cfg.tls_cert, "ssl_keyfile": cfg.tls_key}
    if cfg.allow_insecure_http:
        return {}
    raise SystemExit(f"refusing to start: no TLS cert/key at {cfg.tls_cert} / {cfg.tls_key} "
                     "(run `python3 -m havokbox.provision`, or set allow_insecure_http: true)")


def main() -> None:  # pragma: no cover - Pi entry point
    import uvicorn

    cfg = BoxConfig.load()
    ssl = tls_args(cfg)
    uvicorn.run(create_app(build(cfg)), host="0.0.0.0", port=8443 if ssl else 8080,
                workers=1, log_level="warning", **ssl)


if __name__ == "__main__":  # pragma: no cover
    main()
