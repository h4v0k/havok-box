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

SPACES = ("wired", "wifi", "ble", "subghz", "sdr", "esp")
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
        self.held: set[str] = set()      # lanes owned by a wardrive session
        self._cv = threading.Condition()

    def hold(self, lanes) -> bool:
        """Take lanes for wardrive. False if any has a job running or queued (design #1)."""
        with self._cv:
            lanes = set(lanes)
            if any(ln in self.running for ln in lanes) or any(self.lanes.get(ln) for ln in lanes):
                return False
            self.held |= lanes
            return True

    def release(self, lanes) -> None:
        with self._cv:
            self.held -= set(lanes)
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
    def __init__(self, api, cfg: BoxConfig, jobs: Jobs, publisher=None):
        self.api = api
        self.cfg = cfg
        self.jobs = jobs
        self.publisher = publisher

    # ---- auth -------------------------------------------------------------
    def authorized(self, auth_header: str | None) -> bool:
        if not self.cfg.token:          # no token configured -> fail closed
            return False
        if not auth_header or not auth_header.startswith("Bearer "):
            return False
        return hmac.compare_digest(auth_header[7:].encode(), self.cfg.token.encode())

    # ---- endpoints --------------------------------------------------------
    def state(self) -> tuple[int, dict]:
        st = self.api.state()
        st.update(self.jobs.snapshot())
        st["console_enabled"] = self.cfg.console_enabled_now()
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
        try:
            job = self.jobs.submit(f"{task['label']} [{mode}]", lambda: self.api.execute_scan(task),
                                   lane=space)
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
        lane = getattr(spec, "space", "") or "default"
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
               "live_distance_m": wd.live_distance_m(), "notes": list(wd.notes)[:10]}
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
    orch = Orchestrator(scope, store, registry, make_runner(cfg.tool_timeout_s), hw=cfg.hardware())
    api = Api(scope, store, orch, mode=cfg.default_mode)
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
    threading.Thread(target=drainer.run_forever, args=(cfg.drain_interval_s,),
                     daemon=True, name="havokbox-drain").start()
    h = Handlers(api, cfg, jobs, publisher=publisher)
    from .wardrive.db import WardriveDB, load_key
    from .wardrive.service import WardriveService
    data_dir = os.path.dirname(cfg.db_path)
    wdb = WardriveDB(store, cfg.db_path, load_key(os.path.join(data_dir, "secrets", "wardrive.key")))
    h.wardrive = WardriveService(wdb, jobs, orch, store, cfg.hardware(), scope=scope,
                                 mine=cfg.wardrive_mine, retention_days=cfg.wardrive_retention_days)
    h.wardrive.boot()
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
                    request.headers.get("authorization")):
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

    async def post_publish(request):
        return reply(h.publish())

    async def get_console(request):
        return reply(h.console(request.client.host if request.client else None))

    static = Path(__file__).parent / "static"
    routes = [
        Route("/api/state", get_state),
        Route("/api/scan", post_scan, methods=["POST"]),
        Route("/api/mode", post_mode, methods=["POST"]),
        Route("/api/approve", post_approve, methods=["POST"]),
        Route("/api/run", post_run, methods=["POST"]),
        Route("/api/jobs/{job_id}", get_job),
        Route("/api/console", get_console),
        Route("/api/publish", post_publish, methods=["POST"]),
        Route("/api/wardrive/start", wd_start, methods=["POST"]),
        Route("/api/wardrive/stop", wd_stop, methods=["POST"]),
        Route("/api/wardrive/ack", wd_ack, methods=["POST"]),
        Route("/api/wardrive/delete", wd_delete, methods=["POST"]),
        Route("/api/wardrive/state", wd_state),
        Route("/api/wardrive/export", wd_export),
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
