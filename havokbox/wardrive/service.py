"""WardriveService — receive-only drive sessions (docs/design-wardrive.md + resolutions).

Start: hold the radio lanes (fails if a job is using them), void unconsumed approvals, switch the
orchestrator to passive-only, tell the Marauder `stopscan` (a killed deauth keeps transmitting
until it hears that), open the session row, start the GPS reader and the collector threads.
Stop (or watchdog shutdown): stop collectors and kill their process groups, close the session,
then release the lanes and the passive-only lock — in that order, so nothing active can slip in
while a radio is still listening.

Collectors (all recon.passive; pinned argv built by the tested modules):
- Kismet devices + alerts every 10 s (read-only key via header file; Kismet tags its own GPS)
- BLE: the Sniffle helper in 20 s windows (pcap deleted after parsing)
- RF floor: rtl_power sweeps every 60 s, recorded only
- Track: GPS fix → TrackRecorder (25 m / 10 s); "GNSS degraded" is a note, never an alert
- Follow-me: every 60 s over your stops in this + the previous 24 h of sessions
"""
from __future__ import annotations

import collections
import glob
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time

from ..store import new_id
from . import followme, geo, kismet_poll, rf_floor, trackers
from .db import CELL_CAP
from .gps import GpsReader, GpsState

KISMET_EVERY_S = 10
BLE_WINDOW_S = 20
RF_EVERY_S = 60
FOLLOW_EVERY_S = 60
START_GRACE_S = 120          # devices seen in the first 2 min are "present at start"
LANES = ("wifi", "ble", "esp", "sdr", "subghz")


class GroupRunner:
    """Runs collector argv in its own process group and remembers it, so Stop can kill the whole
    group (timeout -> sniff_receiver -> tshark), not just the helper (design #4)."""
    def __init__(self):
        self._procs: set = set()
        self._lock = threading.Lock()

    def __call__(self, argv: list[str], timeout: float) -> str:
        try:
            p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                 start_new_session=True)
        except OSError:
            return ""
        with self._lock:
            self._procs.add(p)
        try:
            out, _ = p.communicate(timeout=timeout)
            return out or ""
        except subprocess.TimeoutExpired:
            self._kill(p)
            return ""
        finally:
            with self._lock:
                self._procs.discard(p)

    @staticmethod
    def _kill(p) -> None:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(p.pid, sig)
            except (ProcessLookupError, PermissionError):
                return
            try:
                p.wait(timeout=3)
                return
            except subprocess.TimeoutExpired:
                continue

    def kill_all(self) -> None:
        with self._lock:
            procs = list(self._procs)
        for p in procs:
            self._kill(p)


default_runner = GroupRunner


class WardriveError(RuntimeError):
    pass


class WardriveService:
    def __init__(self, db, jobs, orch, store, hw: dict, scope=None, mine=(), runner=None,
                 popen=None, wall=time.time, mono=time.monotonic, gps_reader_factory=None,
                 retention_days: int = 7, clock_floor: float = 1_793_000_000,
                 notifier=None, alpr_path: str | None = None, quiet_zones=()):
        self.db, self.jobs, self.orch, self.store = db, jobs, orch, store
        self.hw, self.scope = hw, scope
        self.runner = runner if runner is not None else GroupRunner()
        # Wardrive never writes the evidence table (it is published, design #9): local notes only.
        self.notes = collections.deque(maxlen=50)
        self.wall, self.mono = wall, mono
        self.retention_days, self.clock_floor = retention_days, clock_floor
        self.gps = GpsState(clock=mono)
        self._reader_factory = gps_reader_factory or (
            lambda st: GpsReader(st, popen=popen or subprocess.Popen, clock=mono))
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.reader = None
        self.sid = None
        self.started_mono = None
        self.track = None
        self.plain: dict[str, str] = {}          # dev_key -> plaintext, RAM only (alerted devices)
        self.kinds: dict[str, str] = {}          # dev_key -> tracker class
        self.present_at_start: set[str] = set()
        mine_ids = {m.lower() for m in mine}
        if scope is not None:
            mine_ids |= set(scope.bssids) | set(scope.ble)
        self.mine_ids = mine_ids
        # ---- Drive Guard (Phase 5) ----
        self.mode = None                   # "drive" | "sentry" while running
        self.notifier = notifier
        self.alpr_path = alpr_path
        self.alpr_index = None
        self.alpr_warner = None
        self.alpr_near = None              # {"id","dist_m","mono"}
        self.quiet_zones = [z for z in quiet_zones if isinstance(z, dict)]
        self._recent_pts = collections.deque(maxlen=60)
        self._speed_hist = collections.deque(maxlen=120)   # (mono, speed or None)
        self._reset_guard()

    def _reset_guard(self):
        self.anchor = None
        self._anchor_fixes = []
        self._far_count = 0
        self._fast_since = None
        self._moved_alerted = False
        self._tracker_seen: dict[str, float] = {}       # sentry: tracker key -> first mono seen
        self._tpms_windows = 0
        self._tpms_heard: dict[str, int] = collections.Counter()
        self._last_floor = None
        self._sdr_i = 0

    # ---- lifecycle ---------------------------------------------------------
    def boot(self) -> None:
        """Server start: abort sessions left running, silence the Marauder, purge old drives."""
        n = self.db.abort_running(self.wall())
        if n:
            self._note(f"boot: {n} unfinished session(s) marked aborted")
        self._marauder_stop()
        self._clean_ble_scratch()
        self.purge()

    def live_distance_m(self) -> float:
        return self.track.distance_m if (self.sid and self.track) else 0.0

    def running(self) -> bool:
        return self.sid is not None

    def start(self, note: str = "", mode: str = "drive") -> str:
        if mode not in ("drive", "sentry"):
            raise WardriveError("mode must be drive or sentry")
        with self._lock:
            if self.sid is not None:
                raise WardriveError("a session is already running")
            if any(t.is_alive() for t in self._threads):
                raise WardriveError("the last drive is still shutting down; try again in a moment")
            if not self.jobs.hold(LANES):
                raise WardriveError("a scan is using the radios; wait for it to finish")
            try:
                self.store.void_unconsumed_approvals()
                self.orch.passive_only = True
                self._marauder_stop()
                sid = self.db.start_session(note, self.wall(), mode=mode)
            except Exception:
                self.orch.passive_only = False
                self.jobs.release(LANES)
                raise
            self.sid, self.started_mono = sid, self.mono()
            self._capping = False
            self.mode = mode
            self._reset_guard()
            self.alpr_warner = self._new_warner()
            self.track = geo.TrackRecorder()
            self.plain, self.kinds, self.present_at_start = {}, {}, set()
            self._stop.clear()
            try:
                self.reader = self._reader_factory(self.gps)
                self.reader.start()
            except Exception as exc:
                self.db.end_session(sid, "failed", 0, self.wall())
                self.sid, self.reader = None, None
                self.orch.passive_only = False
                self.jobs.release(LANES)
                raise WardriveError(f"GPS reader failed to start: {exc}")
            self._start_threads()
            self._note(f"session {sid} started (radios held, passive only)")
            return sid

    def _collectors(self):
        if self.mode == "sentry":   # power (Guard #9): BLE + GPS, a sparse TPMS check, sentry rules
            return ((self.tick_track, 1), (self.tick_ble, 0), (self.tick_sentry, 10),
                    (self.tick_sdr_sentry, 0))
        return ((self.tick_track, 1), (self.tick_kismet, KISMET_EVERY_S), (self.tick_ble, 0),
                (self.tick_sdr, 0), (self.tick_follow, FOLLOW_EVERY_S))

    def _start_threads(self):
        self._threads = [threading.Thread(target=self._loop, args=(fn, every), daemon=True,
                                          name=f"wardrive-{fn.__name__}")
                         for fn, every in self._collectors()]
        for t in self._threads:
            t.start()

    def _halt_collectors(self):
        """Stop collector threads and their process groups, but keep lanes + passive-only."""
        self._stop.set()
        kill = getattr(self.runner, "kill_all", None)
        if kill:
            kill()
        for t in self._threads:
            t.join(timeout=10)
        if any(t.is_alive() for t in self._threads) and kill:
            kill()
            for t in self._threads:
                t.join(timeout=10)
        return not any(t.is_alive() for t in self._threads)

    def switch_mode(self, mode: str, note: str = "") -> str:
        """Drive <-> sentry in place (Guard #5): end one row, start the next, radios stay held
        the whole time so no job can grab one in the gap."""
        with self._lock:
            if self.sid is None:
                raise WardriveError("no session running")
            if mode == self.mode:
                return self.sid
            if not self._halt_collectors():
                raise WardriveError("a collector is still stopping; try again in a moment")
            self._record_own_tpms()
            self.db.end_session(self.sid, "switched", self.track.distance_m if self.track else 0, self.wall())
            sid = self.db.start_session(note, self.wall(), mode=mode)
            self.sid, self.mode, self.started_mono = sid, mode, self.mono()
            self.track = geo.TrackRecorder()
            self.present_at_start = set()
            self._reset_guard()
            self.alpr_warner = self._new_warner()
            self._stop.clear()
            self._start_threads()
            self._note(f"switched to {mode}")
            return sid

    def stop(self, status: str = "stopped", sid: str | None = None) -> None:
        with self._lock:
            if self.sid is None or (sid is not None and sid != self.sid):
                return   # e.g. a late cap-stop must not end a newer session
            self._record_own_tpms()
            self._stop.set()
            if self.reader:
                self.reader.stop()
            kill = getattr(self.runner, "kill_all", None)
            if kill:
                kill()                         # whole process groups: Sniffle, tshark, rtl_power, curl
            for t in self._threads:
                t.join(timeout=10)
            if any(t.is_alive() for t in self._threads):
                if kill:
                    kill()
                for t in self._threads:
                    t.join(timeout=10)
            self._clean_ble_scratch()
            self.db.end_session(self.sid, status, self.track.distance_m if self.track else 0, self.wall())
            self._note(f"session {self.sid} {status}, "
                                       f"{(self.track.distance_m if self.track else 0) / 1000:.1f} km")
            alive = any(t.is_alive() for t in self._threads)
            self.sid, self.reader, self.mode, self.alpr_near = None, None, None, None
            if not alive:
                self._threads = []
                self.orch.passive_only = False      # only after every collector is down
                self.jobs.release(LANES)
            else:
                # A collector refused to die: keep the radios held and passive-only on; start()
                # refuses until it's gone. Logged so the operator knows why.
                self._note("a collector is still running; radios stay held until it exits")
                threading.Thread(target=self._release_when_down, daemon=True).start()
            self.purge()

    def _release_when_down(self) -> None:
        for t in self._threads:
            t.join()
        with self._lock:
            if self.sid is None:
                self._threads = []
                self.orch.passive_only = False
                self.jobs.release(LANES)

    def _loop(self, fn, every) -> None:
        while not self._stop.is_set():
            try:
                fn()
            except Exception as exc:          # a collector error must not end the drive
                self._note(f"{fn.__name__}: {exc}")
            if every:
                self._stop.wait(every)

    # ---- helpers -----------------------------------------------------------
    def _note(self, text: str) -> None:
        self.notes.appendleft({"ts": self.wall(), "text": str(text)[:200]})

    def _clean_ble_scratch(self) -> None:
        """Remove Sniffle pcaps a killed helper never got to delete (privacy #9)."""
        wd = self.hw.get("work_dir") or ""
        if not wd:
            return
        for d in glob.glob(os.path.join(wd, "ble_*")):
            shutil.rmtree(d, ignore_errors=True)

    def purge(self) -> int:
        """Retention for box tables AND Kismet's own logs (plaintext MACs), only with a set clock."""
        now, ok = self.wall(), self.wall() >= self.clock_floor
        n = self.db.purge(self.retention_days, now, ok)
        if ok:
            cutoff = now - self.retention_days * 86400
            for f in glob.glob(os.path.join(self.hw.get("kismet_log_dir") or "/nonexistent", "*.kismet*")):
                try:
                    if os.path.getmtime(f) < cutoff:
                        os.remove(f)
                except OSError:
                    pass
        return n

    def kismet_logs_for(self, session: dict) -> list[str]:
        start = session["started"]
        end = (session.get("ended") or self.wall()) + 3600
        out = []
        for f in glob.glob(os.path.join(self.hw.get("kismet_log_dir") or "/nonexistent", "*.kismet")):
            try:
                if start <= os.path.getmtime(f) <= end:
                    out.append(f)
            except OSError:
                pass
        return sorted(out, key=os.path.getmtime)

    def delete_session(self, sid: str) -> bool:
        rows = self.db.query("SELECT * FROM wardrive_sessions WHERE id=?", (sid,))
        if not rows or not self.db.delete_session(sid):
            return False
        for f in self.kismet_logs_for(rows[0]):
            for g in glob.glob(f + "*"):
                try:
                    os.remove(g)
                except OSError:
                    pass
        return True

    def _marauder_stop(self) -> None:
        self.runner([sys.executable, "-m", "havokbox.helpers.marauder", "stop",
                     "--port", self.hw.get("marauder_port", "")], 10)

    def _now(self, fix=None) -> float:
        fix = fix or self.gps.fix()
        return fix.get("ts") or self.wall()   # prefer GPS time (#8)

    def _early(self) -> bool:
        return self.mono() - (self.started_mono or 0) < START_GRACE_S

    def _obs(self, radio, kind, dev_id, rssi, lat, lon, ts, name=None, tclass=None):
        key = self.db.dev_key(radio, kind, dev_id)
        if tclass:
            self.kinds[key] = tclass
        self.plain[key] = dev_id.lower()
        if self._early():
            self.present_at_start.add(key)
        return {"radio": radio, "dev_key": key, "ts": ts, "rssi": rssi, "lat": lat, "lon": lon,
                "cell": geo.cell_id(lat, lon) if lat is not None and lon is not None else "nofix",
                "name": name if (radio == "wifi" and kind == "ap") else None,   # privacy (#9)
                "kind": tclass or kind}

    def _store_obs(self, obs) -> None:
        if not obs or self.sid is None:
            return
        sid = self.sid
        if self.db.add_cells(sid, obs) >= CELL_CAP and not getattr(self, "_capping", False):
            self._capping = True
            self._alert("cap", "high", None, None, f"session reached {CELL_CAP} rows; collection stopped")
            threading.Thread(target=self.stop, kwargs={"status": "capped", "sid": sid}, daemon=True).start()

    def _alert(self, kind, severity, dev_key, dev_plain, detail, fix=None) -> bool:
        fix = fix or self.gps.fix()
        ts = self._now(fix)
        new = self.db.add_alert(self.sid, ts, kind, severity, dev_key or "-", dev_plain, detail,
                                fix.get("lat"), fix.get("lon"), kismet_poll.alert_bucket(ts))
        if new and self.notifier is not None and getattr(self.notifier, "enabled", False) and \
                (severity == "high" or self.mode == "sentry"):
            try:
                self.notifier.send(f"{kind}:{dev_key}", kind, severity, f"{phrase_for(kind)} — {detail}",
                                   ts, fix.get("lat"), fix.get("lon"))
            except Exception as exc:
                self._note(f"notify: {type(exc).__name__}")
        return new

    def _quiet(self, fix) -> bool:
        if fix.get("lat") is None:
            return False
        return any(geo.haversine_m(fix["lat"], fix["lon"], z.get("lat", 0), z.get("lon", 0))
                   <= float(z.get("radius_m", 200)) for z in self.quiet_zones)

    # ---- collectors --------------------------------------------------------
    def tick_track(self) -> None:
        fix = self.gps.fix()
        self._speed_hist.append((self.mono(), fix.get("speed") if (fix.get("mode") or 0) >= 2 else None))
        if fix.get("lat") is None or (fix.get("mode") or 0) < 2:
            return
        self._recent_pts.append((fix["lat"], fix["lon"]))
        if self.mode == "drive" and self.alpr_warner is not None:
            hit = self.alpr_warner.update(self._now(fix), fix["lat"], fix["lon"], fix.get("speed") or 0,
                                          fix.get("track"), list(self._recent_pts))
            if hit:
                self.alpr_near = {"id": str(hit["id"]), "dist_m": int(hit["dist_m"]), "mono": self.mono()}
        p = self.track.offer(self._now(fix), fix["lat"], fix["lon"], fix.get("mode"))
        if p:
            self.db.add_track(self.sid, p["ts"], p["lat"], p["lon"], p["fixq"], fix.get("degraded"))

    def tick_kismet(self) -> None:
        fix = self.gps.fix()
        obs = []
        for d in kismet_poll.parse_devices(self.runner(kismet_poll.devices_argv(self.hw), 15)):
            if not d.get("dev_id"):
                continue
            # Where WE are now (Kismet's location is a lifetime average) and OUR time base, so
            # Wi-Fi observations line up with the track and stops (review #3, #4).
            obs.append(self._obs("wifi", d.get("kind"), d["dev_id"], d.get("rssi"), fix.get("lat"),
                                 fix.get("lon"), self._now(fix), name=d.get("name")))
        self._store_obs(obs)
        for a in kismet_poll.parse_alerts(self.runner(kismet_poll.alerts_argv(self.hw), 15)):
            dev = a.get("dev_id")
            self._alert(a["kind"], a.get("severity", "medium"), dev, dev, a.get("detail"), fix)

    def tick_ble(self) -> None:
        argv = [sys.executable, "-m", "havokbox.helpers.ble_scan", "--sniffle-dir",
                self.hw.get("sniffle_dir", ""), "--port", self.hw.get("sniffle_port", ""),
                "--seconds", str(BLE_WINDOW_S), "--work-dir", self.hw.get("work_dir", "")]
        out = self.runner(argv, BLE_WINDOW_S + 30)
        try:
            devices = json.loads(out).get("devices", []) if out else []
        except (ValueError, AttributeError):
            devices = []
        fix = self.gps.fix()
        ts = self._now(fix)
        self._store_obs([self._obs("ble", None, d["addr"], d.get("rssi"), fix.get("lat"), fix.get("lon"),
                                   ts, tclass=trackers.classify(d))
                         for d in devices if d.get("addr")])
        if not devices:
            self._stop.wait(5)   # no dongle / no output: don't spin

    def tick_rf(self) -> None:
        fix = self.gps.fix()
        for band in rf_floor.BANDS:
            if self._stop.is_set():
                return
            m = rf_floor.parse_medians(self.runner(rf_floor.sweep_argv(band), 30))
            if m.get("median_db") is not None:
                self.db.add_rf(self.sid, self._now(fix), band, m["median_db"], fix.get("lat"), fix.get("lon"))

    # ---- SDR owner (Guard #11): one thread, TPMS windows + a floor sweep every 10 min ----
    def _tpms_window(self, seconds: int = 50) -> list:
        from . import tpms
        freq = tpms.FREQS[self._sdr_i % len(tpms.FREQS)]
        self._sdr_i += 1
        return tpms.parse_window(self.runner(tpms.window_argv(freq, seconds), seconds + 15))

    def _store_tpms(self, recs) -> None:
        fix = self.gps.fix()
        ts = self._now(fix)
        self._tpms_windows += 1
        obs = []
        for r in recs:
            key_plain = f"{r['model']}:{r['id']}"
            o = self._obs("tpms", "tpms", key_plain, r.get("rssi"), fix.get("lat"), fix.get("lon"), ts)
            self._tpms_heard[o["dev_key"]] += 1
            obs.append(o)
        self._store_obs(obs)

    def tick_sdr(self) -> None:
        if self._last_floor is None or self.mono() - self._last_floor >= 600:
            self._last_floor = self.mono()
            self.tick_rf()
        if not self._stop.is_set():
            self._store_tpms(self._tpms_window(50))

    def tick_sdr_sentry(self) -> None:
        recs = self._tpms_window(30)
        mine = {k for (r, k) in self.db.mine_keys() if r == "tpms"}
        heard = {self.db.dev_key("tpms", "tpms", f"{r['model']}:{r['id']}") for r in recs}
        if mine & heard:   # your own tires transmitting = wheels turning (Guard #6)
            self._car_moved("your tire sensors woke up — the wheels are turning")
        self._stop.wait(270)

    def _record_own_tpms(self) -> None:
        """Offer sensors heard in >=80 % of TPMS windows over >=5 km as 'your tires' (Guard #12)."""
        if self.mode != "drive" or not self.sid or not self.track or self.track.distance_m < 5000:
            return
        if self._tpms_windows < 5:
            return
        for key, n in self._tpms_heard.items():
            if n / self._tpms_windows >= 0.8:
                self.db.add_candidate("tpms", key, self.sid)

    # ---- sentry (Guard #6, #7) ------------------------------------------------
    def _car_moved(self, why: str) -> None:
        if not self._moved_alerted:
            self._moved_alerted = True
            self._alert("car_moved", "high", "car", None, why)

    def tick_sentry(self) -> None:
        fix = self.gps.fix()
        now = self.mono()
        good = fix.get("lat") is not None and (fix.get("mode") or 0) >= 2
        if self.anchor is None:
            if good:
                self._anchor_fixes.append((fix["lat"], fix["lon"]))
            if now - self.started_mono >= 120 and self._anchor_fixes:
                lats = sorted(p[0] for p in self._anchor_fixes)
                lons = sorted(p[1] for p in self._anchor_fixes)
                self.anchor = (lats[len(lats) // 2], lons[len(lons) // 2])
        elif good:
            d = geo.haversine_m(self.anchor[0], self.anchor[1], fix["lat"], fix["lon"])
            limit = max(75.0, 3 * (fix.get("eph") or 0))
            self._far_count = self._far_count + 1 if d > limit else 0
            if self._far_count >= 3:
                self._car_moved(f"the car is {int(d)} m from where it was parked")
            spd = fix.get("speed") or 0
            if spd > 2:
                self._fast_since = self._fast_since or now
                if now - self._fast_since >= 10:
                    self._car_moved("the car is moving")
            else:
                self._fast_since = None
        if self._quiet(fix):
            return   # home/work: only car-moved alerts
        # trackers held near the car >= 10 min with RSSI > -75
        rows = self.db.query("SELECT dev_key, kind, MAX(best_rssi) AS rssi, MIN(first_ts) AS first, "
                             "MAX(last_ts) AS last FROM device_cells WHERE session_id=? AND radio='ble' "
                             "AND kind IN ('findmy_separated','google_dult','tile','smarttag','chipolo') "
                             "GROUP BY dev_key", (self.sid,))
        for r in rows:
            if (r["rssi"] or -999) > -75 and (r["last"] - r["first"]) >= 600:
                self._alert("sentry_tracker", "high", r["dev_key"], self.plain.get(r["dev_key"]),
                            f"{TRACKER_NAMES.get(r['kind'], 'A tracker')} has been near the car for "
                            f"{int((r['last'] - r['first']) // 60)} min")

    # ---- ALPR -------------------------------------------------------------------
    def load_alpr(self) -> int:
        from . import alpr
        cams = alpr.load(self.alpr_path) if self.alpr_path else []
        self.alpr_index = alpr.Index(cams) if cams else None
        return len(cams)

    def _new_warner(self):
        if self.alpr_index is None:
            return None
        from . import alpr
        return alpr.Warner(self.alpr_index)

    def refresh_alpr(self, bbox=None, transport=None) -> int:
        from . import alpr
        bbox = bbox or alpr.DEFAULT_BBOX
        cams = alpr.validate(alpr.fetch(bbox, transport=transport), bbox)
        if not cams:
            raise WardriveError("no cameras returned; kept the previous copy")
        alpr.save_atomic(self.alpr_path, cams)
        return self.load_alpr()

    # ---- guard state ---------------------------------------------------------------
    def stationary_for(self) -> float:
        """Seconds the box has been below 1.5 m/s with a fix (0 if moving)."""
        now = self.mono()
        t = 0.0
        for m, spd in reversed(self._speed_hist):
            if spd is None or spd >= 1.5:
                break
            t = now - m
        return t

    def no_fix_for(self) -> float:
        fix = self.gps.fix()
        if (fix.get("mode") or 0) >= 2:
            return 0.0
        last_good = next((m for m, s in reversed(self._speed_hist) if s is not None), None)
        return self.mono() - last_good if last_good is not None else float("inf")

    def can_touch(self) -> bool:
        """Server-side touch lock (Guard #3): stationary >= 5 s, or no fix for > 60 s."""
        return self.stationary_for() >= 5 or self.no_fix_for() > 60

    def tick_follow(self) -> None:
        since = self._now() - 24 * 3600
        pts = self.db.query("SELECT ts, lat, lon FROM track WHERE ts >= ? AND session_id IN "
                            "(SELECT id FROM wardrive_sessions WHERE COALESCE(ended, ?) >= ?) ORDER BY ts",
                            (since, self._now(), since))
        stops = geo.find_stops(pts)
        if len(stops) < 2:
            return
        sessions = [r["id"] for r in self.db.query(
            "SELECT id FROM wardrive_sessions WHERE COALESCE(ended, ?) >= ?", (self._now(), since))]
        rows = []
        for sess in sessions:   # PK(session_id, ...) prefix: an index range, not a table scan
            rows += self.db.query("SELECT radio, dev_key, kind, first_ts, last_ts, best_rssi, lat, lon "
                                  "FROM device_cells WHERE session_id=? AND last_ts >= ? AND lat IS NOT NULL "
                                  "AND (kind IS NULL OR kind != 'ap')", (sess, since))
        by_dev: dict[str, dict] = {}
        for r in rows:
            d = by_dev.setdefault(r["dev_key"], {"kind": self.kinds.get(r["dev_key"]) or
                                                 (r["kind"] if r["kind"] in TRACKER_KINDS else None),
                                                 "radio": r["radio"], "obs": []})
            for ts in (r["first_ts"], r["last_ts"]):
                d["obs"].append({"ts": ts, "lat": r["lat"], "lon": r["lon"], "rssi": r["best_rssi"]})
        mine = {self.db.dev_key("ble", None, m) for m in self.mine_ids} | \
               {self.db.dev_key("wifi", "client", m) for m in self.mine_ids} | \
               {k for (_, k) in self.db.mine_keys()}
        for a in followme.assess(stops, by_dev, mine=mine, present_at_start=self.present_at_start):
            if by_dev.get(a["dev_key"], {}).get("radio") == "tpms":
                # TPMS range is 10-50 m and sensors are shared by every car: medium at most (#10)
                self._alert("follow_tpms", "medium", a["dev_key"], None,
                            f"A car's tire sensors were at {a['stops_matched']} of your stops "
                            f"{a['span_m'] / 1000:.1f} km apart")
                continue
            what = TRACKER_NAMES.get(a.get("tracker"), "A device")
            detail = (f"{what} seen at {a['stops_matched']} of your stops "
                      f"{a['span_m'] / 1000:.1f} km apart"
                      + (" (was nearby when the drive started — confirm if it's yours)"
                         if a.get("present_at_start") else ""))
            self._alert("follow", a["severity"], a["dev_key"], self.plain.get(a["dev_key"]), detail)


TRACKER_KINDS = {"findmy_separated", "google_dult", "tile", "smarttag", "chipolo"}

PHRASES = {   # spoken on the tablet: 6 words or fewer (Guard #1)
    "follow": "Device following you",
    "follow_tpms": "Car may be following you",
    "car_moved": "Your car is moving",
    "sentry_tracker": "Tracker near your car",
    "cap": "Drive log is full",
}


def phrase_for(kind: str) -> str:
    if kind in PHRASES:
        return PHRASES[kind]
    return "Wi-Fi attack nearby"   # Kismet attack headers (DEAUTHFLOOD, BCASTDISCON, ...)
TRACKER_NAMES = {
    "findmy_separated": "AirTag / Find My tracker (away from its owner)",
    "google_dult": "Google Find My Device tracker",
    "tile": "Tile tracker",
    "smarttag": "Samsung SmartTag",
    "chipolo": "Chipolo tracker",
}
