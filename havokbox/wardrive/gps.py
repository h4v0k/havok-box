"""gpsd reader for wardrive. Receive-only."""
import calendar
import json
import os
import signal
import statistics
import subprocess
import threading
import time
from collections import deque

# gpsd itself is configured `-b` (read-only) on the Pi; gpspipe only watches its JSON.
GPSPIPE_ARGV = ["gpspipe", "-w"]


def _parse_time(s):
    if not isinstance(s, str):
        return None
    try:
        base = s.rstrip("Z")
        frac = 0.0
        if "." in base:
            base, f = base.split(".", 1)
            frac = float("0." + f)
        return calendar.timegm(time.strptime(base, "%Y-%m-%dT%H:%M:%S")) + frac
    except (ValueError, OverflowError):
        return None


def _num(v):
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def parse_line(line):
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    cls = obj.get("class")
    if cls == "TPV":
        mode = obj.get("mode")
        return {"class": "TPV", "ts": _parse_time(obj.get("time")),
                "lat": _num(obj.get("lat")), "lon": _num(obj.get("lon")),
                "mode": mode if isinstance(mode, int) and 0 <= mode <= 3 else 0,
                "speed": _num(obj.get("speed")),
                "eph": _num(obj.get("eph")),      # horizontal error estimate (m)
                "track": _num(obj.get("track"))}  # course over ground (deg true)
    if cls == "SKY":
        sats = obj.get("satellites")
        used, snrs = 0, []
        if isinstance(sats, list):
            for s in sats:
                if isinstance(s, dict) and s.get("used") is True:
                    used += 1
                    ss = _num(s.get("ss"))
                    if ss is not None:
                        snrs.append(ss)
        elif isinstance(obj.get("uSat"), int):
            used = obj["uSat"]
        return {"class": "SKY", "used": used,
                "snr_mean": (sum(snrs) / len(snrs)) if snrs else None}
    return None


class GpsState:
    WINDOW_S = 60.0

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._fix = {"ts": None, "lat": None, "lon": None, "mode": 0, "speed": None}
        self._used = None
        self._snr = None
        self._last3d = None
        self._snr_hist = deque()  # (t, snr)

    def update(self, parsed):
        if not parsed:
            return
        now = self._clock()
        with self._lock:
            if parsed.get("class") == "TPV":
                self._fix = {k: parsed.get(k) for k in ("ts", "lat", "lon", "mode", "speed", "eph", "track")}
                self._fix["mono"] = now
                if parsed.get("mode") == 3:
                    self._last3d = now
            elif parsed.get("class") == "SKY":
                self._used = parsed.get("used")
                self._snr = parsed.get("snr_mean")
                if self._snr is not None:
                    self._snr_hist.append((now, self._snr))
                while self._snr_hist and now - self._snr_hist[0][0] > self.WINDOW_S:
                    self._snr_hist.popleft()

    def mark_no_fix(self):
        with self._lock:
            self._fix = {"ts": None, "lat": None, "lon": None, "mode": 0, "speed": None,
                         "eph": None, "track": None, "mono": self._clock()}

    def fix(self):
        now = self._clock()
        with self._lock:
            out = dict(self._fix)
            out["used"] = self._used
            out["snr_mean"] = self._snr
            degraded = False
            if self._last3d is not None and now - self._last3d <= self.WINDOW_S:
                if self._used is not None and self._used <= 2:
                    degraded = True
                elif self._snr is not None:
                    base = [s for (t, s) in self._snr_hist if now - t <= self.WINDOW_S]
                    if len(base) >= 3 and statistics.median(base) - self._snr >= 10:
                        degraded = True
            out["degraded"] = degraded
            return out


class GpsReader:
    def __init__(self, state, popen=subprocess.Popen, clock=time.monotonic):
        self.state = state
        self._popen = popen
        self._clock = clock
        self._proc = None
        self._thread = None

    def start(self):
        if self._proc is not None:
            return
        self._proc = self._popen(GPSPIPE_ARGV, stdout=subprocess.PIPE, text=True,
                                 start_new_session=True)
        self._thread = threading.Thread(target=self._run, args=(self._proc,), daemon=True)
        self._thread.start()

    def _run(self, proc):
        try:
            for line in proc.stdout:
                try:
                    self.state.update(parse_line(line))
                except Exception:
                    continue
        except Exception:
            pass
        finally:
            self.state.mark_no_fix()

    def stop(self):
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        self.state.mark_no_fix()
