"""Indoor Wi-Fi site survey (design-phase6 #16/#17): grid-tap, receive-only, own APs only.

Tables are written only by SurveyService, through the shared Store connection + lock; reads use
a separate read-only connection. Holds the "wifi" lane only (owner "survey"), never wardrive's.
"""
from __future__ import annotations

import csv
import io
import json
import statistics
import threading
import time
import uuid

from .wardrive import kismet_poll

SCHEMA = """
CREATE TABLE IF NOT EXISTS surveys (
    id TEXT PRIMARY KEY, name TEXT, started REAL, ended REAL, status TEXT,
    bssids TEXT, grid_w INTEGER, grid_h INTEGER
);
CREATE TABLE IF NOT EXISTS survey_cells (
    survey_id TEXT, bssid TEXT, x INTEGER, y INTEGER, n INTEGER, median_rssi REAL, ts REAL,
    PRIMARY KEY(survey_id, bssid, x, y)
);
"""

DWELL_S = 15.0
POLL_S = 2.0
MIN_SAMPLES = 3
WEAK_DBM = -70
GRID_MIN, GRID_MAX = 2, 40


class SurveyError(RuntimeError):
    pass


class SurveyService:
    def __init__(self, store, db_path, jobs, scope, hw, runner, clock=time.time,
                 sleep=time.sleep, mono=time.monotonic):
        self.store, self.db_path, self.jobs, self.scope = store, db_path, jobs, scope
        self.hw, self.runner = hw, runner
        self.clock, self.sleep, self.mono = clock, sleep, mono
        self._mu = threading.Lock()
        self._current = None        # {"id","bssids","w","h"}
        self._measuring = False
        with store._lock, store.cx:
            store.cx.executescript(SCHEMA)

    # ---- helpers -----------------------------------------------------------
    def _ro(self):
        import sqlite3
        cx = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=5)
        cx.row_factory = sqlite3.Row
        return cx

    def _query(self, sql, args=()):
        cx = self._ro()
        try:
            return [dict(r) for r in cx.execute(sql, args)]
        finally:
            cx.close()

    def _write(self, sql, args=()):
        with self.store._lock, self.store.cx:
            return self.store.cx.execute(sql, args)

    # ---- lifecycle ---------------------------------------------------------
    def start(self, name, bssids, grid_w=12, grid_h=12) -> str:
        targets = sorted({str(b).strip().lower() for b in (bssids or []) if str(b).strip()})
        if not targets:
            raise ValueError("bssids must be a non-empty list")
        allowed = {b.lower() for b in self.scope.bssids}
        bad = [b for b in targets if b not in allowed]
        if bad:
            raise ValueError(f"bssid not in scope (own APs only): {', '.join(bad)}")
        try:
            w, h = int(grid_w), int(grid_h)
        except (TypeError, ValueError):
            raise ValueError("grid must be integers")
        if not (GRID_MIN <= w <= GRID_MAX and GRID_MIN <= h <= GRID_MAX):
            raise ValueError(f"grid must be {GRID_MIN}..{GRID_MAX} in each dimension")
        with self._mu:
            if self._current is not None:
                raise SurveyError("a survey is already running")
            if not self.jobs.hold(["wifi"], owner="survey"):
                raise SurveyError("radio busy (scan, wardrive or sentry running)")
            sid = uuid.uuid4().hex[:16]
            try:
                self._write("INSERT INTO surveys(id,name,started,ended,status,bssids,grid_w,grid_h)"
                            " VALUES(?,?,?,?,?,?,?,?)",
                            (sid, str(name or "")[:80], self.clock(), None, "running",
                             json.dumps(targets), w, h))
            except Exception:
                self.jobs.release(["wifi"], owner="survey")
                raise
            self._current = {"id": sid, "bssids": targets, "w": w, "h": h}
            return sid

    def stop(self, status: str = "done"):
        with self._mu:
            cur = self._current
            if cur is None:
                return None
            self._write("UPDATE surveys SET ended=?, status=? WHERE id=?",
                        (self.clock(), status, cur["id"]))
            self._current = None
            self.jobs.release(["wifi"], owner="survey")
            return cur["id"]

    def abort_running(self) -> int:
        """Boot-time: mark leftover running surveys aborted (never touches the lane)."""
        cur = self._write("UPDATE surveys SET ended=?, status='aborted' WHERE status='running'",
                          (self.clock(),))
        return cur.rowcount

    # ---- measuring ---------------------------------------------------------
    def measure(self, x, y) -> dict:
        with self._mu:
            cur = self._current
            if cur is None:
                raise SurveyError("no survey running")
            try:
                x, y = int(x), int(y)
            except (TypeError, ValueError):
                raise ValueError("x and y must be integers")
            if not (0 <= x < cur["w"] and 0 <= y < cur["h"]):
                raise ValueError("cell outside the grid")
            if self._measuring:
                raise SurveyError("already measuring")
            self._measuring = True
        try:
            targets = cur["bssids"]
            samples = {b: [] for b in targets}
            last_ts = {b: None for b in targets}
            deadline = self.mono() + DWELL_S
            while True:
                raw = self.runner(kismet_poll.devices_argv(self.hw, since_s=5), 10)
                for d in kismet_poll.parse_devices(raw):
                    b = d["dev_id"]
                    if b not in samples or d["rssi"] is None or d["ts"] is None:
                        continue
                    if last_ts[b] is not None and d["ts"] <= last_ts[b]:
                        continue            # stale: Kismet has not heard it again
                    last_ts[b] = d["ts"]
                    samples[b].append(d["rssi"])
                if all(len(v) >= MIN_SAMPLES for v in samples.values()):
                    break
                if self.mono() + POLL_S > deadline:
                    break
                self.sleep(POLL_S)
            out, now = {}, self.clock()
            for b in targets:
                v = samples[b]
                if len(v) >= MIN_SAMPLES:
                    med = float(statistics.median(v))
                    out[b] = {"median": med, "n": len(v)}
                    self._write(
                        "INSERT INTO survey_cells(survey_id,bssid,x,y,n,median_rssi,ts)"
                        " VALUES(?,?,?,?,?,?,?) ON CONFLICT(survey_id,bssid,x,y) DO UPDATE SET"
                        " n=excluded.n, median_rssi=excluded.median_rssi, ts=excluded.ts",
                        (cur["id"], b, x, y, len(v), med, now))
                else:
                    out[b] = {"median": None, "n": len(v)}
            return out
        finally:
            with self._mu:
                self._measuring = False

    # ---- reads -------------------------------------------------------------
    def _get(self, survey_id):
        rows = self._query("SELECT * FROM surveys WHERE id=?", (survey_id,))
        if not rows:
            raise KeyError(survey_id)
        return rows[0]

    def heatmap(self, survey_id) -> dict:
        s = self._get(survey_id)
        cells = self._query("SELECT bssid,x,y,median_rssi,n FROM survey_cells WHERE survey_id=?"
                            " ORDER BY bssid,y,x", (survey_id,))
        return {"grid": [s["grid_w"], s["grid_h"]], "bssids": json.loads(s["bssids"] or "[]"),
                "cells": cells, "weak": [c for c in cells if c["median_rssi"] < WEAK_DBM]}

    def list(self) -> list:
        rows = self._query("SELECT * FROM surveys ORDER BY started DESC LIMIT 20")
        for r in rows:
            r["bssids"] = json.loads(r["bssids"] or "[]")
        return rows

    def delete(self, survey_id) -> bool:
        s = self._get(survey_id)
        if s["status"] == "running":
            raise SurveyError("survey is running; stop it first")
        with self.store._lock, self.store.cx:
            self.store.cx.execute("DELETE FROM survey_cells WHERE survey_id=?", (survey_id,))
            self.store.cx.execute("DELETE FROM surveys WHERE id=?", (survey_id,))
        return True

    def csv(self, survey_id) -> str:
        self._get(survey_id)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["bssid", "x", "y", "median_rssi", "n"])
        for c in self._query("SELECT bssid,x,y,median_rssi,n FROM survey_cells WHERE survey_id=?"
                             " ORDER BY bssid,y,x", (survey_id,)):
            w.writerow([c["bssid"], c["x"], c["y"], c["median_rssi"], c["n"]])
        return buf.getvalue()
