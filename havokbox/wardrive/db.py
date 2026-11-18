"""Wardrive storage (design-wardrive.md resolutions #4-#9).

Tables live in the box DB but are written ONLY by the WardriveService (alert acks only by the
dashboard). Writes go through the shared Store connection + lock as one batched transaction;
heavy reads (Drive tab, follow-me) use a separate read-only connection so they never take the
write lock.

Privacy: client and BLE identifiers are stored as a keyed HMAC (key lives on the box, 0600);
plaintext is kept only for access points and for devices that raised an alert. Nothing here is
published, and nothing here writes evidence or findings.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS wardrive_sessions (
    id TEXT PRIMARY KEY, started REAL, ended REAL, status TEXT, distance_m REAL DEFAULT 0,
    note TEXT, cells INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS wd_one_running ON wardrive_sessions(status) WHERE status='running';
CREATE TABLE IF NOT EXISTS device_cells (
    session_id TEXT, radio TEXT, dev_key TEXT, cell TEXT, first_ts REAL, last_ts REAL,
    n INTEGER, best_rssi REAL, lat REAL, lon REAL, name TEXT, kind TEXT,
    PRIMARY KEY(session_id, radio, dev_key, cell)
);
CREATE INDEX IF NOT EXISTS wd_cells_dev ON device_cells(radio, dev_key, last_ts);
CREATE TABLE IF NOT EXISTS track (
    session_id TEXT, ts REAL, lat REAL, lon REAL, fixq INTEGER, degraded INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS wd_track ON track(session_id, ts);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, ts REAL, kind TEXT, severity TEXT,
    dev_key TEXT, dev_plain TEXT, detail TEXT, lat REAL, lon REAL, bucket INTEGER,
    UNIQUE(session_id, kind, dev_key, bucket)
);
CREATE INDEX IF NOT EXISTS wd_alerts ON alerts(session_id, ts);
CREATE TABLE IF NOT EXISTS alert_acks (alert_id INTEGER PRIMARY KEY, acked REAL);
CREATE TABLE IF NOT EXISTS wardrive_mine (
    radio TEXT, dev_key TEXT, label TEXT, added REAL, PRIMARY KEY(radio, dev_key)
);
CREATE TABLE IF NOT EXISTS mine_candidates (
    radio TEXT, dev_key TEXT, session_id TEXT, PRIMARY KEY(radio, dev_key, session_id)
);
CREATE TABLE IF NOT EXISTS rf_floor (
    session_id TEXT, ts REAL, band TEXT, median_db REAL, lat REAL, lon REAL
);
"""

CELL_CAP = 300_000
BATCH = 500
CHILD_TABLES = ("device_cells", "track", "alerts", "rf_floor")


def load_key(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            k = fh.read()
        if len(k) >= 32:
            return k
    except OSError:
        pass
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    k = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(k)
    return k


class WardriveDB:
    def __init__(self, store, db_path: str, key: bytes):
        self.store = store            # shared writer connection + lock
        self.db_path = db_path
        self.key = key
        with store._lock, store.cx:
            store.cx.executescript(SCHEMA)
            cols = {r[1] for r in store.cx.execute("PRAGMA table_info(wardrive_sessions)")}
            if "mode" not in cols:   # migration (Drive Guard #5): CREATE IF NOT EXISTS won't add it
                store.cx.execute("ALTER TABLE wardrive_sessions ADD COLUMN mode TEXT DEFAULT 'drive'")

    # ---- identifiers -------------------------------------------------------
    def dev_key(self, radio: str, kind: str | None, dev_id: str) -> str:
        dev_id = (dev_id or "").lower()
        if radio == "wifi" and kind == "ap":
            return dev_id                                   # APs are public infrastructure
        return "h:" + hmac.new(self.key, f"{radio}:{dev_id}".encode(), hashlib.sha256).hexdigest()[:20]

    # ---- reads (separate read-only connection) -----------------------------
    def ro(self) -> sqlite3.Connection:
        cx = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=5)
        cx.row_factory = sqlite3.Row
        return cx

    def query(self, sql, args=()):
        cx = self.ro()
        try:
            return [dict(r) for r in cx.execute(sql, args)]
        finally:
            cx.close()

    # ---- writes (batched, shared lock) -------------------------------------
    def _write(self, fn):
        with self.store._lock, self.store.cx:
            return fn(self.store.cx)

    def start_session(self, note: str = "", now: float | None = None, mode: str = "drive") -> str:
        sid = secrets.token_hex(8)
        def go(cx):
            cx.execute("INSERT INTO wardrive_sessions(id,started,status,note,mode) VALUES(?,?,?,?,?)",
                       (sid, now or time.time(), "running", (note or "")[:120], mode))
        self._write(go)   # raises sqlite3.IntegrityError if one is already running
        return sid

    def end_session(self, sid: str, status: str, distance_m: float, now: float | None = None):
        self._write(lambda cx: cx.execute(
            "UPDATE wardrive_sessions SET status=?, ended=?, distance_m=? WHERE id=? AND status='running'",
            (status, now or time.time(), distance_m, sid)))

    def abort_running(self, now: float | None = None) -> int:
        """Boot: a session left 'running' by a crash/restart is aborted, never resumed (#4)."""
        def go(cx):
            rows = cx.execute("SELECT id FROM wardrive_sessions WHERE status='running'").fetchall()
            for r in rows:
                last = cx.execute("SELECT MAX(ts) FROM track WHERE session_id=?", (r[0],)).fetchone()[0]
                cx.execute("UPDATE wardrive_sessions SET status='aborted', ended=? WHERE id=?",
                           (last or now or time.time(), r[0]))
            return len(rows)
        return self._write(go)

    def running(self):
        rows = self.store._read("SELECT * FROM wardrive_sessions WHERE status='running'")
        return rows[0] if rows else None

    def add_cells(self, sid: str, obs: list[dict]) -> int:
        """obs: {radio, dev_key, cell, ts, rssi, lat, lon, name, kind}. Upsert per cell, batched.
        Returns the session's cell-row total (the service stops collection at CELL_CAP)."""
        sql = ("INSERT INTO device_cells(session_id,radio,dev_key,cell,first_ts,last_ts,n,best_rssi,"
               "lat,lon,name,kind) VALUES(?,?,?,?,?,?,1,?,?,?,?,?) "
               "ON CONFLICT(session_id,radio,dev_key,cell) DO UPDATE SET last_ts=excluded.last_ts, "
               "n=n+1, best_rssi=MAX(COALESCE(best_rssi,-999),COALESCE(excluded.best_rssi,-999)), "
               "kind=COALESCE(excluded.kind,kind)")
        total = getattr(self, "_cells", {}).get(sid, 0)
        self._cells = getattr(self, "_cells", {})
        self._calls = getattr(self, "_calls", 0) + 1
        for i in range(0, len(obs), BATCH):
            chunk = obs[i:i + BATCH]
            def go(cx):
                before = cx.total_changes
                cx.executemany(sql, [(sid, o["radio"], o["dev_key"], o["cell"], o["ts"], o["ts"],
                                      o.get("rssi"), o.get("lat"), o.get("lon"), o.get("name"),
                                      o.get("kind")) for o in chunk])
                if self._calls % 10 and sid in self._cells:
                    return self._cells[sid] + len(chunk)        # upper bound between real counts
                n = cx.execute("SELECT COUNT(*) FROM device_cells WHERE session_id=?", (sid,)).fetchone()[0]
                cx.execute("UPDATE wardrive_sessions SET cells=? WHERE id=?", (n, sid))
                return n
            total = self._write(go)
            self._cells[sid] = total
        return total

    def add_track(self, sid, ts, lat, lon, fixq, degraded=False):
        self._write(lambda cx: cx.execute("INSERT INTO track VALUES(?,?,?,?,?,?)",
                                          (sid, ts, lat, lon, fixq, int(bool(degraded)))))

    def add_rf(self, sid, ts, band, median_db, lat, lon):
        self._write(lambda cx: cx.execute("INSERT INTO rf_floor VALUES(?,?,?,?,?,?)",
                                          (sid, ts, band, median_db, lat, lon)))

    def add_alert(self, sid, ts, kind, severity, dev_key, dev_plain, detail, lat, lon, bucket) -> bool:
        def go(cx):
            cur = cx.execute(
                "INSERT OR IGNORE INTO alerts(session_id,ts,kind,severity,dev_key,dev_plain,detail,lat,lon,bucket)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (sid, ts, kind, severity, dev_key, dev_plain, (detail or "")[:300], lat, lon, bucket))
            return cur.rowcount == 1
        return self._write(go)

    # ---- "mine" (dashboard-written) -------------------------------------
    def mine_keys(self) -> set:
        return {(r["radio"], r["dev_key"]) for r in self.store._read("SELECT radio, dev_key FROM wardrive_mine")}

    def add_mine(self, radio: str, dev_key: str, label: str = ""):
        self._write(lambda cx: cx.execute("INSERT OR REPLACE INTO wardrive_mine VALUES(?,?,?,?)",
                                          (radio, dev_key, (label or "")[:60], time.time())))

    def add_candidate(self, radio: str, dev_key: str, sid: str):
        self._write(lambda cx: cx.execute("INSERT OR IGNORE INTO mine_candidates VALUES(?,?,?)",
                                          (radio, dev_key, sid)))

    def offers(self, min_sessions: int = 2) -> list:
        return self.store._read(
            "SELECT c.radio, c.dev_key, COUNT(*) AS sessions FROM mine_candidates c "
            "LEFT JOIN wardrive_mine m ON m.radio=c.radio AND m.dev_key=c.dev_key "
            "WHERE m.dev_key IS NULL GROUP BY c.radio, c.dev_key HAVING COUNT(*) >= ?", (min_sessions,))

    def ack(self, alert_id: int):   # dashboard is the only writer of alert_acks
        self._write(lambda cx: cx.execute("INSERT OR REPLACE INTO alert_acks VALUES(?,?)",
                                          (int(alert_id), time.time())))

    def delete_session(self, sid: str, chunk: int = 5000) -> bool:
        """Child tables first, in short batches so the write lock is never held for long (#8)."""
        st = self.store._read("SELECT status FROM wardrive_sessions WHERE id=?", (sid,))
        if not st or st[0]["status"] == "running":
            return False
        self._write(lambda cx: cx.execute(
            "DELETE FROM alert_acks WHERE alert_id IN (SELECT id FROM alerts WHERE session_id=?)", (sid,)))
        for t in CHILD_TABLES:
            while self._write(lambda cx: cx.execute(
                    f"DELETE FROM {t} WHERE rowid IN (SELECT rowid FROM {t} WHERE session_id=? LIMIT ?)",
                    (sid, chunk)).rowcount):
                pass
        self._write(lambda cx: cx.execute("DELETE FROM wardrive_sessions WHERE id=? AND status!='running'", (sid,)))
        return True

    def purge(self, retention_days: int, now: float, clock_ok: bool) -> int:
        """Retention (#8): only with a trustworthy clock, never a running session, child-first."""
        if not clock_ok:
            return 0
        cutoff = now - retention_days * 86400
        old = self.store._read("SELECT id FROM wardrive_sessions WHERE status!='running' AND "
                               "COALESCE(ended, started) < ?", (cutoff,))
        n = 0
        for r in old:
            n += int(self.delete_session(r["id"]))
        return n
