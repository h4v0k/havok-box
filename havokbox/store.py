"""The single on-box writer. SQLite, WAL, serialized writes.

Enforces the design-check invariants:
- findings are idempotent on result_id (a re-sent result is a no-op, never a double count);
- attack-path proposals are idempotent on (result_id, step_kind);
- approvals are bound to one task_id and consumed exactly once;
- the offline-queue drain writes the proposal and marks the entry done in ONE transaction;
- a watchdog restart voids every approval not yet consumed.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    result_id TEXT PRIMARY KEY,
    space TEXT, kind TEXT, summary TEXT, data TEXT, mode TEXT, created REAL
);
CREATE TABLE IF NOT EXISTS proposals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id TEXT, step_kind TEXT, task TEXT, status TEXT, created REAL,
    UNIQUE(result_id, step_kind)
);
CREATE TABLE IF NOT EXISTS approvals (
    task_id TEXT PRIMARY KEY,
    category TEXT, target TEXT, granted REAL, consumed REAL
);
CREATE TABLE IF NOT EXISTS offline_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id TEXT, kind TEXT, payload TEXT, done REAL, created REAL,
    UNIQUE(result_id, kind)
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, detail TEXT
);
"""


def new_id() -> str:
    return uuid.uuid4().hex


class Store:
    def __init__(self, path: str = ":memory:"):
        self.cx = sqlite3.connect(path, check_same_thread=False)
        self.cx.row_factory = sqlite3.Row
        self.cx.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()  # one writer at a time — the single-writer discipline
        self.cx.executescript(SCHEMA)

    def close(self) -> None:
        self.cx.close()

    # ---- findings (orchestrator only) -------------------------------------
    def add_finding(self, result_id, space, kind, summary, data, mode) -> bool:
        with self._lock, self.cx:
            cur = self.cx.execute(
                "INSERT OR IGNORE INTO findings(result_id,space,kind,summary,data,mode,created)"
                " VALUES(?,?,?,?,?,?,?)",
                (result_id, space, kind, summary, json.dumps(data), mode, time.time()),
            )
            return cur.rowcount == 1  # False means it was already there (idempotent)

    # ---- attack-path proposals (orchestrator only) ------------------------
    def add_proposal(self, result_id, step_kind, task) -> bool:
        with self._lock, self.cx:
            cur = self.cx.execute(
                "INSERT OR IGNORE INTO proposals(result_id,step_kind,task,status,created)"
                " VALUES(?,?,?,?,?)",
                (result_id, step_kind, json.dumps(task), "pending", time.time()),
            )
            return cur.rowcount == 1

    # ---- approvals (dashboard grants; orchestrator consumes) --------------
    def grant_approval(self, task_id, category, target) -> None:
        with self._lock, self.cx:
            self.cx.execute(
                "INSERT OR IGNORE INTO approvals(task_id,category,target,granted,consumed)"
                " VALUES(?,?,?,?,NULL)",
                (task_id, category, json.dumps(target), time.time()),
            )

    def consume_approval(self, task_id) -> bool:
        """Consume a matching, un-consumed approval. True only if this call consumed it."""
        with self._lock, self.cx:
            cur = self.cx.execute(
                "UPDATE approvals SET consumed=? WHERE task_id=? AND consumed IS NULL",
                (time.time(), task_id),
            )
            return cur.rowcount == 1

    def void_unconsumed_approvals(self) -> int:
        with self._lock, self.cx:
            cur = self.cx.execute("DELETE FROM approvals WHERE consumed IS NULL")
            return cur.rowcount

    # ---- offline queue ----------------------------------------------------
    def enqueue(self, result_id, kind, payload) -> None:
        with self._lock, self.cx:
            self.cx.execute(
                "INSERT OR IGNORE INTO offline_queue(result_id,kind,payload,done,created)"
                " VALUES(?,?,?,NULL,?)",
                (result_id, kind, json.dumps(payload), time.time()),
            )

    def pending_queue(self):
        return [dict(r) for r in self.cx.execute(
            "SELECT * FROM offline_queue WHERE done IS NULL ORDER BY id")]

    def drain(self, queue_id, result_id, step_kind, task) -> None:
        """Write the proposal and mark the entry done atomically. Idempotent on retry."""
        with self._lock, self.cx:
            self.cx.execute(
                "INSERT OR IGNORE INTO proposals(result_id,step_kind,task,status,created)"
                " VALUES(?,?,?,?,?)",
                (result_id, step_kind, json.dumps(task), "pending", time.time()),
            )
            self.cx.execute("UPDATE offline_queue SET done=? WHERE id=?", (time.time(), queue_id))

    def drain_empty(self, queue_id) -> None:
        """Mark a queue entry done when the commander proposed nothing. Idempotent."""
        with self._lock, self.cx:
            self.cx.execute("UPDATE offline_queue SET done=? WHERE id=? AND done IS NULL",
                            (time.time(), queue_id))

    def mark_proposal(self, result_id, step_kind, status) -> None:
        with self._lock, self.cx:
            self.cx.execute(
                "UPDATE proposals SET status=? WHERE result_id=? AND step_kind=?",
                (status, result_id, step_kind),
            )

    # ---- evidence (append-only) -------------------------------------------
    def log(self, kind, detail) -> None:
        with self._lock, self.cx:
            self.cx.execute(
                "INSERT INTO evidence(ts,kind,detail) VALUES(?,?,?)", (time.time(), kind, detail)
            )

    # ---- reads (dashboard / publisher) ------------------------------------
    def findings(self):
        return [dict(r) for r in self.cx.execute("SELECT * FROM findings ORDER BY created")]

    def proposals(self):
        return [dict(r) for r in self.cx.execute(
            "SELECT * FROM proposals WHERE status='pending' ORDER BY created")]

    def evidence(self):
        return [dict(r) for r in self.cx.execute("SELECT * FROM evidence ORDER BY id")]
