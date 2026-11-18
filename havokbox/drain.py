"""Offline drain loop (req 7; design-check #6, #7, #8).

Findings never wait on the API. Each new finding's digest is queued; when the box is online this
loop sends the digest to the API commander, rebuilds what comes back through tasks.make_task, and
writes the survivors with store.drain_many — every proposal plus "entry done" in ONE transaction.
A crash before commit just re-drains, and INSERT OR IGNORE on (result_id, step_kind) makes the
repeat a no-op. step_kind is derived from tool + canonical target, so a commander proposal that
duplicates a planner one lands on the same row.

The commander can only ever add a button: tool must be registered, category comes from the
registry, unknown target keys are rejected, the target is pre-checked against the scope gate, the
id is fresh and the label is generated in code. Running it still needs the orchestrator + gate +
a digest-bound approval.

Retries are bounded: an API/parse error backs off (30s, 60s, 120s ...) and the entry is marked
failed after MAX_ATTEMPTS. A reply with zero valid proposals still marks the entry done.
"""
from __future__ import annotations

import json
import socket
import threading
import time

from .commander import SpendCapReached
from .scope import Gate
from .tasks import TaskError, make_task

MAX_ATTEMPTS = 5
BASE_BACKOFF_S = 30


def default_online(host: str = "api.anthropic.com", port: int = 443, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Drainer:
    def __init__(self, store, commander, registry: dict, scope, online=default_online,
                 clock=time.monotonic):
        self.store = store
        self.commander = commander
        self.registry = registry
        self.gate = Gate(scope)
        self.online = online
        self.clock = clock
        self._stop = threading.Event()
        self._capped_logged = False
        self._attempts: dict[int, int] = {}     # queue id -> failed attempts (in memory)
        self._next_try: dict[int, float] = {}   # queue id -> earliest retry time

    # ---- sanitise ---------------------------------------------------------
    def sanitise(self, raw: dict, digest: dict) -> dict | None:
        if not isinstance(raw, dict):
            return None
        try:
            task = make_task(self.registry, raw.get("tool"), raw.get("target"),
                             digest.get("mode") or "stealth", digest["result_id"],
                             suggested=False, source="commander")
        except TaskError as exc:
            self.store.log("refused", f"commander proposal dropped: {exc}")
            return None
        decision = self.gate.evaluate(task)
        if not decision.allowed:
            self.store.log("refused", f"commander proposal out of scope: {task['step_kind']}: "
                                      f"{decision.reason}")
            return None
        return task

    def _fail(self, entry_id: int, why: str) -> None:
        n = self._attempts.get(entry_id, 0) + 1
        self._attempts[entry_id] = n
        if n >= MAX_ATTEMPTS:
            self.store.drain_empty(entry_id)
            self.store.log("commander", f"queue entry {entry_id} failed after {n} attempts: {why}")
            self._attempts.pop(entry_id, None)
            self._next_try.pop(entry_id, None)
        else:
            self._next_try[entry_id] = self.clock() + BASE_BACKOFF_S * (2 ** (n - 1))
            self.store.log("commander", f"drain deferred ({n}/{MAX_ATTEMPTS}): {why}")

    # ---- one pass ---------------------------------------------------------
    def drain_once(self) -> int:
        """Drain what we can. Returns how many queue entries were completed."""
        if not getattr(self.commander, "enabled", False) or not self.online():
            return 0
        done = 0
        now = self.clock()
        for entry in self.store.pending_queue():
            if entry["kind"] != "commander" or self._next_try.get(entry["id"], 0) > now:
                continue
            digest = json.loads(entry["payload"])
            try:
                raw_tasks = self.commander.propose(digest)
            except SpendCapReached as exc:
                if not self._capped_logged:
                    self.store.log("commander", str(exc))
                    self._capped_logged = True
                break
            except Exception as exc:  # network/API error: back off, bounded
                self._fail(entry["id"], str(exc))
                break
            self._capped_logged = False
            tasks, seen = [], set()
            for raw in list(raw_tasks)[:3]:
                t = self.sanitise(raw, digest)
                if t and t["step_kind"] not in seen:
                    seen.add(t["step_kind"])
                    tasks.append(t)
            if tasks:
                tasks[0]["suggested"] = True
            self.store.drain_many(entry["id"], [(t["_rid"], t["_step"], t) for t in tasks])
            self._attempts.pop(entry["id"], None)
            self._next_try.pop(entry["id"], None)
            self.store.log("commander", f"{digest.get('summary')} -> {len(tasks)} proposal(s)")
            done += 1
        return done

    # ---- loop -------------------------------------------------------------
    def run_forever(self, interval_s: float = 30) -> None:
        while not self._stop.is_set():
            try:
                self.drain_once()
            except Exception as exc:  # never let the loop die
                self.store.log("error", f"drain loop: {exc}")
            self._stop.wait(interval_s)

    def stop(self) -> None:
        self._stop.set()
