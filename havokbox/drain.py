"""Offline drain loop (req 7).

Findings never wait on the API. Each new finding's digest is queued; when the box is online this
loop sends the digest to the API commander, sanitises what comes back, and writes the proposals.
The LAST write of an entry goes through store.drain(), which inserts the proposal and marks the
entry done in one transaction — a crash before commit just re-drains, and INSERT OR IGNORE on
(result_id, step_kind) makes the repeat a no-op.

Sanitising means the commander can only ever add a button: the tool must be registered, the
category is forced to the tool's true category, params are validated and stripped to the spec,
the target is pre-checked against the scope gate, and the task gets a fresh id (so a model can't
aim at an existing approval). Running it still needs the orchestrator + gate + approval.
"""
from __future__ import annotations

import json
import socket
import threading

from .commander import SpendCapReached
from .scope import Gate
from .store import new_id
from .tools import validate_params


def default_online(host: str = "api.anthropic.com", port: int = 443, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Drainer:
    def __init__(self, store, commander, registry: dict, scope, online=default_online):
        self.store = store
        self.commander = commander
        self.registry = registry
        self.gate = Gate(scope)
        self.online = online
        self._stop = threading.Event()
        self._capped_logged = False

    # ---- sanitise ---------------------------------------------------------
    def sanitise(self, raw: dict, digest: dict) -> dict | None:
        spec = self.registry.get(raw.get("tool"))
        if spec is None:
            return None
        target = raw.get("target") if isinstance(raw.get("target"), dict) else {}
        target = {k: v for k, v in target.items() if k in spec.params}
        ok, _ = validate_params(spec, target)
        if not ok:
            return None
        task = {"category": spec.category, "tool": spec.name, "target": target}
        decision = self.gate.evaluate(task)
        if not decision.allowed:
            self.store.log("refused", f"commander proposal out of scope: {spec.name} {target}: "
                                      f"{decision.reason}")
            return None
        label = str(raw.get("label") or spec.name)[:80]
        step = "ai:" + spec.name + ":" + json.dumps(target, sort_keys=True)
        task.update({"id": new_id(), "step_kind": step, "label": label,
                     "why": str(raw.get("why") or "")[:240], "suggested": False,
                     "mode": digest.get("mode") or "stealth",
                     "_rid": digest["result_id"], "_step": step})
        return task

    # ---- one pass ---------------------------------------------------------
    def drain_once(self) -> int:
        """Drain what we can. Returns how many queue entries were completed."""
        if not getattr(self.commander, "enabled", False) or not self.online():
            return 0
        done = 0
        for entry in self.store.pending_queue():
            if entry["kind"] != "commander":
                continue
            digest = json.loads(entry["payload"])
            try:
                raw_tasks = self.commander.propose(digest)
            except SpendCapReached as exc:
                if not self._capped_logged:
                    self.store.log("commander", str(exc))
                    self._capped_logged = True
                break
            except Exception as exc:  # network/API error: leave it queued, try next pass
                self.store.log("commander", f"drain deferred: {exc}")
                break
            self._capped_logged = False
            tasks, seen = [], set()
            for raw in raw_tasks[:3]:
                t = self.sanitise(raw, digest)
                if t and t["step_kind"] not in seen:
                    seen.add(t["step_kind"])
                    tasks.append(t)
            if tasks:
                tasks[0]["suggested"] = True
                for t in tasks[:-1]:
                    self.store.add_proposal(t["_rid"], t["step_kind"], t)
                last = tasks[-1]
                self.store.drain(entry["id"], last["_rid"], last["step_kind"], last)
            else:
                self.store.drain_empty(entry["id"])
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
