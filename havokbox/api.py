"""Backend API the dashboard calls. Pure Python so it's testable without the HTTP layer;
the FastAPI server is a thin wrapper over this.

Flow: scan a space -> orchestrator runs the passive/discovery tool -> finding is stored ->
planner proposes next steps -> dashboard shows them -> approve (grant) -> run (consume + execute).
"""
from __future__ import annotations

import json

from . import planner
from .store import new_id


class Api:
    def __init__(self, scope, store, orchestrator, mode: str = "stealth"):
        self.scope = scope
        self.store = store
        self.orch = orchestrator
        self.mode = mode

    # ---- scan buttons -----------------------------------------------------
    def _space_task(self, space: str, mode: str) -> dict:
        if space == "wired":
            net = str(self.scope.include[0])
            return {"id": new_id(), "category": "recon.discovery", "tool": "nmap.discovery",
                    "target": {"network": net}, "mode": mode}
        if space == "wifi":
            return {"id": new_id(), "category": "recon.passive", "tool": "kismet.scan",
                    "target": {}, "mode": mode}
        raise ValueError(f"unknown space: {space}")

    def set_mode(self, mode: str) -> None:
        self.mode = mode

    def scan(self, space: str, mode: str | None = None) -> dict:
        res = self.orch.execute(self._space_task(space, mode or self.mode))
        if res.get("status") == "ok":
            self._plan_from(res["result_id"])
        return res

    # ---- proposal lifecycle ----------------------------------------------
    def _plan_from(self, result_id: str) -> None:
        rows = [r for r in self.store.findings() if r["result_id"] == result_id]
        if not rows:
            return
        finding = dict(rows[0])
        finding["data"] = json.loads(finding["data"])
        for task in planner.plan([finding]):
            task["_rid"] = result_id
            task["_step"] = task["step_kind"]
            self.store.add_proposal(result_id, task["step_kind"], task)

    def _find_proposal(self, task_id: str):
        for p in self.store.proposals():
            t = json.loads(p["task"])
            if t.get("id") == task_id:
                return t
        return None

    def approve(self, task_id: str) -> dict:
        t = self._find_proposal(task_id)
        if not t:
            return {"status": "not_found"}
        self.store.grant_approval(task_id, t["category"], t.get("target", {}))
        return {"status": "granted"}

    def run(self, task_id: str) -> dict:
        t = self._find_proposal(task_id)
        if not t:
            return {"status": "not_found"}
        res = self.orch.execute(t)
        if res.get("status") == "ok":
            self.store.mark_proposal(t["_rid"], t["_step"], "executed")
            self._plan_from(res["result_id"])
        return res

    # ---- dashboard state --------------------------------------------------
    def state(self) -> dict:
        findings = []
        for r in self.store.findings():
            d = dict(r)
            d["data"] = json.loads(d["data"])
            findings.append(d)
        proposals = []
        for p in self.store.proposals():
            t = json.loads(p["task"])
            proposals.append({
                "task_id": t.get("id"),
                "category": t.get("category"),
                "target": t.get("target"),
                "label": t.get("label"),
                "suggested": t.get("suggested", False),
                "needs_approval": t.get("category") not in ("recon.passive", "recon.discovery"),
            })
        return {"mode": self.mode, "findings": findings, "proposals": proposals}
