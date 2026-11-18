"""Backend API the dashboard calls. Pure Python so it's testable without the HTTP layer;
the FastAPI server is a thin wrapper over this.

Flow: scan a space -> orchestrator runs the passive/discovery tool -> finding is stored ->
planner proposes next steps -> dashboard shows them -> approve (grant) -> run (consume + execute).
"""
from __future__ import annotations

import json

from . import planner
from .config import MODES
from .preview import command_for
from .scope import Gate
from .store import new_id

PASSIVE_CATS = ("recon.passive", "recon.discovery")
TEST_CATS = ("wifi.deauth", "wifi.inject", "rf.replay", "rf.transmit", "auth.attempt", "exploit.tool")
DIGEST_MAX = 64


def digest(finding: dict) -> dict:
    """The compact, on-box-parsed summary sent to the API commander — never raw tool output."""
    data = finding.get("data") or {}
    out = {"result_id": finding["result_id"], "kind": finding["kind"], "space": finding["space"],
           "summary": finding["summary"], "mode": finding.get("mode")}
    if finding["kind"] == "hosts":
        out["hosts"] = [h["ip"] for h in data.get("hosts", [])][:DIGEST_MAX]
    elif finding["kind"] == "services":
        out["services"] = [{"ip": s.get("ip"), "port": s.get("port"), "service": s.get("service")}
                           for s in data.get("services", [])][:DIGEST_MAX]
    elif finding["kind"] == "wifi_survey":
        out["evil_twins"] = [{"ssid": t.get("ssid"), "bssid": t.get("bssid")}
                             for t in data.get("evil_twins", [])][:DIGEST_MAX]
        out["ap_count"] = len(data.get("aps", []))
    return out


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
        if mode not in MODES:
            raise ValueError(f"unknown mode: {mode}")
        self.mode = mode
        self.store.log("mode", f"mode set to {mode}")

    def scan(self, space: str, mode: str | None = None) -> dict:
        mode = mode or self.mode
        if mode not in MODES:
            raise ValueError(f"unknown mode: {mode}")
        if space == "wired" and mode == "stealth":
            # Stealth discovery is a passive listener (bettercap/arpwatch) that isn't built yet.
            # Refuse rather than run an active sweep and record it as "stealth".
            return {"status": "unavailable",
                    "reason": "passive host listen not built yet; switch to Standard to sweep"}
        task = self._space_task(space, mode)
        if Gate(self.scope).evaluate(task).needs_approval:
            # Scope says this scan needs approval: park it as a proposal the dashboard can approve.
            task.update({"step_kind": f"scan:{space}:{task['id']}", "label": f"Discover hosts on "
                         f"{task['target'].get('network', space)}", "suggested": True,
                         "_rid": f"scan:{space}", "_step": f"scan:{space}:{task['id']}"})
            self.store.add_proposal(task["_rid"], task["_step"], task)
            return {"status": "needs_approval", "task_id": task["id"]}
        res = self.orch.execute(task)
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
            # Freeze the mode at proposal time so the confirm-sheet preview is exactly what runs.
            task["mode"] = finding.get("mode") or self.mode
            self.store.add_proposal(result_id, task["step_kind"], task)
        # Queue the finding digest for the API commander (drained when online; req 7).
        self.store.enqueue(result_id, "commander", digest(finding))

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
        self.store.log("approved", f"{t['category']} {t.get('tool')} {json.dumps(t.get('target', {}))}"
                                   f" :: {command_for(t, self.scope) or '(no preview)'}")
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
    def state(self, evidence_limit: int = 50) -> dict:
        findings = []
        for r in self.store.findings():
            d = dict(r)
            d["data"] = json.loads(d["data"])
            findings.append(d)
        proposals = []
        gate = Gate(self.scope)
        for p in self.store.proposals():
            t = json.loads(p["task"])
            cmd = command_for(t, self.scope)
            decision = gate.evaluate(t)   # show the gate's verdict BEFORE the user taps
            runnable = cmd is not None and decision.allowed
            proposals.append({
                "task_id": t.get("id"),
                "result_id": t.get("_rid"),
                "category": t.get("category"),
                "tool": t.get("tool"),
                "target": t.get("target"),
                "label": t.get("label"),
                "mode": t.get("mode", "stealth"),
                "suggested": bool(t.get("suggested")) and runnable,
                "needs_approval": decision.needs_approval or not decision.allowed,
                "command": cmd,
                "runnable": runnable,
                "in_scope": decision.allowed,
                "gate_reason": decision.reason,
                "why": t.get("why", ""),
                "source": "commander" if str(t.get("step_kind", "")).startswith("ai:") else "planner",
            })
        evidence = self.store.evidence_recent(evidence_limit)
        return {"mode": self.mode, "phase": self._phase(findings, proposals),
                "findings": findings, "proposals": proposals, "evidence": evidence,
                "commander_pending": bool(self.store.pending_queue())}

    @staticmethod
    def _phase(findings, proposals) -> str:
        if not findings:
            return "recon"
        if any(p["category"] in TEST_CATS for p in proposals) or any(
                f["kind"] == "services" for f in findings):
            return "test"
        return "enumerate"
