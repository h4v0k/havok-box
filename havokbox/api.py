"""Backend API the dashboard calls. Pure Python so it's testable without the HTTP layer;
the server is a thin wrapper over this.

Flow: build a scan task (in the request) -> orchestrator runs the passive/discovery tool ->
finding is stored -> planner proposes next steps (rebuilt by tasks.make_task) -> dashboard shows
them with the exact command and its digest -> approve(task_id, digest) -> run (approval checked
against the digest again, then consumed + executed).
"""
from __future__ import annotations

import json

from . import planner
from .config import MODES
from .preview import argv_for, command_for
from .scope import Gate
from .tasks import TaskError, make_task, task_digest

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
        out["evil_twins"] = [{"ssid": t.get("ssid"), "bssid": t.get("bssid"),
                              "channel": t.get("channel")}
                             for t in data.get("evil_twins", [])][:DIGEST_MAX]
        out["ap_count"] = len(data.get("aps", []))
    return out


class Api:
    def __init__(self, scope, store, orchestrator, mode: str = "stealth"):
        self.scope = scope
        self.store = store
        self.orch = orchestrator
        self.mode = mode

    @property
    def registry(self):
        return self.orch.registry

    @property
    def gate(self):
        return Gate(self.scope)

    # ---- scan buttons -----------------------------------------------------
    def set_mode(self, mode: str) -> None:
        if mode not in MODES:
            raise ValueError(f"unknown mode: {mode}")
        self.mode = mode
        self.store.log("mode", f"mode set to {mode}")

    def prepare_scan(self, space: str, mode: str | None = None) -> dict:
        """Build the scan task in the request (design-check #3). Returns {status, task?}."""
        mode = mode or self.mode
        if mode not in MODES:
            raise ValueError(f"unknown mode: {mode}")
        if space == "wired":
            if mode == "stealth":
                # Stealth discovery is a passive listener (bettercap/arpwatch) not built yet.
                # Refuse rather than run an active sweep and record it as "stealth".
                return {"status": "unavailable",
                        "reason": "passive host listen not built yet; switch to Standard to sweep"}
            tool, target = "nmap.discovery", {"network": str(self.scope.include[0])}
        elif space == "wifi":
            tool, target = "kismet.scan", {}
        else:
            raise ValueError(f"unknown space: {space}")
        task = make_task(self.registry, tool, target, mode, f"scan:{space}", suggested=True,
                         source="scan")
        decision = self.gate.evaluate(task)
        if not decision.allowed:
            self.store.log("refused", f"scan {space}: {decision.reason}")
            return {"status": "refused", "reason": decision.reason}
        if decision.needs_approval:
            # Scope says this scan needs approval: park it as a proposal the dashboard approves.
            task["_step"] = task["step_kind"] = f"{task['step_kind']}#{task['id'][:8]}"
            self.store.add_proposal(task["_rid"], task["_step"], task)
            return {"status": "needs_approval", "task_id": task["id"]}
        return {"status": "ready", "task": task}

    def execute_scan(self, task: dict) -> dict:
        res = self.orch.execute(task)
        if res.get("status") == "ok":
            self._plan_from(res["result_id"])
        return res

    def scan(self, space: str, mode: str | None = None) -> dict:
        prep = self.prepare_scan(space, mode)
        return self.execute_scan(prep["task"]) if prep["status"] == "ready" else prep

    # ---- proposal lifecycle ----------------------------------------------
    def _plan_from(self, result_id: str) -> None:
        rows = [r for r in self.store.findings() if r["result_id"] == result_id]
        if not rows:
            return
        finding = dict(rows[0])
        finding["data"] = json.loads(finding["data"])
        mode = finding.get("mode") or self.mode
        for raw in planner.plan([finding]):
            try:
                task = make_task(self.registry, raw["tool"], raw.get("target"), mode, result_id,
                                 suggested=raw.get("suggested", False), source="planner")
            except TaskError as exc:
                # e.g. a step whose tool isn't registered yet — no dead buttons.
                self.store.log("skipped", f"planner step {raw.get('tool')}: {exc}")
                continue
            self.store.add_proposal(result_id, task["step_kind"], task)
        self.store.enqueue(result_id, "commander", digest(finding))

    def _find_proposal(self, task_id: str):
        for p in self.store.proposals():
            t = json.loads(p["task"])
            if t.get("id") == task_id:
                return t
        return None

    def current_digest(self, task: dict) -> str:
        return task_digest(task, argv_for(task, self.scope, self.registry, self.orch.hw))

    def approve(self, task_id: str, shown_digest: str | None = None) -> dict:
        t = self._find_proposal(task_id)
        if not t:
            return {"status": "not_found"}
        cur = self.current_digest(t)
        if shown_digest != cur:
            self.store.log("refused", f"approve {task_id}: digest mismatch (shown command is stale)")
            return {"status": "stale", "reason": "command changed; reopen the sheet"}
        self.store.grant_approval(task_id, t["category"], {"target": t.get("target", {}),
                                                           "digest": cur})
        self.store.log("approved", f"{t['category']} {t.get('tool')} {json.dumps(t.get('target', {}))}"
                                   f" :: {command_for(t, self.scope, self.registry, self.orch.hw)} :: sha256={cur[:16]}")
        return {"status": "granted"}

    def approval_ok(self, task_id: str) -> bool:
        """An open approval exists AND its digest matches the command that would run now."""
        t = self._find_proposal(task_id)
        row = self.store.open_approval(task_id)
        if not t or not row:
            return False
        try:
            granted = json.loads(row["target"]).get("digest")
        except (TypeError, ValueError, AttributeError):
            return False
        return granted == self.current_digest(t)

    def needs_approval(self, task: dict) -> bool:
        d = self.gate.evaluate(task)
        return d.needs_approval or not d.allowed

    def run(self, task_id: str) -> dict:
        t = self._find_proposal(task_id)
        if not t:
            return {"status": "not_found"}
        if self.needs_approval(t) and self.store.open_approval(task_id) and not self.approval_ok(task_id):
            # Approved command no longer matches what would run: void, don't execute.
            self.store.void_unconsumed_approvals()
            self.store.log("refused", f"run {task_id}: approval digest no longer matches")
            return {"status": "refused", "reason": "approval no longer matches the command"}
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
        gate = self.gate
        for p in self.store.proposals():
            t = json.loads(p["task"])
            argv = argv_for(t, self.scope, self.registry, self.orch.hw)
            decision = gate.evaluate(t)
            runnable = argv is not None and decision.allowed
            proposals.append({
                "task_id": t.get("id"),
                "result_id": t.get("_rid"),
                "category": t.get("category"),
                "tool": t.get("tool"),
                "target": t.get("target"),
                "label": t.get("label"),            # generated in code (tasks.LABELS)
                "mode": t.get("mode", "stealth"),
                "suggested": bool(t.get("suggested")) and runnable,
                "needs_approval": decision.needs_approval or not decision.allowed,
                "approved": self.store.open_approval(t.get("id")) is not None,
                "command": command_for(t, self.scope, self.registry, self.orch.hw),
                "digest": task_digest(t, argv),
                "runnable": runnable,
                "in_scope": decision.allowed,
                "gate_reason": decision.reason,
                "source": t.get("source", "planner"),
            })
        return {"mode": self.mode, "phase": self._phase(findings, proposals),
                "findings": findings, "proposals": proposals,
                "evidence": self.store.evidence_recent(evidence_limit),
                "commander_pending": bool(self.store.pending_queue())}

    @staticmethod
    def _phase(findings, proposals) -> str:
        if not findings:
            return "recon"
        if any(p["category"] in TEST_CATS for p in proposals) or any(
                f["kind"] == "services" for f in findings):
            return "test"
        return "enumerate"
