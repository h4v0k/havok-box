"""Backend API the dashboard calls. Pure Python so it's testable without the HTTP layer;
the server is a thin wrapper over this.

Flow: build a scan task (in the request) -> orchestrator runs the passive/discovery tool ->
finding is stored -> planner proposes next steps (rebuilt by tasks.make_task) -> dashboard shows
them with the exact command and its digest -> approve(task_id, digest) -> run (approval checked
against the digest again, then consumed + executed).
"""
from __future__ import annotations

import json
import time

from . import planner
from .config import MODES
from .preview import argv_for, command_for
from .scope import Gate
from .tasks import TaskError, make_task, task_digest

TEST_CATS = ("wifi.deauth", "wifi.inject", "wifi.capture", "rf.replay", "rf.transmit",
             "auth.attempt", "exploit.tool")

# Recon card buttons: (space, action) -> tool per mode. Only shown when the tool is registered.
CARDS = [
    {"space": "wired", "title": "Wired / IP", "sub": "Pi NIC on the lab network", "actions": [
        {"action": "discover", "label": "Discover hosts",
         "tool": {"stealth": "wired.listen", "standard": "nmap.discovery"},
         "hint": {"stealth": "Stealth: passive listen to ARP / DHCP / mDNS. Sends nothing.",
                  "standard": "Standard: nmap -sn sweep of in-scope networks (excluded hosts skipped)."}}]},
    {"space": "wifi", "title": "Wi-Fi", "sub": "Alfa · Kismet", "actions": [
        {"action": "scan", "label": "Scan Wi-Fi", "tool": "kismet.scan",
         "hint": "Passive listen. Flags rogue APs and evil twins."}]},
    {"space": "ble", "title": "BLE", "sub": "SONOFF · Sniffle", "actions": [
        {"action": "scan", "label": "Scan BLE", "tool": "ble.scan",
         "hint": "Passive advertising sniff."}]},
    {"space": "subghz", "title": "Sub-GHz", "sub": "Yard Stick One", "actions": [
        {"action": "scan", "label": "Scan sub-GHz", "tool": "subghz.scan",
         "hint": "Listens on 433.92 MHz, saves each signal it hears, lists saved captures."}]},
    {"space": "sdr", "title": "Wideband RX", "sub": "RTL-SDR", "actions": [
        {"action": "survey", "label": "Spectrum survey", "tool": "sdr.survey",
         "hint": "rtl_power sweep, strongest signals."},
        {"action": "decode", "label": "Decode IoT (433)", "tool": "sdr.decode",
         "hint": "rtl_433 on 433.92 MHz."}]},
    {"space": "radio", "title": "Ham & two-way radio", "sub": "RTL-SDR · receive only", "actions": [
        {"action": "bands", "label": "Who's talking (VHF/UHF)", "tool": "radio.bands",
         "hint": "FRS/GMRS, MURS, NOAA weather, 2m, 70cm and 915 MHz (LoRa): which channels are active."},
        {"action": "aprs", "label": "APRS stations", "tool": "radio.aprs",
         "hint": "2 min on 144.390 MHz. Ham stations heard, with positions."}]},
    {"space": "mesh", "title": "LoRa mesh", "sub": "Meshtastic · Heltec V4", "actions": [
        {"action": "nodes", "label": "Meshtastic nodes nearby", "tool": "mesh.nodes",
         "hint": "Nodes the box's LoRa radio has heard: name, signal, hops, position if shared."}]},
    {"space": "sdr2", "title": "Aircraft", "sub": "RTL-SDR · readsb", "actions": [
        {"action": "adsb", "label": "Aircraft (ADS-B)", "tool": "air.adsb",
         "hint": "60 s on 1090 MHz. Emergency squawks highlighted."}]},
    {"space": "esp", "title": "ESP Wi-Fi", "sub": "Marauder board", "actions": [
        {"action": "scan", "label": "Scan (ESP)", "tool": "marauder.scan",
         "hint": "Second radio; passive AP scan."}]},
]


def _card_tool(action: dict, mode: str) -> str:
    t = action["tool"]
    return t[mode] if isinstance(t, dict) else t
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


BASELINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT, space TEXT, key TEXT, label TEXT, attrs TEXT,
    learned_at REAL, UNIQUE(space, key)
);
"""


class Api:
    def __init__(self, scope, store, orchestrator, mode: str = "stealth", gateway_ip=None,
                 pinned_static=(), inventory=None):
        self.scope = scope
        self.store = store
        self.orch = orchestrator
        self.mode = mode
        self.gateway_ip = gateway_ip
        self.pinned_static = tuple(pinned_static or ())
        self.inventory = inventory
        from .baseline import DriftCache
        self._drift_cache = DriftCache()
        self._baseline_ready = False

    # ---- baseline drift (requirement #2; the dashboard is the only writer) -----
    def _baseline_init(self):
        if not self._baseline_ready:
            with self.store._lock, self.store.cx:
                self.store.cx.executescript(BASELINE_SCHEMA)
            self._baseline_ready = True

    def baseline_rows(self) -> list[dict]:
        self._baseline_init()
        rows = self.store._read("SELECT * FROM baseline ORDER BY id")
        for r in rows:
            try:
                r["attrs"] = json.loads(r["attrs"] or "{}")
            except ValueError:
                r["attrs"] = {}
        return rows

    def _findings_parsed(self):
        out = []
        for r in self.store.findings():
            d = dict(r)
            try:
                d["data"] = json.loads(d["data"])
            except (TypeError, ValueError):
                d["data"] = {}
            out.append(d)
        return out

    def baseline_learn(self) -> int:
        """Snapshot the current lab inventory as the baseline (replaces it)."""
        from .baseline import inventory
        self._baseline_init()
        inv = inventory(self._findings_parsed())
        rows = [(space, key, attrs.get("label") or attrs.get("ssid") or key, json.dumps(attrs), time.time())
                for space, items in inv.items() if not space.startswith("_")
                for key, attrs in items.items()]
        with self.store._lock, self.store.cx:
            self.store.cx.execute("DELETE FROM baseline")
            self.store.cx.executemany(
                "INSERT INTO baseline(space,key,label,attrs,learned_at) VALUES(?,?,?,?,?)", rows)
        self.store.log("baseline", f"learned {len(rows)} item(s)")
        return len(rows)

    def baseline_accept(self, space: str, key: str) -> bool:
        from .baseline import inventory
        self._baseline_init()
        attrs = inventory(self._findings_parsed()).get(space, {}).get(key)
        if attrs is None:
            return False
        with self.store._lock, self.store.cx:
            self.store.cx.execute(
                "INSERT OR REPLACE INTO baseline(space,key,label,attrs,learned_at) VALUES(?,?,?,?,?)",
                (space, key, attrs.get("label") or attrs.get("ssid") or key, json.dumps(attrs), time.time()))
        self.store.log("baseline", f"accepted {space}:{key}")
        return True

    def baseline_forget(self) -> None:
        self._baseline_init()
        with self.store._lock, self.store.cx:
            self.store.cx.execute("DELETE FROM baseline")
        self.store.log("baseline", "baseline cleared")

    def drift(self, findings=None) -> dict:
        rows = self.baseline_rows()
        if not rows:
            return {"learned": False, "items": []}
        items = self._drift_cache.get(findings if findings is not None else self._findings_parsed(),
                                      rows, gateway_ip=self.gateway_ip, pinned_static=self.pinned_static)
        return {"learned": True, "learned_at": max(r["learned_at"] for r in rows), "items": items}

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

    def cards(self) -> list[dict]:
        """Recon cards for the UI — only buttons whose tool is registered (no dead buttons)."""
        out = []
        for c in CARDS:
            acts = []
            for a in c["actions"]:
                tool = _card_tool(a, self.mode)
                if tool in self.registry and self._installed(tool):
                    hint = a["hint"][self.mode] if isinstance(a["hint"], dict) else a["hint"]
                    acts.append({"action": a["action"], "label": a["label"], "hint": hint})
            if acts:
                out.append({"space": c["space"], "title": c["title"], "sub": c["sub"],
                            "actions": acts})
        return out

    def _installed(self, tool: str) -> bool:
        return self.inventory is None or self.inventory.has(tool)

    def tool_catalog(self) -> list[dict]:
        """Every registered tool the operator can aim at a target (for the Tools panel). Passive
        recon tools and recipes included; hides tools whose binary isn't installed."""
        out = []
        for name, spec in self.registry.items():
            if not self._installed(name):
                continue
            out.append({"tool": name, "category": spec.category, "space": getattr(spec, "space", ""),
                        "phase": getattr(spec, "phase", None),
                        "recipe": bool(getattr(spec, "recipe", False)),
                        "label": getattr(spec, "label", None) or _plain(name),
                        "help": _help(name),
                        "params": {k: {kk: vv for kk, vv in v.items() if kk != "default"}
                                   for k, v in (spec.params or {}).items()},
                        "needs_approval": spec.category not in ("recon.passive",),
                        "target_key": self._target_key(spec.category)})
        out.sort(key=lambda t: (t["category"], t["tool"]))
        return out

    @staticmethod
    def _target_key(category):
        from .recipes import REQUIRED_KEY
        return REQUIRED_KEY.get(category)

    def manual_tool(self, tool: str, target: dict) -> dict:
        """Operator aims a registered tool at a target. Builds a gated proposal (approval flow
        unchanged); never runs anything here. Out-of-scope is refused by the gate at state time."""
        spec = self.registry.get(tool)
        if spec is None or not self._installed(tool):
            return {"status": "unknown_tool"}
        try:
            task = make_task(self.registry, tool, target or {}, self.mode, f"manual:{tool}",
                             suggested=False, source="manual")
        except TaskError as exc:
            return {"status": "bad_params", "reason": str(exc)}
        d = self.gate.evaluate(task)
        if not d.allowed:
            return {"status": "refused", "reason": d.reason}
        self.store.add_proposal(task["_rid"] + ":" + task["id"][:8], task["step_kind"] + "#" + task["id"][:8], task)
        return {"status": "ok", "task_id": task["id"], "needs_approval": d.needs_approval}

    def prepare_scan(self, space: str, mode: str | None = None, action: str | None = None) -> dict:
        """Build the scan task in the request (design-check #3). Returns {status, task?}."""
        mode = mode or self.mode
        if mode not in MODES:
            raise ValueError(f"unknown mode: {mode}")
        card = next((c for c in CARDS if c["space"] == space), None)
        if card is None:
            raise ValueError(f"unknown space: {space}")
        act = next((a for a in card["actions"] if a["action"] == (action or card["actions"][0]["action"])), None)
        if act is None:
            raise ValueError(f"unknown action: {action}")
        tool = _card_tool(act, mode)
        if tool == "nmap.discovery" and not self.scope.include:
            reason = "no engagement: find the lab and pick it on the Engagement card first"
            self.store.log("refused", f"scan {space}: {reason}")
            return {"status": "refused", "reason": reason}
        target = {"network": str(self.scope.include[0])} if tool == "nmap.discovery" else {}
        try:
            task = make_task(self.registry, tool, target, mode, f"scan:{space}", suggested=True,
                             source="scan")
        except TaskError as exc:
            return {"status": "unavailable", "reason": str(exc)}
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

    def scan(self, space: str, mode: str | None = None, action: str | None = None) -> dict:
        prep = self.prepare_scan(space, mode, action)
        return self.execute_scan(prep["task"]) if prep["status"] == "ready" else prep

    # ---- proposal lifecycle ----------------------------------------------
    def _plan_from(self, result_id: str) -> None:
        rows = [r for r in self.store.findings() if r["result_id"] == result_id]
        if not rows:
            return
        finding = dict(rows[0])
        finding["data"] = json.loads(finding["data"])
        mode = finding.get("mode") or self.mode
        for raw in planner.plan([finding], scope=self.scope, mode=mode):
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

    def _is_recipe(self, tool) -> bool:
        spec = self.registry.get(tool)
        return bool(spec is not None and getattr(spec, "recipe", False))

    def needs_approval(self, task: dict) -> bool:
        d = self.gate.evaluate(task)
        return d.needs_approval or not d.allowed or self._is_recipe(task.get("tool"))

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
                "help": t.get("help") or _help(t.get("tool")),
                "mode": t.get("mode", "stealth"),
                "suggested": bool(t.get("suggested")) and runnable,
                "needs_approval": decision.needs_approval or not decision.allowed or self._is_recipe(t.get("tool")),
                "approved": self.store.open_approval(t.get("id")) is not None,
                "recipe": self._is_recipe(t.get("tool")),
                "command": command_for(t, self.scope, self.registry, self.orch.hw),
                "digest": task_digest(t, argv),
                "runnable": runnable,
                "in_scope": decision.allowed,
                "gate_reason": decision.reason,
                "source": t.get("source", "planner"),
            })
        try:
            drift = self.drift(findings)
        except Exception as exc:   # drift is advisory; never break the dashboard
            drift = {"learned": False, "items": [], "error": str(exc)[:120]}
        return {"mode": self.mode, "phase": self._phase(findings, proposals), "cards": self.cards(),
                "drift": drift, "tools": self.tool_catalog(),
                "missing_tools": self.inventory.missing if self.inventory else [],
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


def _help(tool) -> str:
    from .tasks import HELP
    return HELP.get(tool or "", "")


def _plain(tool: str) -> str:
    """Tool-panel name: the action label without its {placeholders}."""
    import re
    from .tasks import LABELS
    names = {"wifi.watch": "Watch one Wi-Fi network", "subghz.replay": "Replay a saved remote",
             "ble.gatt": "Read what a Bluetooth device offers", "sdr.decode": "Decode sensor signals",
             "radio.aprs": "Ham radio position reports", "net.local": "Which networks is the box on",
             "marauder.deauth": "Kick Wi-Fi clients off a network (ESP32 board)"}
    if tool in names:
        return names[tool]
    text = LABELS.get(tool)
    if not text:
        return tool
    out = re.sub(r"\s*\(?\{[a-z_]+\}\)?", "", text).strip(" :")
    out = re.sub(r"\s+(on|at|for|off|of)\s*:?$", "", out).strip(" :")
    out = re.sub(r"\s+(on|off|at)\s+\(", " (", out)
    return out or tool
