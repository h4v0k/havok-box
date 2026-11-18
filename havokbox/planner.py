"""Rule-based planner — the offline commander seam.

Given findings, it proposes the obvious next-step tasks. This is what runs with no internet;
when online, the Claude API commander can replace or extend these proposals. Deterministic and
testable. It only ever *proposes* — the gate and the human approval still stand between a
proposal and anything active running.
"""
from __future__ import annotations

from .store import new_id


def _task(category, tool, target, step_kind, label, suggested=True) -> dict:
    return {
        "id": new_id(),
        "category": category,
        "tool": tool,
        "target": target,
        "step_kind": step_kind,
        "label": label,
        "suggested": suggested,
    }


def plan(findings: list[dict]) -> list[dict]:
    """findings: dicts with parsed `data`. Returns proposed tasks (not yet gated/approved)."""
    out = []
    for f in findings:
        data = f.get("data") or {}
        if f.get("kind") == "hosts":
            for host in data.get("hosts", []):
                ip = host["ip"]
                out.append(_task(
                    "recon.active", "nmap.services", {"ip": ip},
                    f"services:{ip}", f"Scan services on {ip}",
                ))
        elif f.get("kind") == "wifi_survey":
            for twin in data.get("evil_twins", []):
                bssid = twin.get("bssid")
                out.append(_task(
                    "wifi.deauth", "wifi.capture", {"bssid": bssid},
                    f"handshake:{bssid}", f"Capture handshake on evil twin {bssid}",
                ))
    return out
