"""Aircraft (ADS-B via readsb) on the RTL-SDR (second dongle if configured). Passive receive only;
no network listeners (Phase 6 #14). Ship tracking (AIS) was removed at the owner's request."""
from __future__ import annotations

import json

from ..store import new_id

EMERGENCY = {"7500": "hijack", "7600": "radio failure", "7700": "general emergency"}


def _serial(hw) -> str:
    hw = hw or {}
    s = hw.get("sdr2_serial") or hw.get("sdr_serial") or ""
    if s and not all(c.isalnum() or c in "-_" for c in s):
        raise ValueError("bad SDR serial")
    return s


def _seconds(t) -> int:
    return max(10, min(int((t or {}).get("seconds") or 60), 600))


def build_adsb(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    return [["python3", "-m", "havokbox.helpers.adsb", "--device", _serial(hw) or "0",
             "--seconds", str(_seconds(target)), "--work-dir", hw.get("tmpfs_dir") or "/run/havokbox"]]


def parse_adsb(stdout: str) -> list[dict]:
    try:
        obj = json.loads(stdout)
    except (ValueError, TypeError):
        return []
    rows = obj.get("aircraft") if isinstance(obj, dict) else None
    return [a for a in rows if isinstance(a, dict)][:200] if isinstance(rows, list) else []


def emergencies(aircraft: list[dict]) -> list[dict]:
    return [{"hex": a.get("hex"), "flight": a.get("flight"), "squawk": str(a["squawk"]),
             "meaning": EMERGENCY[str(a["squawk"])]}
            for a in aircraft if str(a.get("squawk")) in EMERGENCY]


def adsb(task: dict, ctx) -> dict:
    steps = build_adsb(task.get("target", {}), ctx.mode, ctx.scope, ctx.hw)
    out = [ctx.runner(argv) for argv in steps]
    ac = parse_adsb(out[0] if out else "")
    em = emergencies(ac)
    pos = sum(1 for a in ac if a.get("lat") is not None and a.get("lon") is not None)
    return {"result_id": new_id(), "space": "sdr2", "kind": "aircraft",
            "summary": f"{len(ac)} aircraft, {pos} with position, {len(em)} emergency",
            "data": {"aircraft": ac, "emergencies": em}}
