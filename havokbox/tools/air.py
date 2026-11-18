"""Air/sea RF tools on the second dongle: ADS-B aircraft (readsb) and AIS vessels (AIS-catcher).
Passive receive only; no network listeners (Phase 6 #14, #15)."""
from __future__ import annotations

import json

from ..store import new_id

EMERGENCY = {"7500": "hijack", "7600": "radio failure", "7700": "general emergency"}
MAX_VESSELS = 64


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
             "--seconds", str(_seconds(target)), "--work-dir", hw["work_dir"]]]


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


def build_ais(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    serial = _serial(hw)
    # UNCONFIRMED on device: "-o 5" is believed to select full JSON-per-message on stdout; "-d:SERIAL"
    # selects the dongle by serial. Check `AIS-catcher -h` on the Pi. timeout bounds the run.
    return [["timeout", str(_seconds(target)), "AIS-catcher"]
            + (["-d:" + serial] if serial else []) + ["-o", "5"]]


def _num(v, bad):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and v != bad else None


def parse_ais(stdout: str) -> list[dict]:
    ships: dict[str, dict] = {}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if not isinstance(m, dict) or m.get("mmsi") in (None, ""):
            continue
        key = str(m["mmsi"])
        if key not in ships and len(ships) >= MAX_VESSELS:
            continue
        v = ships.setdefault(key, {"mmsi": key, "name": None, "shiptype": None, "lat": None,
                                   "lon": None, "speed": None, "course": None})
        name = str(m.get("shipname") or "").strip("@ ").strip()
        if name:
            v["name"] = name
        if m.get("shiptype") is not None:
            v["shiptype"] = m["shiptype"]
        lat, lon = _num(m.get("lat"), 91), _num(m.get("lon"), 181)
        if lat is not None and lon is not None:
            v["lat"], v["lon"] = lat, lon
        for k, bad in (("speed", 102.3), ("course", 360)):
            x = _num(m.get(k), bad)
            if x is not None:
                v[k] = x
    return list(ships.values())


def ais(task: dict, ctx) -> dict:
    steps = build_ais(task.get("target", {}), ctx.mode, ctx.scope, ctx.hw)
    out = [ctx.runner(argv) for argv in steps]
    ships = parse_ais(out[0] if out else "")
    return {"result_id": new_id(), "space": "sdr2", "kind": "vessels",
            "summary": f"{len(ships)} vessel(s), {sum(1 for s in ships if s['lat'] is not None)} with position",
            "data": {"vessels": ships}}
