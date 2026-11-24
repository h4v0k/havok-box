"""Ham / two-way radio tools on the main RTL-SDR. Receive only.

radio.bands: which FRS/GMRS, MURS, NOAA, 2m and 70cm channels are active right now.
radio.aprs:  APRS stations heard on 144.390 MHz (Dire Wolf), with positions.
"""
from __future__ import annotations

import json

from ..store import new_id
from ..helpers.radio import BANDS, DEFAULT_BANDS
from .sdr import dev_args

HELPER = ["python3", "-m", "havokbox.helpers.radio"]
BAND_CHOICES = ["all", *BANDS]


def _device(hw) -> list[str]:
    d = dev_args(hw, style="librtlsdr")      # ["-d", serial] or []
    return ["--device", d[1]] if d else []


def build_bands(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    t = target or {}
    band = t.get("band", "all")
    if band not in BAND_CHOICES:
        raise ValueError("unknown band")
    names = DEFAULT_BANDS if band == "all" else (band,)
    return [HELPER + ["bands", "--bands", ",".join(names), "--seconds", str(int(t.get("seconds") or 60))]
            + _device(hw)]


def build_aprs(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    return [HELPER + ["aprs", "--seconds", str(int((target or {}).get("seconds") or 120))] + _device(hw)]


def _json(ctx, argv) -> dict:
    try:
        d = json.loads(ctx.runner(argv))
        return d if isinstance(d, dict) else {"status": "error", "error": "unexpected output"}
    except (TypeError, ValueError):
        return {"status": "error", "error": "unparseable helper output"}


def bands(task: dict, ctx) -> dict:
    [argv] = build_bands(task.get("target", {}), ctx.mode, ctx.scope, ctx.hw)
    d = _json(ctx, argv)
    if d.get("status") == "error":
        summary = f"radio scan error: {d.get('error')}"
    else:
        act = [a for b in d.get("bands", []) for a in b.get("active", [])]
        named = [a["label"] for a in act if a.get("label")]
        summary = f"{len(act)} active channel(s)" + (f": {', '.join(named[:4])}" if named else "")
    return {"result_id": new_id(), "space": "radio", "kind": "radio_bands", "summary": summary, "data": d}


def aprs(task: dict, ctx) -> dict:
    [argv] = build_aprs(task.get("target", {}), ctx.mode, ctx.scope, ctx.hw)
    d = _json(ctx, argv)
    if d.get("status") == "error":
        summary = f"APRS error: {d.get('error')}"
    else:
        st = d.get("stations", [])
        pos = sum(1 for s in st if s.get("lat") is not None)
        summary = f"{len(st)} APRS station(s), {pos} with position"
    return {"result_id": new_id(), "space": "radio", "kind": "aprs", "summary": summary, "data": d}
