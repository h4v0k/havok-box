"""RTL-SDR tools: rtl_power spectrum survey and rtl_433 IoT decode. Passive receive only."""
from __future__ import annotations

import json
import statistics

from ..store import new_id

DECODE_FREQS = ("315M", "433.92M", "915M")
_DROP = {"raw", "data", "codes", "mic", "rows", "pulse_data"}


def build_survey(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    t = target or {}
    start = t.get("start_mhz", 24)
    end = t.get("end_mhz", 1700)
    seconds = int(t.get("seconds") or 60)
    if start >= end:
        raise ValueError("start_mhz must be below end_mhz")
    return [["rtl_power", "-f", f"{start:g}M:{end:g}M:1M", "-i", "10", "-e", f"{seconds}s",
             "/dev/stdout"]]


def parse_survey(stdout: str, start_mhz: float = 24, end_mhz: float = 1700) -> dict:
    best: dict[float, float] = {}
    for line in (stdout or "").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 7:
            continue
        try:
            lo, step = float(parts[2]), float(parts[4])
            dbs = [float(x) for x in parts[6:]]
        except ValueError:
            continue
        if step <= 0:
            continue
        for i, db in enumerate(dbs):
            mhz = round((lo + i * step) / 1e6, 3)
            if mhz not in best or db > best[mhz]:
                best[mhz] = db
    top = sorted(best.items(), key=lambda kv: -kv[1])[:10]
    return {"range": [start_mhz, end_mhz],
            "top": [{"mhz": m, "db": round(d, 2)} for m, d in top],
            "noise_floor_db": round(statistics.median(best.values()), 2) if best else None}


def survey(task: dict, ctx) -> dict:
    target = task.get("target", {})
    steps = build_survey(target, ctx.mode, ctx.scope, ctx.hw)
    out = [ctx.runner(argv) for argv in steps]
    data = parse_survey(out[0] if out else "", target.get("start_mhz", 24), target.get("end_mhz", 1700))
    return {"result_id": new_id(), "space": "sdr", "kind": "spectrum",
            "summary": f"{len(data['top'])} strongest of {data['range'][0]:g}-{data['range'][1]:g} MHz",
            "data": data}


def build_decode(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    t = target or {}
    freq = t.get("freq") or "433.92M"
    seconds = int(t.get("seconds") or 60)
    return [["rtl_433", "-F", "json", "-M", "level", "-T", str(seconds), "-f", freq]]


def parse_decode(stdout: str) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict) or "model" not in ev:
            continue
        key = (str(ev.get("model")), str(ev.get("id", "")), str(ev.get("channel", "")))
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"model": key[0], "id": ev.get("id"), "channel": ev.get("channel"),
                               "count": 0, "last": None, "rssi": None}
        g["count"] += 1
        g["last"] = ev.get("time", g["last"])
        if isinstance(ev.get("rssi"), (int, float)):
            g["rssi"] = ev["rssi"]
    return sorted(groups.values(), key=lambda g: -g["count"])[:64]


def decode(task: dict, ctx) -> dict:
    target = task.get("target", {})
    steps = build_decode(target, ctx.mode, ctx.scope, ctx.hw)
    out = [ctx.runner(argv) for argv in steps]
    devs = parse_decode(out[0] if out else "")
    freq = target.get("freq") or "433.92M"
    return {"result_id": new_id(), "space": "sdr", "kind": "iot_devices",
            "summary": f"{len(devs)} IoT device(s) decoded on {freq}",
            "data": {"freq": freq, "devices": devs}}
