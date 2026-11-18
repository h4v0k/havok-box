"""BLE tools: advertising scan (Sniffle helper) and GATT service enumeration (gatttool)."""
from __future__ import annotations

import json
import re

from ..store import new_id

SERVICE_NAMES = {
    "1800": "Generic Access", "1801": "Generic Attribute", "1802": "Immediate Alert",
    "1803": "Link Loss", "1804": "Tx Power", "1805": "Current Time", "180a": "Device Information",
    "180d": "Heart Rate", "180f": "Battery", "1810": "Blood Pressure", "1812": "Human Interface Device",
    "1816": "Cycling Speed and Cadence", "1818": "Cycling Power", "181a": "Environmental Sensing",
    "1819": "Location and Navigation", "181c": "User Data", "181d": "Weight Scale",
    "fe59": "Nordic DFU", "fd6f": "Exposure Notification",
}
_BASE = "-0000-1000-8000-00805f9b34fb"
_SVC = re.compile(
    r"attr handle\s*=\s*(0x[0-9a-fA-F]+),\s*end grp handle\s*=\s*(0x[0-9a-fA-F]+)\s+uuid:\s*([0-9a-fA-F-]+)")


def build_scan(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    s = int((target or {}).get("seconds") or 30)
    return [["python3", "-m", "havokbox.helpers.ble_scan", "--sniffle-dir", hw["sniffle_dir"],
             "--port", hw["sniffle_port"], "--seconds", str(s), "--work-dir", hw["work_dir"]]]


def parse_scan(stdout: str) -> list[dict]:
    try:
        obj = json.loads(stdout)
    except (ValueError, TypeError):
        return []
    devs = obj.get("devices") if isinstance(obj, dict) else None
    if not isinstance(devs, list):
        return []
    return [d for d in devs if isinstance(d, dict)][:64]


def scan(task: dict, ctx) -> dict:
    steps = build_scan(task.get("target", {}), ctx.mode, ctx.scope, ctx.hw)
    out = [ctx.runner(argv) for argv in steps]
    devs = parse_scan(out[0] if out else "")
    return {"result_id": new_id(), "space": "ble", "kind": "ble_devices",
            "summary": f"{len(devs)} BLE device(s) advertising",
            "data": {"devices": devs}}


def build_gatt(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    addr_type = (target or {}).get("addr_type") or "public"
    return [["timeout", "30", "gatttool", "-i", hw["bt_iface"], "-b", target["addr"],
             "-t", addr_type, "--primary"]]


def _short(uuid: str) -> str | None:
    u = uuid.lower()
    if len(u) == 4:
        return u
    if len(u) == 8 and u.startswith("0000"):
        return u[4:]
    if u.endswith(_BASE) and u.startswith("0000"):
        return u[4:8]
    return None


def parse_gatt(stdout: str) -> list[dict]:
    out = []
    for line in (stdout or "").splitlines():
        m = _SVC.search(line)
        if not m:
            continue
        uuid = m.group(3).lower()
        short = _short(uuid)
        out.append({"start": m.group(1).lower(), "end": m.group(2).lower(), "uuid": uuid,
                    "name": SERVICE_NAMES.get(short, "Unknown") if short else "Unknown"})
        if len(out) >= 64:
            break
    return out


def gatt(task: dict, ctx) -> dict:
    target = task["target"]
    steps = build_gatt(target, ctx.mode, ctx.scope, ctx.hw)
    out = [ctx.runner(argv) for argv in steps]
    svcs = parse_gatt(out[0] if out else "")
    return {"result_id": new_id(), "space": "ble", "kind": "ble_gatt",
            "summary": f"{target['addr']}: {len(svcs)} GATT service(s)",
            "data": {"addr": target["addr"], "services": svcs}}
