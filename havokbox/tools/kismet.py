"""Kismet wrapper: pull the current device list and flag evil twins against the scope.

The on-box adapter fetches Kismet's REST device view (via the runner, e.g. curl to
localhost:2501) and normalises each device to {type, ssid, bssid, channel, signal}. The
parser and detector work on that normalised shape so they're testable without Kismet.
"""
from __future__ import annotations

import json

from ..store import new_id

KISMET_CMD = ["curl", "-s", "http://localhost:2501/devices/views/all/devices.json"]


def _normalise(d: dict) -> tuple[str, dict]:
    """Accept Kismet's raw REST shape (kismet.device.base.*) or the already-flat shape."""
    if "kismet.device.base.macaddr" in d or "kismet.device.base.type" in d:
        sig = d.get("kismet.device.base.signal")
        signal = sig.get("kismet.common.signal.last_signal") if isinstance(sig, dict) else None
        kind = str(d.get("kismet.device.base.type") or "")
        dev = {
            "ssid": d.get("kismet.device.base.commonname") or d.get("kismet.device.base.name") or None,
            "bssid": str(d.get("kismet.device.base.macaddr") or "").lower() or None,
            "channel": d.get("kismet.device.base.channel"),
            "signal": signal,
        }
        return ("AP" if kind.endswith("AP") else "client"), dev
    dev = {
        "ssid": d.get("ssid"),
        "bssid": (d.get("bssid") or "").lower() or None,
        "channel": d.get("channel"),
        "signal": d.get("signal"),
    }
    return ("AP" if d.get("type") == "AP" else "client"), dev


def parse_devices(devices: list[dict]) -> tuple[list[dict], list[dict]]:
    aps, clients = [], []
    for d in devices if isinstance(devices, list) else []:
        if not isinstance(d, dict):
            continue
        kind, dev = _normalise(d)
        (aps if kind == "AP" else clients).append(dev)
    return aps[:256], clients[:256]


def detect_evil_twins(aps: list[dict], known_ssids: set, known_bssids: set) -> list[dict]:
    """An AP broadcasting a known SSID from a BSSID that isn't ours is an evil twin / rogue."""
    twins = []
    for ap in aps:
        if ap.get("ssid") in known_ssids and (ap.get("bssid") or "") not in known_bssids:
            twins.append(ap)
    return twins


def scan(task: dict, ctx) -> dict:
    raw = ctx.runner(KISMET_CMD)
    devices = json.loads(raw) if raw else []
    aps, clients = parse_devices(devices)
    twins = detect_evil_twins(aps, set(ctx.scope.ssids), set(ctx.scope.bssids))
    note = f", {len(twins)} evil twin(s)" if twins else ""
    return {
        "result_id": new_id(),
        "space": "wifi",
        "kind": "wifi_survey",
        "summary": f"{len(aps)} AP(s), {len(clients)} client(s){note}",
        "data": {"aps": aps, "clients": clients, "evil_twins": twins},
    }
