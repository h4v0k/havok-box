"""Wi-Fi tools: Alfa adapter in monitor mode, aircrack-ng suite.

``wifi.watch`` and ``wifi.capture`` run the ``havokbox.helpers.wifi_capture`` helper (airodump-ng needs
a timed, file-writing session, so the real work lives there, testable with an injected runner/popen).
``wifi.deauth`` is simple enough to run directly: ``iw`` to set the channel, then ``aireplay-ng``.

Monitor-mode interface and the work directory always come from ``hw`` (``DEFAULT_HW``), never from the
target. Lab-only: wraps standard installed tools against BSSIDs the gate has already checked are in
the owner's own ``wifi.bssids`` scope list, under per-action approval for anything beyond passive watch.
"""
from __future__ import annotations

import json
import re

from ..store import new_id

HELPER_ARGV = ["python3", "-m", "havokbox.helpers.wifi_capture"]
HANDSHAKE_RE = re.compile(r"\((\d+)\s+handshake", re.I)
SENT_RE = re.compile(r"(\d+)\s+packets\s+sent", re.I)


def _mon(hw: dict) -> str:
    return hw["wifi_mon_iface"]


def _work_dir(hw: dict) -> str:
    return hw["work_dir"]


# ---------------------------------------------------------------- wifi.watch

def build_watch(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    bssid = target["bssid"]
    channel = int(target["channel"])
    seconds = int(target.get("seconds", 60))
    return [HELPER_ARGV + ["watch", "--iface", _mon(hw), "--bssid", bssid, "--channel", str(channel),
                           "--seconds", str(seconds), "--work-dir", _work_dir(hw)]]


def watch(task: dict, ctx) -> dict:
    argv, = build_watch(task["target"], ctx.mode, ctx.scope, ctx.hw)
    out = ctx.runner(argv)
    data = _load_helper_json(out)
    bssid = task["target"]["bssid"]
    channel = int(task["target"]["channel"])
    clients = data.get("clients", []) if isinstance(data, dict) else []
    return {
        "result_id": new_id(),
        "space": "wifi",
        "kind": "ap_watch",
        "summary": f"{bssid}: {len(clients)} client(s) on ch{channel}",
        "data": {"bssid": bssid, "channel": channel, "clients": clients, "ap": data.get("ap") if isinstance(data, dict) else None},
    }


# ---------------------------------------------------------------- wifi.capture

def build_capture(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    bssid = target["bssid"]
    channel = int(target["channel"])
    seconds = int(target.get("seconds", 120))
    return [HELPER_ARGV + ["capture", "--iface", _mon(hw), "--bssid", bssid, "--channel", str(channel),
                           "--seconds", str(seconds), "--work-dir", _work_dir(hw)]]


def capture(task: dict, ctx) -> dict:
    argv, = build_capture(task["target"], ctx.mode, ctx.scope, ctx.hw)
    out = ctx.runner(argv)
    data = _load_helper_json(out)
    bssid = task["target"]["bssid"]
    handshake = bool(data.get("handshake")) if isinstance(data, dict) else False
    return {
        "result_id": new_id(),
        "space": "wifi",
        "kind": "capture",
        "summary": f"{bssid}: handshake captured" if handshake else f"{bssid}: no handshake yet",
        "data": {
            "bssid": bssid,
            "file": data.get("file") if isinstance(data, dict) else None,
            "handshake": handshake,
            "sha256": data.get("sha256") if isinstance(data, dict) else None,
        },
    }


# ---------------------------------------------------------------- wifi.capture_deauth

def build_capture_deauth(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    bssid = target["bssid"]
    channel = int(target["channel"])
    seconds = int(target.get("seconds", 90))
    count = int(target.get("count", 3))
    argv = HELPER_ARGV + ["capture-deauth", "--iface", _mon(hw), "--bssid", bssid, "--channel", str(channel),
                          "--seconds", str(seconds), "--work-dir", _work_dir(hw), "--count", str(count)]
    client = target.get("client")
    if client:
        argv += ["--client", client]
    return [argv]


def capture_deauth(task: dict, ctx) -> dict:
    argv, = build_capture_deauth(task["target"], ctx.mode, ctx.scope, ctx.hw)
    out = ctx.runner(argv)
    data = _load_helper_json(out)
    bssid = task["target"]["bssid"]
    handshake = bool(data.get("handshake")) if isinstance(data, dict) else False
    return {
        "result_id": new_id(),
        "space": "wifi",
        "kind": "capture",
        "summary": f"{bssid}: handshake captured (deauth-assisted)" if handshake else f"{bssid}: no handshake yet (deauth-assisted)",
        "data": {
            "bssid": bssid,
            "file": data.get("file") if isinstance(data, dict) else None,
            "handshake": handshake,
            "sha256": data.get("sha256") if isinstance(data, dict) else None,
            "deauth_sent": data.get("deauth_sent") if isinstance(data, dict) else None,
        },
    }


# ---------------------------------------------------------------- wifi.deauth (standalone)

def build_deauth(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    bssid = target["bssid"]
    channel = int(target["channel"])
    count = int(target.get("count", 5))
    mon = _mon(hw)
    argv = ["aireplay-ng", "-0", str(count), "-a", bssid]
    client = target.get("client")
    if client:
        argv += ["-c", client]
    argv.append(mon)
    return [["iw", "dev", mon, "set", "channel", str(channel)], argv]


def parse_deauth_sent(stdout: str) -> int:
    m = SENT_RE.search(stdout or "")
    return int(m.group(1)) if m else 0


def deauth(task: dict, ctx) -> dict:
    steps = build_deauth(task["target"], ctx.mode, ctx.scope, ctx.hw)
    ctx.runner(steps[0])
    out = ctx.runner(steps[1])
    sent = parse_deauth_sent(out)
    bssid = task["target"]["bssid"]
    client = task["target"].get("client")
    mode_desc = f"targeted ({client})" if client else "broadcast"
    return {
        "result_id": new_id(),
        "space": "wifi",
        "kind": "deauth",
        "summary": f"{bssid}: {mode_desc} deauth, {sent} frame(s) sent",
        "data": {"bssid": bssid, "client": client, "sent": sent},
    }


# ---------------------------------------------------------------- shared

def _load_helper_json(out: str):
    try:
        return json.loads(out)
    except (json.JSONDecodeError, TypeError):
        return {"status": "error", "error": "unparseable helper output"}
