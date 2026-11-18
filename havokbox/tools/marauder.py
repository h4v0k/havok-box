"""ESP32 Marauder tools: passive AP survey + gated deauth.

Both run havokbox/helpers/marauder.py as a subprocess via ctx.runner; the helper owns the
serial port and prints one parsed JSON object, which we just json.loads here.
"""
from __future__ import annotations

import json

from ..store import new_id

HELPER = ["python3", "-m", "havokbox.helpers.marauder"]
BROADCAST = "ff:ff:ff:ff:ff:ff"


def build_scan(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    seconds = target.get("seconds", 20)
    return [HELPER + [
        "scan",
        "--port", hw["marauder_port"],
        "--seconds", str(seconds),
    ]]


def build_deauth(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    client = target.get("client", BROADCAST)
    seconds = target.get("seconds", 10)
    return [HELPER + [
        "deauth",
        "--port", hw["marauder_port"],
        "--bssid", str(target["bssid"]),
        "--channel", str(target["channel"]),
        "--client", str(client),
        "--seconds", str(seconds),
    ]]


def _run_json(ctx, argv) -> dict:
    stdout = ctx.runner(argv)
    try:
        return json.loads(stdout)
    except (TypeError, ValueError):
        return {"status": "error", "error": "unparseable helper output"}


def scan(task: dict, ctx) -> dict:
    [argv] = build_scan(task["target"], ctx.mode, ctx.scope, ctx.hw)
    data = _run_json(ctx, argv)
    aps = data.get("aps", []) if isinstance(data, dict) else []
    return {
        "result_id": new_id(),
        "space": "esp",
        "kind": "esp_survey",
        "summary": f"{len(aps)} AP(s) seen",
        "data": {"aps": aps[:64]},
    }


def deauth(task: dict, ctx) -> dict:
    [argv] = build_deauth(task["target"], ctx.mode, ctx.scope, ctx.hw)
    data = _run_json(ctx, argv)
    status = data.get("status", "error") if isinstance(data, dict) else "error"
    bssid = task["target"].get("bssid")
    summary = f"deauth {status}: {bssid}" if status != "refused" else f"deauth refused: {data.get('reason')}"
    return {
        "result_id": new_id(),
        "space": "esp",
        "kind": "deauth",
        "summary": summary,
        "data": data if isinstance(data, dict) else {"status": "error"},
    }
