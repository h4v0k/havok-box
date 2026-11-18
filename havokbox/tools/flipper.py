"""Flipper Zero sub-GHz tools: passive recon scan + gated replay of a saved capture.

Both run the serial-conversation logic in havokbox/helpers/flipper.py as a subprocess (the
helper owns the serial port; ctx.runner executes the argv and returns stdout). Parsing has
already happened inside the helper, on-box; here we just json.loads the one line it prints.
"""
from __future__ import annotations

import json

from ..store import new_id

HELPER = ["python3", "-m", "havokbox.helpers.flipper"]


def build_scan(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    freq_mhz = target.get("freq_mhz", 433.92)
    seconds = target.get("seconds", 30)
    return [HELPER + [
        "scan",
        "--port", hw["flipper_port"],
        "--freq-mhz", str(freq_mhz),
        "--seconds", str(seconds),
    ]]


def build_replay(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    return [HELPER + [
        "replay",
        "--port", hw["flipper_port"],
        "--id", str(target["id"]),
        "--freq-mhz", str(target["freq_mhz"]),
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
    received = data.get("received", []) if isinstance(data, dict) else []
    captures = data.get("captures", []) if isinstance(data, dict) else []
    return {
        "result_id": new_id(),
        "space": "subghz",
        "kind": "subghz",
        "summary": f"{len(received)} signal(s) received, {len(captures)} saved capture(s)",
        "data": {"received": received[:64], "captures": captures[:64]},
    }


def replay(task: dict, ctx) -> dict:
    [argv] = build_replay(task["target"], ctx.mode, ctx.scope, ctx.hw)
    data = _run_json(ctx, argv)
    status = data.get("status", "error") if isinstance(data, dict) else "error"
    cap_id = task["target"].get("id")
    summary = f"replay {status}: {cap_id}" if status != "refused" else f"replay refused: {data.get('reason')}"
    return {
        "result_id": new_id(),
        "space": "subghz",
        "kind": "replay",
        "summary": summary,
        "data": data if isinstance(data, dict) else {"status": "error"},
    }
