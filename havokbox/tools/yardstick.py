"""Yard Stick One sub-GHz tools (rfcat): passive listen + gated replay of a saved capture.

The radio work happens in havokbox/helpers/yardstick.py as a subprocess (it owns the USB device);
ctx.runner executes the argv and returns the one JSON line it prints. Same result shapes as the
Flipper tools, so the Sub-GHz card and the planner don't change.
"""
from __future__ import annotations

import json

from ..store import new_id

HELPER = ["python3", "-m", "havokbox.helpers.yardstick"]


def build_scan(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    return [HELPER + ["scan", "--freq-mhz", str(target.get("freq_mhz", 433.92)),
                      "--seconds", str(target.get("seconds", 30)), "--work-dir", hw["work_dir"]]]


def build_replay(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    return [HELPER + ["replay", "--id", str(target["id"]), "--freq-mhz", str(target["freq_mhz"]),
                      "--work-dir", hw["work_dir"]]]


def _run_json(ctx, argv) -> dict:
    try:
        data = json.loads(ctx.runner(argv))
    except (TypeError, ValueError):
        return {"status": "error", "error": "unparseable helper output"}
    return data if isinstance(data, dict) else {"status": "error", "error": "unexpected helper output"}


def scan(task: dict, ctx) -> dict:
    [argv] = build_scan(task["target"], ctx.mode, ctx.scope, ctx.hw)
    data = _run_json(ctx, argv)
    if data.get("status") == "error":
        summary = f"Yard Stick error: {data.get('error')}"
    else:
        summary = (f"{len(data.get('received', []))} signal(s) at {task['target'].get('freq_mhz', 433.92)} MHz, "
                   f"{len(data.get('captures', []))} saved capture(s)")
    return {"result_id": new_id(), "space": "subghz", "kind": "subghz", "summary": summary,
            "data": {"received": data.get("received", [])[:64], "captures": data.get("captures", [])[:64],
                     **({"error": data["error"]} if "error" in data else {})}}


def replay(task: dict, ctx) -> dict:
    [argv] = build_replay(task["target"], ctx.mode, ctx.scope, ctx.hw)
    data = _run_json(ctx, argv)
    status = data.get("status", "error")
    cap_id = task["target"].get("id")
    summary = (f"replay refused: {data.get('reason')}" if status == "refused"
               else f"replay {status}: {cap_id}" + (f" ({data['error']})" if data.get("error") else ""))
    return {"result_id": new_id(), "space": "subghz", "kind": "replay", "summary": summary, "data": data}
