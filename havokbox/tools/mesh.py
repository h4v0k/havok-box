"""Meshtastic nodes nearby (LoRa). Reads the bridge's snapshot; the bridge owns the radio.

Passive: these are nodes that announced themselves on the mesh the box's node is on.
"""
from __future__ import annotations

import json

from ..store import new_id

HELPER = ["python3", "-m", "havokbox.helpers.meshbridge"]


def build_nodes(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    return [HELPER + ["nodes", "--data-dir", hw.get("data_dir") or "/data/havokbox"]]


def nodes(task: dict, ctx) -> dict:
    [argv] = build_nodes(task.get("target", {}), ctx.mode, ctx.scope, ctx.hw)
    try:
        d = json.loads(ctx.runner(argv))
    except (TypeError, ValueError):
        d = {"status": {"connected": False, "error": "unparseable helper output"}, "nodes": []}
    st = d.get("status") or {}
    rows = d.get("nodes") or []
    if not st.get("connected"):
        summary = "LoRa node not connected" + (f" ({st['error']})" if st.get("error") else "")
    else:
        recent = [r for r in rows if r.get("last_heard_s") is not None and r["last_heard_s"] <= 3600]
        summary = f"{len(rows)} Meshtastic node(s) known, {len(recent)} heard in the last hour"
    return {"result_id": new_id(), "space": "mesh", "kind": "mesh_nodes", "summary": summary,
            "data": {"status": st, "nodes": rows[:100], "age_s": d.get("age_s")}}
