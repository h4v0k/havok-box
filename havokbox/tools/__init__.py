"""Tool wrappers: each runs one standard Kali tool, parses its output on-box, and returns
a short structured result.

A tool is `fn(task, ctx) -> dict` (result_id, space, kind, summary, data). `ctx` carries the
shell runner, the current mode, and the scope.

Tools are declared as `ToolSpec`s in registry.py: the agent picks a tool by name and fills
typed params, which are validated against the spec AND bound to the tool's true gate category
before anything runs — so a task can't claim a quieter category than the tool really is.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

_BSSID = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


@dataclass
class ToolCtx:
    runner: object   # callable(list[str]) -> str (stdout)
    mode: str
    scope: object


@dataclass
class ToolSpec:
    name: str
    category: str                 # the gate category this tool ALWAYS runs under
    params: dict                  # field name -> {"type": ..., "required": bool}
    fn: object                    # callable(task, ctx) -> result dict
    space: str = ""


def validate_params(spec: ToolSpec, target: dict) -> tuple[bool, str]:
    target = target or {}
    for name, meta in spec.params.items():
        present = name in target and target[name] not in (None, "")
        if not present:
            if meta.get("required"):
                return False, f"missing param: {name}"
            continue
        value, kind = target[name], meta["type"]
        try:
            if kind == "cidr":
                ipaddress.ip_network(value, strict=False)
            elif kind == "ip":
                ipaddress.ip_address(value)
            elif kind == "bssid":
                if not _BSSID.match(str(value)):
                    return False, f"{name}: not a BSSID"
            elif kind == "number":
                if not isinstance(value, (int, float)):
                    return False, f"{name}: not a number"
            elif kind == "str":
                if not isinstance(value, str):
                    return False, f"{name}: not a string"
        except ValueError:
            return False, f"{name}: not a valid {kind}"
    return True, "ok"
