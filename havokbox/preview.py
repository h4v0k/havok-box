"""Exact-command preview for the approval sheet.

Every registered tool declares `build(target, mode, scope, hw) -> [argv, ...]`, the same builder
its run function calls. The sheet shows those argv lists and the approval digest covers them, so
the preview can't drift from the run. A tool with no builder shows "not available" and the sheet
won't offer Run.
"""
from __future__ import annotations

import shlex

from .tools import DEFAULT_HW


def _registry():
    from .tools.registry import default_registry
    return default_registry()


def argv_for(task: dict, scope, registry: dict | None = None, hw: dict | None = None):
    spec = (registry or _registry()).get(task.get("tool"))
    if spec is None or spec.build is None:
        return None
    try:
        steps = spec.build(task.get("target") or {}, task.get("mode", "stealth"), scope,
                           {**DEFAULT_HW, **(hw or {})})
    except (KeyError, TypeError, ValueError):
        return None
    return [list(a) for a in steps] if steps else None


def command_for(task: dict, scope, registry: dict | None = None, hw: dict | None = None):
    steps = argv_for(task, scope, registry, hw)
    return "\n".join(shlex.join(a) for a in steps) if steps is not None else None
