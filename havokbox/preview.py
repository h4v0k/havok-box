"""Exact-command preview for the approval sheet.

The confirm sheet must show the command that will really run. These builders call the SAME
argv builders the tools use, with the task's frozen mode, so the preview can't drift from the
run. A tool with no builder here shows "not available" and the sheet won't offer Run.
"""
from __future__ import annotations

import shlex

from .tools import kismet, nmap


def _nmap_discovery(target, mode, scope):
    return nmap.build_discovery_cmd(target["network"], [str(e) for e in scope.exclude])


def _nmap_services(target, mode, scope):
    return nmap.build_services_cmd(target["ip"], mode)


def _kismet_scan(target, mode, scope):
    return list(kismet.KISMET_CMD)


BUILDERS = {
    "nmap.discovery": _nmap_discovery,
    "nmap.services": _nmap_services,
    "kismet.scan": _kismet_scan,
}


def command_for(task: dict, scope) -> str | None:
    fn = BUILDERS.get(task.get("tool"))
    if fn is None:
        return None
    try:
        argv = fn(task.get("target") or {}, task.get("mode", "stealth"), scope)
    except (KeyError, TypeError, ValueError):
        return None
    return shlex.join(argv)
