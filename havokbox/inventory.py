"""Tool inventory — which registered tools have their binary installed (design-kali-pack §2).

At boot every ToolSpec declares the binary it runs (spec.binary, or the first argv element of a
zero-target build). A tool whose binary is missing (shutil.which) is hidden from the cards and the
planner, and listed on the Report tab as "not installed", so the dashboard never offers a button
that can only fail.
"""
from __future__ import annotations

import shutil

# argv[0] values that are never a real tool binary (a recipe/tool wrapper is refused earlier if its
# argv[0] is one of these; here we just never treat them as an installed-binary signal).
_NON_BINARIES = {"timeout", "env", "sh", "bash", "python3", "python", "stdbuf"}


def binary_of(spec) -> str | None:
    """The executable a ToolSpec needs installed, if we can tell."""
    b = getattr(spec, "binary", None)
    if b:
        return b
    build = getattr(spec, "build", None)
    if build is None:
        return None
    try:
        steps = build({}, "stealth", None, {})
    except Exception:
        return None
    if not steps:
        return None
    argv = steps[0]
    for tok in argv:
        if tok == "timeout":            # ["timeout", "N", "realbin", ...]
            continue
        if tok.isdigit():
            continue
        if tok in _NON_BINARIES:
            # a python -m helper: we can't cheaply know the tool it shells out to; treat as present
            return None
        return tok
    return None


class Inventory:
    def __init__(self, registry: dict, which=shutil.which):
        self.installed: dict[str, bool] = {}
        self.missing: list[str] = []
        for name, spec in registry.items():
            b = binary_of(spec)
            ok = True if b is None else bool(which(b))
            self.installed[name] = ok
            if not ok:
                self.missing.append(name)
        self.missing.sort()

    def has(self, name: str) -> bool:
        return self.installed.get(name, True)
