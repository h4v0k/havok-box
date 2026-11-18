"""Recipe loader (design-kali-pack §1).

An owner-written YAML file (config/recipes.yaml) turns any installed tool into a gated dashboard
button with no code wrapper. A recipe becomes a ToolSpec that goes through the exact same path as
every built-in tool: registry -> category binding -> scope gate -> typed params -> approval ->
orchestrator. There is never a shell.

Fail-closed validation (a bad recipe is dropped and logged, the rest still load):
  - name starts with "recipe.", unique, [a-z0-9._-].
  - category is a known gate category; the recipe declares the gate target key that category needs
    (recon.active/auth.attempt/exploit.tool -> ip; wifi.* -> bssid; ble.active -> addr;
    net.poison -> network; wifi.rogue_ap -> ssid; rf.* -> id + freq_mhz), and that param is declared.
  - argv[0] is a real binary, never a shell/interpreter, and contains no placeholder.
  - every {placeholder} in argv is a declared param; no param is type "str" (unbounded free text).
  - placeholders fill whole argv elements or part of one, by value, after validate_params — never
    via a shell. Defaults are applied in build() so the approval digest covers the real command.
"""
from __future__ import annotations

import re

from .scope import BLE_CATEGORIES, NETWORK_CATEGORIES, POISON, ROGUE_AP, RF_TX_CATEGORIES, WIFI_CATEGORIES
from .tools import ToolSpec, validate_params

NAME_RE = re.compile(r"^recipe\.[a-z0-9._-]{1,48}$")
PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
SHELLS = {"sh", "bash", "zsh", "dash", "ash", "ksh", "csh", "tcsh", "fish", "busybox", "env",
          "perl", "ruby", "php", "lua", "node", "nodejs", "awk", "gawk", "nawk", "xargs",
          "eval", "exec", "command", "source", "."}
PY = re.compile(r"^python[0-9.]*$")
PARSERS = {"lines", "json", "xml", "none"}
# the gate target key each category requires, so a recipe can't declare an active category with no
# scoped target and sneak past the gate on a missing-key refusal
REQUIRED_KEY = {c: "ip" for c in NETWORK_CATEGORIES}
REQUIRED_KEY.update({c: "bssid" for c in WIFI_CATEGORIES})
REQUIRED_KEY.update({c: "addr" for c in BLE_CATEGORIES})
REQUIRED_KEY.update({c: "id" for c in RF_TX_CATEGORIES})
REQUIRED_KEY[POISON] = "network"
REQUIRED_KEY[ROGUE_AP] = "ssid"
PARAM_TYPES = {"cidr", "ip", "bssid", "mac", "int", "number", "name", "choice"}   # never "str"
MAX_TIMEOUT = 900


class RecipeError(ValueError):
    pass


def _apply(token: str, target: dict) -> str:
    return PLACEHOLDER_RE.sub(lambda m: str(target[m.group(1)]), token)


def _validate(rec: dict, known_categories: set) -> dict:
    if not isinstance(rec, dict):
        raise RecipeError("recipe is not a mapping")
    name = rec.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise RecipeError(f"bad recipe name {name!r} (must match {NAME_RE.pattern})")
    category = rec.get("category")
    if category not in known_categories:
        raise RecipeError(f"{name}: unknown category {category!r}")
    params = rec.get("params") or {}
    if not isinstance(params, dict):
        raise RecipeError(f"{name}: params must be a mapping")
    for pname, meta in params.items():
        if not isinstance(meta, dict) or meta.get("type") not in PARAM_TYPES:
            raise RecipeError(f"{name}: param {pname!r} needs a type in {sorted(PARAM_TYPES)} (not str)")
        if meta.get("type") == "choice" and not meta.get("choices"):
            raise RecipeError(f"{name}: choice param {pname!r} needs choices")
    need = REQUIRED_KEY.get(category)
    if need and need not in params:
        raise RecipeError(f"{name}: category {category} needs a declared {need!r} param for the gate")
    argv = rec.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise RecipeError(f"{name}: argv must be a non-empty list of strings")
    binary = argv[0]
    if PLACEHOLDER_RE.search(binary):
        raise RecipeError(f"{name}: argv[0] must be a literal binary, not a placeholder")
    base = binary.rsplit("/", 1)[-1]
    if base in SHELLS or PY.match(base):
        raise RecipeError(f"{name}: argv[0] {binary!r} is a shell/interpreter")
    for tok in argv:
        for ph in PLACEHOLDER_RE.findall(tok):
            if ph not in params:
                raise RecipeError(f"{name}: placeholder {{{ph}}} not a declared param")
    timeout = rec.get("timeout_s", 300)
    if not isinstance(timeout, int) or not (1 <= timeout <= MAX_TIMEOUT):
        raise RecipeError(f"{name}: timeout_s must be 1..{MAX_TIMEOUT}")
    parse = rec.get("parse", "lines")
    if parse not in PARSERS:
        raise RecipeError(f"{name}: parse must be one of {sorted(PARSERS)}")
    return {"name": name, "category": category, "space": str(rec.get("space") or "wired"),
            "phase": rec.get("phase", "recon"), "label": str(rec.get("label") or name),
            "params": params, "argv": argv, "timeout_s": timeout, "parse": parse}


def _parse_output(text: str, mode: str, cap: int = 200):
    text = text or ""
    if mode == "none":
        return {"bytes": len(text)}
    if mode == "json":
        import json
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(("{", "[")):
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
            if len(rows) >= cap:
                break
        return {"rows": rows}
    if mode == "xml":
        return {"xml_len": len(text)}        # kept raw-length only; a recipe can't guess a schema
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()][:cap]
    return {"lines": lines}


def make_spec(rec: dict):
    """Build a ToolSpec from a validated recipe dict. build() fills defaults then substitutes
    placeholders by value (no shell); fn runs exactly that argv and parses generically."""
    from .store import new_id

    def build(target, mode, scope, hw, _rec=rec):
        t = dict(target or {})
        for pname, meta in _rec["params"].items():
            if pname not in t and "default" in meta:
                t[pname] = meta["default"]
        argv = [_apply(tok, t) for tok in _rec["argv"]]
        return [["timeout", str(_rec["timeout_s"])] + argv]

    def fn(task, ctx, _rec=rec):
        argv = build(task.get("target"), ctx.mode, ctx.scope, ctx.hw)[0]
        out = ctx.runner(argv)
        data = _parse_output(out, _rec["parse"])
        n = data.get("lines") and len(data["lines"]) or data.get("rows") and len(data["rows"]) or 0
        return {"result_id": new_id(), "space": _rec["space"], "kind": "recipe",
                "summary": f"{_rec['name']}: {n} result line(s)" if n else f"{_rec['name']}: done",
                "data": {"recipe": _rec["name"], **data}}

    spec = ToolSpec(name=rec["name"], category=rec["category"], params=rec["params"], fn=fn,
                    space=rec["space"], build=build)
    spec.binary = rec["argv"][0].rsplit("/", 1)[-1]
    spec.phase = rec["phase"]
    spec.label = rec["label"]
    spec.recipe = True
    return spec


def load_recipes(path: str, known_categories: set, log=None) -> dict:
    """Read config/recipes.yaml once at boot. Returns {name: ToolSpec}. A bad recipe is dropped
    (logged) and never blocks the good ones; a missing file is fine."""
    import os
    if not path or not os.path.exists(path):
        return {}
    import yaml
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except Exception as exc:
        if log:
            log("recipe", f"recipes.yaml unreadable: {exc}")
        return {}
    if not isinstance(doc, list):
        if log:
            log("recipe", "recipes.yaml is not a list of recipes")
        return {}
    out, seen = {}, set()
    for rec in doc:
        try:
            v = _validate(rec, known_categories)
            if v["name"] in seen:
                raise RecipeError(f"duplicate recipe name {v['name']}")
            seen.add(v["name"])
            out[v["name"]] = make_spec(v)
        except RecipeError as exc:
            if log:
                log("recipe", f"dropped: {exc}")
    return out
