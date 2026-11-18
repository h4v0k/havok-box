# Tool worker contract

How to add a tool. Read `docs/workflows.md` (which Kali tool sits behind which button) and
`havokbox/tools/nmap.py` (the reference implementation) first. **Lab-only: wrap standard installed
tools; write no exploit code or payloads.**

## A tool module

Each tool is three pure pieces plus a run function, in `havokbox/tools/<group>.py`:

```python
def build_<x>(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    """EXACT argv list(s) the run function executes, in order. Deterministic: same inputs ->
    same output (no timestamps, random names or task ids) because the approval digest covers it."""

def parse_<x>(stdout: str) -> ...:        # pure, fixture-tested, tolerant of junk/empty output

def <x>(task: dict, ctx) -> dict:          # the ToolSpec.fn
    steps = build_<x>(task["target"], ctx.mode, ctx.scope, ctx.hw)
    out = [ctx.runner(argv) for argv in steps]   # ctx.runner(list[str]) -> stdout str
    ...parse...
    return {"result_id": new_id(), "space": "<space>", "kind": "<kind>",
            "summary": "<one short line>", "data": {...small, parsed...}}
```

Rules:
- `build_*` must be what `fn` runs — call it from `fn`, never re-assemble argv elsewhere.
- argv lists only. Never `sh -c`, never a shell string, never `shell=True`.
- Every user-influenced value comes from `target` after `validate_params`. Never put free text in argv
  except via a typed param (`name` type for file/capture names).
- Interfaces and serial ports come from `hw` (see `DEFAULT_HW` in `havokbox/tools/__init__.py`),
  never from `target`.
- Anything that needs files, timing, two processes at once, or a serial conversation goes in a
  helper: `havokbox/helpers/<name>.py`, run as `["python3", "-m", "havokbox.helpers.<name>", --args...]`.
  A helper runs the real tools with `subprocess.run([...])` (argv, timeout), writes any files under
  `hw["work_dir"]`, and prints ONE JSON object to stdout. Helper logic must be importable and
  testable with an injected runner/serial object; `main()` only parses args.
- Bounded: every capture/listen has a duration (`timeout` / `-T` / `--seconds`), capped (≤ 600 s).
- `data` stays small: cap lists (64 items) — the dashboard and the commander digest read it.
- Parsing happens on the box. Only the parsed `data` leaves the tool.

## ToolSpec (you return these; the integrator adds them to `tools/registry.py`)

```python
ToolSpec(name="group.action", category="recon.passive", space="wifi",
         params={"bssid": {"type": "bssid", "required": True},
                 "seconds": {"type": "int", "min": 5, "max": 600}},
         fn=module.action, build=lambda t, mode, scope, hw: module.build_action(t, mode, scope, hw))
```

Param types: `cidr`, `ip`, `bssid`, `mac`, `int`/`number` (with `min`/`max`), `name`
(`[A-Za-z0-9_-]{1,64}`), `choice` (with `choices`), `str`. Optional params need defaults applied in
`build_*` so the preview shows the real value.

## Gate categories (the tool's category is fixed; the gate decides)

| Category | Target key that must be in scope | Approval |
|---|---|---|
| `recon.passive` | none (listening only) | no |
| `recon.discovery` | `network` in networks.include | per scope `auto_allow` |
| `recon.active` | `ip` in networks.include, not excluded | yes |
| `wifi.capture` / `wifi.deauth` / `wifi.inject` | `bssid` in wifi.bssids | yes |
| `ble.active` | `addr` in rf.ble_addresses | yes |
| `rf.replay` / `rf.transmit` | `id` in rf.subghz_ids or rf.ble_addresses AND `freq_mhz` in an rf.tx_bands entry | yes |

Use exactly these target key names for gated tools, or the gate refuses (fail-closed).

## Tests

`tests/test_<group>.py`, stdlib `unittest`, no network, no hardware: fixture stdout strings for
parsers, a recording fake runner for `fn`, and a check that `fn` runs exactly `build_*`'s argv.
Run `python3 -m unittest discover -s tests` from the repo root; keep the whole suite green.
