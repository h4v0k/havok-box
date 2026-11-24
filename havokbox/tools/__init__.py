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
_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")   # safe file/capture names: no paths, no dots

# Hardware defaults (overridden by config "hw"). Prefer /dev/serial/by-id paths on the Pi.
DEFAULT_HW = {
    "wired_iface": "eth0",
    "wifi_iface": "wlan1",          # Alfa, managed name
    "wifi_mon_iface": "wlan1mon",   # Alfa in monitor mode
    "bt_iface": "hci0",
    "sniffle_port": "/dev/ttyUSB0",
    "flipper_port": "/dev/ttyACM0",
    "marauder_port": "/dev/ttyUSB1",
    "sniffle_dir": "/opt/sniffle",
    "kismet_header": "/data/havokbox/secrets/kismet.header",  # "Cookie: KISMET=<key>", chmod 600
    "kismet_log_dir": "/data/havokbox/kismet",   # Kismet's log_prefix (kismetdb files)
    # RTL-SDR dongles by serial (set with rtl_eeprom -s). Empty = device 0 (single-dongle boxes).
    "sdr_serial": "",       # main dongle: TPMS, rtl_433, rtl_power
    "sdr2_serial": "",      # optional second dongle: ADS-B
    "tmpfs_dir": "/run/havokbox",   # scratch for readsb JSON (RAM, not the data partition)  # Sniffle checkout (python_cli/sniff_receiver.py)
    "work_dir": "/data/havokbox/work",
}


@dataclass
class ToolCtx:
    runner: object   # callable(list[str]) -> str (stdout)
    mode: str
    scope: object
    hw: dict = field(default_factory=lambda: dict(DEFAULT_HW))


@dataclass
class ToolSpec:
    name: str
    category: str                 # the gate category this tool ALWAYS runs under
    params: dict                  # field name -> {"type": ..., "required": bool, "min"/"max"/"choices"}
    fn: object                    # callable(task, ctx) -> result dict
    space: str = ""
    # build(target, mode, scope, hw) -> list of argv lists: EXACTLY what fn will run, in order.
    # Used for the confirm-sheet preview and the approval digest. fn must call the same builder.
    build: object = None
    # Executable the tool needs installed, when build's argv[0] is a python -m helper (inventory).
    binary: str | None = None


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
            elif kind == "mac":
                if not _BSSID.match(str(value)):
                    return False, f"{name}: not a MAC address"
            elif kind in ("number", "int"):
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    return False, f"{name}: not a number"
                if kind == "int" and not isinstance(value, int):
                    return False, f"{name}: not an integer"
                if "min" in meta and value < meta["min"]:
                    return False, f"{name}: below {meta['min']}"
                if "max" in meta and value > meta["max"]:
                    return False, f"{name}: above {meta['max']}"
            elif kind == "name":
                if not isinstance(value, str) or not _NAME.match(value) or value.startswith("-"):
                    return False, f"{name}: must be 1-64 of A-Z a-z 0-9 _ - and not start with -"
            elif kind == "ssid":
                if not isinstance(value, str) or not (1 <= len(value) <= 32) or \
                        any(ord(c) < 0x20 or ord(c) == 0x7f for c in value):
                    return False, f"{name}: ssid must be 1-32 printable characters"
            elif kind == "choice":
                if value not in meta.get("choices", ()):
                    return False, f"{name}: must be one of {list(meta.get('choices', ()))}"
            elif kind == "str":
                if not isinstance(value, str):
                    return False, f"{name}: not a string"
            else:
                return False, f"{name}: unknown param type {kind!r}"   # fail closed
        except ValueError:
            return False, f"{name}: not a valid {kind}"
    return True, "ok"
