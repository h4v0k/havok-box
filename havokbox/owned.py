"""Things you've marked as yours from the dashboard, so you don't hand-edit config/scope.yaml.

/data/havokbox/owned.json (written only by the dashboard, mode 0640):

    {"ssids": [...], "bssids": [...], "ble": [...], "subghz": [...],
     "tx_bands": [{"min_mhz", "max_mhz", "label"}],
     "never": [...cidrs] or absent}

Everything here is ADDED to what the scope file lists, except "never": once you edit the never
list on the dashboard, the dashboard's list is the never list (the file's exclude is its starting
point). Each change is validated here and logged by the caller.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re

DEFAULT_PATH = "/data/havokbox/owned.json"
KINDS = ("ssid", "bssid", "ble", "subghz", "tx_band", "never")
_LISTS = {"ssid": "ssids", "bssid": "bssids", "ble": "ble", "subghz": "subghz"}
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_LABEL = re.compile(r"^[A-Za-z0-9 ._()-]{0,40}$")
MAX_ITEMS = 256
TX_MIN, TX_MAX = 300.0, 928.0     # what the Yard Stick can tune; widest band 2 MHz


class OwnedError(ValueError):
    pass


def read(path: str | None) -> dict:
    if not path:
        return {}
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=1)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def normalize(kind: str, value) -> object:
    """Validate one item; returns its stored form or raises OwnedError."""
    if kind not in KINDS:
        raise OwnedError(f"unknown kind {kind!r}")
    if kind == "ssid":
        v = value if isinstance(value, str) else ""
        if not (1 <= len(v) <= 32) or any(ord(c) < 0x20 or ord(c) == 0x7f for c in v):
            raise OwnedError("network name must be 1-32 printable characters")
        return v
    if kind in ("bssid", "ble"):
        v = str(value or "").strip().lower()
        if not _MAC.match(v):
            raise OwnedError("that isn't a MAC address (aa:bb:cc:dd:ee:ff)")
        return v
    if kind == "subghz":
        v = str(value or "").strip()
        if not _ID.match(v):
            raise OwnedError("capture name: 1-64 of A-Z a-z 0-9 _ -")
        return v.lower()
    if kind == "never":
        try:
            return str(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError:
            raise OwnedError(f"{value!r} isn't an IP range (e.g. 192.168.1.0/24)")
    # tx_band: {"min_mhz", "max_mhz", "label"} or a single "mhz" (becomes ±0.1 MHz)
    v = value if isinstance(value, dict) else {}
    try:
        if "mhz" in v:
            lo, hi = float(v["mhz"]) - 0.1, float(v["mhz"]) + 0.1
        else:
            lo, hi = float(v["min_mhz"]), float(v["max_mhz"])
    except (KeyError, TypeError, ValueError):
        raise OwnedError("give a frequency in MHz, e.g. 390")
    if not (TX_MIN <= lo < hi <= TX_MAX) or hi - lo > 2.0:
        raise OwnedError(f"band must be inside {TX_MIN:.0f}-{TX_MAX:.0f} MHz and at most 2 MHz wide")
    label = str(v.get("label") or f"{(lo + hi) / 2:.3f} MHz")[:40]
    if not _LABEL.match(label):
        raise OwnedError("label: letters, numbers, spaces, . _ ( ) -")
    return {"min_mhz": round(lo, 4), "max_mhz": round(hi, 4), "label": label}


def add(path: str, kind: str, value, file_never=()) -> dict:
    item = normalize(kind, value)
    data = read(path)
    if kind == "never":
        cur = data.get("never")
        cur = list(cur) if isinstance(cur, list) else [str(n) for n in file_never]
        if item not in cur:
            cur.append(item)
        data["never"] = cur
    else:
        key = "tx_bands" if kind == "tx_band" else _LISTS[kind]
        cur = [x for x in data.get(key) or []]
        if item not in cur:
            if len(cur) >= MAX_ITEMS:
                raise OwnedError("too many items; remove some first")
            cur.append(item)
        data[key] = cur
    _write(path, data)
    return data


def remove(path: str, kind: str, value, file_never=()) -> dict:
    data = read(path)
    if kind == "never":
        item = normalize(kind, value)
        cur = data.get("never")
        cur = list(cur) if isinstance(cur, list) else [str(n) for n in file_never]
        data["never"] = [n for n in cur if n != item]
    elif kind == "tx_band":
        item = normalize(kind, value)
        data["tx_bands"] = [b for b in data.get("tx_bands") or []
                            if not (b.get("min_mhz") == item["min_mhz"] and b.get("max_mhz") == item["max_mhz"])]
    elif kind in _LISTS:
        item = normalize(kind, value)
        data[_LISTS[kind]] = [x for x in data.get(_LISTS[kind]) or [] if x != item]
    else:
        raise OwnedError(f"unknown kind {kind!r}")
    _write(path, data)
    return data


# ---- read side, used by Scope (tolerant: a bad entry is skipped, never widens anything odd) ----

def strings(data: dict, key: str, lower: bool = True) -> set:
    out = set()
    for x in data.get(key) or []:
        if isinstance(x, str) and x:
            out.add(x.lower() if lower else x)
    return out


def bands(data: dict) -> list[tuple[float, float]]:
    out = []
    for b in data.get("tx_bands") or []:
        try:
            lo, hi = float(b["min_mhz"]), float(b["max_mhz"])
        except (KeyError, TypeError, ValueError):
            continue
        if TX_MIN <= lo < hi <= TX_MAX and hi - lo <= 2.0:
            out.append((lo, hi))
    return out


def never(data: dict):
    """The dashboard's never list as ip_networks, or None if it was never edited there."""
    cur = data.get("never")
    if not isinstance(cur, list):
        return None
    out = []
    for c in cur:
        try:
            out.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            continue
    return out
