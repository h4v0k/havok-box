"""Kismet REST polling for wardrive: pinned argv builders and pure parsers (no I/O here).

The service runs the argv through an injected runner. The API key lives only in the header file
(`-H @file`), never in argv.
"""
from __future__ import annotations

import json

BASE = "http://localhost:2501"
DEFAULT_HEADER_FILE = "/data/havokbox/secrets/kismet.header"

DEVICE_FIELDS = [
    "kismet.device.base.macaddr",
    "kismet.device.base.type",
    "kismet.device.base.commonname",
    "kismet.device.base.name",
    "kismet.device.base.channel",
    "kismet.device.base.signal/kismet.common.signal.last_signal",
    "kismet.device.base.location/kismet.common.location.avg_loc/kismet.common.location.geopoint",
    "kismet.device.base.last_time",
]

ATTACK_HEADERS = {
    "DEAUTHFLOOD", "BCASTDISCON", "DISASSOCTRAFFIC", "CHANCHANGE", "APSPOOF", "BSSTIMESTAMP",
    "CRYPTODROP", "NULLPROBERESP", "DISCONCODEINVALID", "LONGSSID", "MSFBCOMSSID", "MSFDLINKRATE",
    "MSFNETGEARBEACON", "AIRJACKSSID", "WMMTSPEC", "KARMAOUI", "PROBENOJOIN", "NETSTUMBLER",
    "LUCENTTEST", "DHCPCLIENTID", "DHCPCONFLICT", "DHCPNAMECHANGE", "DHCPOSCHANGE", "ADHOCCONFLICT",
    "OUIFLOOD", "SSIDMISMATCH",
}


def _header(hw) -> str:
    return (hw or {}).get("kismet_header") or DEFAULT_HEADER_FILE


def _argv(hw, url: str, post: dict | None = None) -> list[str]:
    argv = ["curl", "-s", "--fail", "--max-time", "10", "-H", f"@{_header(hw)}"]
    if post is not None:
        argv += ["-d", "json=" + json.dumps(post, separators=(",", ":"))]
    return argv + [url]


def _since(since_s) -> int:
    try:
        return max(1, int(since_s))
    except (TypeError, ValueError):
        return 15


def devices_argv(hw: dict, since_s: int = 15) -> list[str]:
    return _argv(hw, f"{BASE}/devices/last-time/-{_since(since_s)}/devices.json",
                 {"fields": DEVICE_FIELDS})


def alerts_argv(hw: dict, since_s: int = 15) -> list[str]:
    return _argv(hw, f"{BASE}/alerts/last-time/-{_since(since_s)}/alerts.json")


def _load(raw):
    if isinstance(raw, (list, dict)):
        return raw
    try:
        return json.loads(raw) if raw and str(raw).strip() else None
    except (ValueError, TypeError):
        return None


def _num(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _get(d: dict, *keys):
    """Look up a key by its full name or the last path segment of a 'a/b/c' field path."""
    for k in keys:
        if k in d:
            return d[k]
    return None


def _dig(d, path: str):
    cur = d
    for part in path.split("/"):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _loc(d: dict):
    geo = None
    for key in ("kismet.device.base.location", "location"):
        loc = d.get(key)
        if isinstance(loc, dict):
            avg = loc.get("kismet.common.location.avg_loc")
            if isinstance(avg, dict):
                geo = avg.get("kismet.common.location.geopoint")
            if geo is None:
                geo = loc.get("kismet.common.location.geopoint")
    flat = d.get("kismet.common.location.geopoint")
    geo = geo if geo is not None else flat
    if isinstance(geo, list) and len(geo) >= 2:
        lon, lat = _num(geo[0]), _num(geo[1])   # Kismet geopoint is [lon, lat]
        if lat is not None and lon is not None and (lat or lon) and abs(lat) <= 90 and abs(lon) <= 180:
            return lat, lon
    return None, None


def parse_devices(raw) -> list[dict]:
    data = _load(raw)
    out = []
    for d in data if isinstance(data, list) else []:
        if not isinstance(d, dict):
            continue
        mac = _get(d, "kismet.device.base.macaddr", "macaddr")
        if not isinstance(mac, str) or not mac.strip():
            continue
        typ = str(_get(d, "kismet.device.base.type", "type") or "")
        kind = "ap" if typ.lower().endswith("ap") else "client"
        name = _get(d, "kismet.device.base.commonname", "commonname") \
            or _get(d, "kismet.device.base.name", "name") or None
        sig = _get(d, "kismet.device.base.signal")
        rssi = None
        if isinstance(sig, dict):
            rssi = _num(sig.get("kismet.common.signal.last_signal"))
        if rssi is None:
            rssi = _num(d.get("kismet.common.signal.last_signal", d.get("signal")))
        if rssi == 0:
            rssi = None
        lat, lon = _loc(d)
        out.append({
            "dev_id": mac.strip().lower(), "radio": "wifi", "kind": kind,
            "name": str(name)[:64] if name else None,
            "channel": _get(d, "kismet.device.base.channel", "channel") or None,
            "rssi": int(rssi) if rssi is not None else None,
            "lat": lat, "lon": lon,
            "ts": _num(_get(d, "kismet.device.base.last_time", "last_time")),
        })
        if len(out) >= 2000:
            break
    return out


def _text(v) -> str:
    return " ".join(str(v).split())[:200] if v is not None else ""


def parse_alerts(raw) -> list[dict]:
    data = _load(raw)
    if isinstance(data, dict):
        data = data.get("kismet.alert.list") or data.get("alerts") or []
    out = []
    for a in data if isinstance(data, list) else []:
        if not isinstance(a, dict):
            continue
        header = str(a.get("kismet.alert.header") or a.get("header") or "").upper()
        if header not in ATTACK_HEADERS:
            continue
        dev = a.get("kismet.alert.transmitter_mac") or a.get("kismet.alert.source_mac") \
            or a.get("transmitter_mac") or a.get("source_mac")
        if isinstance(dev, str) and dev.strip() and dev.strip() != "00:00:00:00:00:00":
            dev = dev.strip().lower()
        else:
            dev = None
        out.append({
            "kind": header, "dev_id": dev,
            "detail": _text(a.get("kismet.alert.text") or a.get("text")),
            "ts": _num(a.get("kismet.alert.timestamp") or a.get("timestamp")),
            "severity": "medium",
        })
        if len(out) >= 500:
            break
    return out


def alert_bucket(ts, minutes: int = 10) -> int:
    t = _num(ts) or 0
    return int(t // (max(1, int(minutes)) * 60))
