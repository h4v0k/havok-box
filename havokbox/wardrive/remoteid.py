"""ASTM F3411 Remote ID over BLE legacy advertising (Phase 6 #7-#10). Receive only.

Input is one `btcommon.eir_ad.entry.service_data` entry as hex. Layout assumed (MUST be confirmed
against a real capture on the device before relying on any value):

  [faff]  optional 16-bit service UUID 0xFFFA, little-endian (tshark may or may not include it)
  0d      ASTM application code
  cc      message counter
  25 bytes message; byte 0 = header, type = high nibble, version = low nibble

  Type 0 Basic ID : b1 = id_type(hi nibble)|ua_type(lo nibble); b2..21 UAS ID (ASCII, NUL padded)
  Type 1 Location : b1 status flags: bits7-4 op status, bit2 height type, bit1 E/W, bit0 speed mult
                    b2 direction (+180 if E/W bit), b3 h-speed, b4 v-speed int8 *0.5,
                    b5..8 lat int32 LE *1e-7, b9..12 lon, b13..14 pressure alt, b15..16 geodetic alt,
                    b17..18 height (all uint16 LE *0.5 - 1000)
  Type 4 System   : b1 flags; b2..5 operator lat int32 LE *1e-7, b6..9 operator lon
  Type 5 OperatorID: b1 id type; b2..21 ASCII
  Type 0xF message pack, and any other type: not decoded (returns None).
Wi-Fi beacon/NAN Remote ID is out of scope (most DJI drones are missed).
"""
from __future__ import annotations

import math
import re
import struct

APP_CODE = 0x0D
MSG_LEN = 25
NEAR_M = 300.0


def _ascii(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("ascii", "replace").strip()


def _alt(raw: int):
    v = raw * 0.5 - 1000.0
    return None if v <= -1000.0 else round(v, 1)


def _coord(lat: float, lon: float):
    if (lat == 0 and lon == 0) or abs(lat) > 90 or abs(lon) > 180:
        return None
    return round(lat, 7), round(lon, 7)


def parse_service_data(hexstr: str):
    """Parse one service-data entry -> dict (with "type") or None."""
    h = re.sub(r"[^0-9a-fA-F]", "", hexstr or "").lower()
    if len(h) % 2:
        return None
    if h.startswith("faff"):
        h = h[4:]
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return None
    if len(raw) < 2 + MSG_LEN or raw[0] != APP_CODE:
        return None
    m = raw[2:2 + MSG_LEN]
    mtype, ver = m[0] >> 4, m[0] & 0x0F
    if mtype == 0:
        return {"type": "basic_id", "version": ver, "id_type": m[1] >> 4, "ua_type": m[1] & 0x0F,
                "ua_id": _ascii(m[2:22])}
    if mtype == 1:
        st = m[1]
        ew, mult = bool(st & 0x02), bool(st & 0x01)
        pos = _coord(*(v * 1e-7 for v in struct.unpack_from("<ii", m, 5)))
        if pos is None:
            return None
        direction = m[2] + (180 if ew else 0)
        speed = None if m[3] == 255 else (m[3] * 0.75 + 63.75 if mult else m[3] * 0.25)
        pa, ga, ht = struct.unpack_from("<HHH", m, 13)
        alt = _alt(ga)
        if alt is None:
            alt = _alt(pa)
        return {"type": "location", "version": ver, "lat": pos[0], "lon": pos[1], "alt": alt,
                "height": _alt(ht), "speed": None if speed is None else round(speed, 2),
                "vspeed": struct.unpack_from("<b", m, 4)[0] * 0.5,
                "direction": direction, "height_agl": bool(st & 0x04)}
    if mtype == 4:
        pos = _coord(*(v * 1e-7 for v in struct.unpack_from("<ii", m, 2)))
        if pos is None:
            return {"type": "system", "version": ver, "op_lat": None, "op_lon": None}
        return {"type": "system", "version": ver, "op_lat": pos[0], "op_lon": pos[1]}
    if mtype == 5:
        return {"type": "operator_id", "version": ver, "operator_id": _ascii(m[2:22])}
    return None


def _dist_m(lat1, lon1, lat2, lon2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = (math.sin((p2 - p1) / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2)
    return 12742000.0 * math.asin(math.sqrt(a))


class DroneTracker:
    """Per-drone merged state, RAM only. Operator location expires after ttl_s and is then
    removed from state and never returned."""

    def __init__(self, ttl_s: float = 600):
        self.ttl_s = ttl_s
        self._d: dict[str, dict] = {}

    def update(self, addr: str, msgs, ts: float) -> None:
        d = self._d.setdefault(addr, {"addr": addr, "ua_id": None, "lat": None, "lon": None,
                                      "alt": None, "speed": None, "op_lat": None, "op_lon": None,
                                      "op_ts": None, "last_seen": ts, "near_since": None})
        d["last_seen"] = ts
        for m in msgs or []:
            if not isinstance(m, dict):
                continue
            t = m.get("type")
            if t == "basic_id" and m.get("ua_id"):
                d["ua_id"] = m["ua_id"]
            elif t == "location":
                d.update(lat=m["lat"], lon=m["lon"], alt=m.get("alt"), speed=m.get("speed"))
            elif t == "system" and m.get("op_lat") is not None:
                d.update(op_lat=m["op_lat"], op_lon=m["op_lon"], op_ts=ts)

    def _expire(self, now: float) -> None:
        for addr in [a for a, d in self._d.items() if now - d["last_seen"] > self.ttl_s]:
            del self._d[addr]
        for d in self._d.values():
            if d["op_ts"] is not None and now - d["op_ts"] > self.ttl_s:
                d.update(op_lat=None, op_lon=None, op_ts=None)

    def drones(self, now: float) -> list[dict]:
        self._expire(now)
        keys = ("addr", "ua_id", "lat", "lon", "alt", "speed", "op_lat", "op_lon", "last_seen")
        return [{k: d[k] for k in keys} for d in self._d.values()]

    def near_for(self, addr: str, car_lat: float, car_lon: float, now: float) -> float:
        """Seconds the drone has continuously been within 300 m of the car, measured across
        successive calls (call once per poll). 0 if unknown, stale or outside the radius."""
        self._expire(now)
        d = self._d.get(addr)
        if d is None or d["lat"] is None or _dist_m(car_lat, car_lon, d["lat"], d["lon"]) > NEAR_M:
            if d is not None:
                d["near_since"] = None
            return 0.0
        if d["near_since"] is None:
            d["near_since"] = now
        return max(0.0, now - d["near_since"])
