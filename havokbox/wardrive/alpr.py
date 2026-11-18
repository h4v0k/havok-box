"""ALPR camera warnings: Overpass fetch/validate (untrusted input), cache, grid index, warner.

Data is OpenStreetMap (c) contributors, ODbL. Never published. Only id, lat/lon, direction kept.
"""
from __future__ import annotations

import json
import math
import os
import urllib.error
import urllib.request

OVERPASS_URL = "https://overpass-api.de/api/interpreter"
DEFAULT_BBOX = (27.55, -82.85, 28.45, -82.05)  # s, w, n, e (Tampa Bay)
MAX_BYTES = 20 * 1024 * 1024
ATTRIBUTION = "Camera data (c) OpenStreetMap contributors, ODbL"
M_PER_DEG = 111320.0

COMPASS = {
    "N": 0, "NNE": 22.5, "NE": 45, "ENE": 67.5, "E": 90, "ESE": 112.5, "SE": 135, "SSE": 157.5,
    "S": 180, "SSW": 202.5, "SW": 225, "WSW": 247.5, "W": 270, "WNW": 292.5, "NW": 315,
    "NNW": 337.5,
    "NORTH": 0, "NORTHEAST": 45, "EAST": 90, "SOUTHEAST": 135, "SOUTH": 180,
    "SOUTHWEST": 225, "WEST": 270, "NORTHWEST": 315,
}


def query(bbox):
    s, w, n, e = bbox
    return f'[out:json][timeout:60];node["surveillance:type"="ALPR"]({s},{w},{n},{e});out body;'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _default_transport(url, data, timeout):
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"User-Agent": "havok-box/1"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(MAX_BYTES + 1)
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, b""


def fetch(bbox, transport=None, timeout=60):
    """POST the query; raises on non-200 (incl. 3xx) or oversize. transport(url, data, timeout)."""
    transport = transport or _default_transport
    status, body = transport(OVERPASS_URL, query(bbox).encode(), timeout)
    if status != 200:
        raise RuntimeError(f"overpass http {status}")
    body = bytes(body)
    if len(body) > MAX_BYTES:
        raise RuntimeError("overpass response too large")
    return body


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _parse_dir(v):
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        d = float(v)
    elif isinstance(v, str):
        s = v.strip().upper()
        if s in COMPASS:
            return float(COMPASS[s])
        try:
            d = float(s)
        except ValueError:
            return None
    else:
        return None
    if not math.isfinite(d) or d < 0 or d > 360:
        return None
    return d % 360.0


def validate(raw_bytes, bbox, cap=20000):
    try:
        doc = json.loads(raw_bytes)
        elements = doc.get("elements") if isinstance(doc, dict) else None
    except (ValueError, TypeError):
        return []
    if not isinstance(elements, list):
        return []
    s, w, n, e = bbox
    out = []
    for el in elements:
        try:
            if not isinstance(el, dict) or el.get("type", "node") != "node":
                continue
            lat, lon, eid = el.get("lat"), el.get("lon"), el.get("id")
            if not (_num(lat) and _num(lon)) or isinstance(eid, bool) or not isinstance(eid, int):
                continue
            if not (s <= lat <= n and w <= lon <= e):
                continue
            tags = el.get("tags") if isinstance(el.get("tags"), dict) else {}
            d = _parse_dir(tags.get("direction"))
            if d is None:
                d = _parse_dir(tags.get("camera:direction"))
            out.append({"id": str(eid), "lat": float(lat), "lon": float(lon), "dir": d})
            if len(out) >= cap:
                break
        except Exception:
            continue
    return out


def save_atomic(path, cams):
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(cams, f, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def load(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [c for c in data if isinstance(c, dict) and _num(c.get("lat")) and _num(c.get("lon"))
            and "id" in c]


def _dist_m(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = (math.sin((p2 - p1) / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2)
    return 2 * 6371000.0 * math.asin(min(1.0, math.sqrt(a)))


def bearing_deg(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return math.degrees(math.atan2(y, x)) % 360.0


def angle_diff(a, b):
    """Smallest absolute difference in degrees, 0..180."""
    d = abs(a - b) % 360.0
    return 360.0 - d if d > 180 else d


class Index:
    def __init__(self, cams, cell_m=1000):
        self.cell_m = cell_m
        self.cells: dict[tuple[int, int], list] = {}
        for c in cams:
            self.cells.setdefault(self._cell(c["lat"], c["lon"]), []).append(c)

    def _cell(self, lat, lon):
        mlon = M_PER_DEG * max(math.cos(math.radians(lat)), 1e-6)
        return (math.floor(lat * M_PER_DEG / self.cell_m), math.floor(lon * mlon / self.cell_m))

    def near(self, lat, lon, radius_m):
        mlat = M_PER_DEG
        mlon = M_PER_DEG * max(math.cos(math.radians(lat)), 1e-6)
        r0, c0 = math.floor(lat * mlat / self.cell_m), math.floor(lon * mlon / self.cell_m)
        k = int(radius_m // self.cell_m) + 1
        out = []
        for r in range(r0 - k, r0 + k + 1):
            for c in range(c0 - k - 1, c0 + k + 2):
                for cam in self.cells.get((r, c), ()):
                    d = _dist_m(lat, lon, cam["lat"], cam["lon"])
                    if d <= radius_m:
                        out.append((cam, d))
        out.sort(key=lambda t: t[1])
        return out


class Warner:
    MIN_SPEED = 4.0
    MIN_BASELINE_M = 50.0
    FACING_DEG = 60.0

    def __init__(self, index, radius_m=300, cone_deg=45, repeat_s=600):
        self.index, self.radius_m, self.cone_deg, self.repeat_s = index, radius_m, cone_deg, repeat_s
        self.prev: dict[str, float] = {}
        self.last_warned: dict[str, float] = {}
        self.passes = 0

    def _heading(self, lat, lon, speed, track, pts):
        if speed is not None and speed > self.MIN_SPEED and track is not None:
            return float(track) % 360.0
        for plat, plon in reversed(pts or []):
            if _dist_m(plat, plon, lat, lon) >= self.MIN_BASELINE_M:
                return bearing_deg(plat, plon, lat, lon)
        return None

    def update(self, ts, lat, lon, speed_mps, track_deg, recent_points):
        near = self.index.near(lat, lon, self.radius_m)
        prev, self.prev = self.prev, {c["id"]: d for c, d in near}
        heading = self._heading(lat, lon, speed_mps, track_deg, recent_points)
        if heading is None:
            return None
        for cam, d in near:  # nearest first
            cid = cam["id"]
            if angle_diff(heading, bearing_deg(lat, lon, cam["lat"], cam["lon"])) > self.cone_deg:
                continue
            if cid in prev and d >= prev[cid]:
                continue
            if cam.get("dir") is not None and angle_diff(
                    cam["dir"], bearing_deg(cam["lat"], cam["lon"], lat, lon)) > self.FACING_DEG:
                continue
            last = self.last_warned.get(cid)
            if last is not None and ts - last < self.repeat_s:
                continue
            self.last_warned[cid] = ts
            self.passes += 1
            return {"id": cid, "dist_m": d}
        return None
