"""Follow-me detection (pure, no DB): a device seen at >=2 of your stops >=2 km apart."""
from __future__ import annotations

import math
import statistics

NEAR_M = 200.0
MIN_SPAN_M = 2000.0
CLOSE_RSSI = -70


def haversine_m(lat1, lon1, lat2, lon2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371000.0 * 2 * math.asin(min(1.0, math.sqrt(a)))


def assess(stops: list[dict], cells_by_device: dict, mine: set | frozenset = frozenset(),
           present_at_start: set | frozenset = frozenset()) -> list[dict]:
    """Return follow alerts (high severity first). See module docstring for rules."""
    alerts = []
    for key, dev in cells_by_device.items():
        if key in mine:
            continue
        obs = dev.get("obs") or []
        matched = []   # (stop, [obs])
        for st in stops:
            hits = [o for o in obs
                    if st["start"] <= o["ts"] <= st["end"]
                    and haversine_m(st["lat"], st["lon"], o["lat"], o["lon"]) <= NEAR_M]
            if hits:
                matched.append((st, hits))
        span = 0.0
        ok = False
        for i, (a, _) in enumerate(matched):
            for b, _ in matched[i + 1:]:
                first, second = (a, b) if a["start"] <= b["start"] else (b, a)
                d = haversine_m(a["lat"], a["lon"], b["lat"], b["lon"])
                span = max(span, d)
                if d >= MIN_SPAN_M and second["start"] > first["end"]:
                    ok = True
        if not ok:
            continue
        hit_obs = [o for _, hs in matched for o in hs]
        rssis = [o["rssi"] for o in hit_obs if o.get("rssi") is not None]
        med = statistics.median(rssis) if rssis else None
        kind = dev.get("kind")
        sev = "high" if kind else "medium"
        if sev == "medium" and med is not None and med > CLOSE_RSSI:
            sev = "high"
        ts = [o["ts"] for o in hit_obs]
        alerts.append({"kind": "follow", "dev_key": key, "severity": sev, "tracker": kind,
                       "stops_matched": len(matched), "span_m": round(span),
                       "first_ts": min(ts), "last_ts": max(ts), "median_rssi": med,
                       "present_at_start": key in present_at_start})
    alerts.sort(key=lambda a: (a["severity"] != "high", a["dev_key"]))
    return alerts
