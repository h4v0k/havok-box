"""Pure geo helpers for wardrive: distance, grid cells, track recording, stop detection."""
import math

EARTH_R = 6371000.0
M_PER_DEG_LAT = 111320.0


def haversine_m(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_R * math.asin(min(1.0, math.sqrt(a)))


def cell_id(lat, lon, size_m=250):
    """Stable grid cell '<row>:<col>'. Row is latitude in meters; column uses a fixed
    cos(cell-row-center latitude) so every point in a row shares the same column width."""
    row = math.floor(lat * M_PER_DEG_LAT / size_m)
    row_lat = (row + 0.5) * size_m / M_PER_DEG_LAT
    m_per_deg_lon = M_PER_DEG_LAT * max(math.cos(math.radians(row_lat)), 1e-6)
    col = math.floor(lon * m_per_deg_lon / size_m)
    return "%d:%d" % (row, col)


class TrackRecorder:
    def __init__(self, min_dist_m=25, min_interval_s=10):
        self.min_dist_m = min_dist_m
        self.min_interval_s = min_interval_s
        self.distance_m = 0.0
        self.last = None

    def offer(self, ts, lat, lon, fixq):
        if lat is None or lon is None:
            return None
        pt = {"ts": ts, "lat": lat, "lon": lon, "fixq": fixq}
        if self.last is None:
            self.last = pt
            return pt
        d = haversine_m(self.last["lat"], self.last["lon"], lat, lon)
        dt = ts - self.last["ts"]
        if d < self.min_dist_m and dt < self.min_interval_s:
            return None
        if not (d > 1000 and dt < 2):
            self.distance_m += d
        self.last = pt
        return pt


def find_stops(points, radius_m=150, min_dwell_s=300):
    stops = []
    n = len(points)
    i = 0
    while i < n:
        clat, clon, cnt = points[i]["lat"], points[i]["lon"], 1
        j = i + 1
        while j < n and haversine_m(clat, clon, points[j]["lat"], points[j]["lon"]) <= radius_m:
            cnt += 1
            clat += (points[j]["lat"] - clat) / cnt
            clon += (points[j]["lon"] - clon) / cnt
            j += 1
        start, end = points[i]["ts"], points[j - 1]["ts"]
        if end - start >= min_dwell_s:
            stops.append({"lat": clat, "lon": clon, "start": start, "end": end})
            i = j
        else:
            i += 1
    return stops
