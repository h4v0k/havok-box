"""Export helpers (design #14): Kismet's own converters for WiGLE/KML, plus our BLE cells CSV."""
from __future__ import annotations

import csv
import io
import os

BLE_COLUMNS = ["dev_id", "name", "kind", "tracker", "first_seen", "last_seen", "best_rssi", "lat", "lon"]


def wigle_argv(kismetdb_path: str, out_path: str) -> list[str]:
    return ["kismetdb_to_wiglecsv", "--in", kismetdb_path, "--out", out_path, "--force"]


def kml_argv(kismetdb_path: str, out_path: str) -> list[str]:
    return ["kismetdb_to_kml", "--in", kismetdb_path, "--out", out_path, "--force"]


def newest_kismetdb(log_dir: str, since_ts: float | None = None) -> str | None:
    best, best_m = None, None
    try:
        names = os.listdir(log_dir)
    except OSError:
        return None
    for n in names:
        if not n.endswith(".kismet"):
            continue
        p = os.path.join(log_dir, n)
        try:
            if not os.path.isfile(p):
                continue
            m = os.path.getmtime(p)
        except OSError:
            continue
        if since_ts is not None and m < since_ts:
            continue
        if best_m is None or m > best_m:
            best, best_m = p, m
    return best


def _cell(v):
    if v is None:
        return ""
    s = str(v)
    if s and s[0] in "=+-@\t\r":
        s = "'" + s
    return s


def ble_csv(rows) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    w.writerow(BLE_COLUMNS)
    for r in rows or []:
        get = r.get if isinstance(r, dict) else (lambda k, r=r: None)
        w.writerow([_cell(get(c)) for c in BLE_COLUMNS])
    return buf.getvalue()
