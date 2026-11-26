"""rtl_power sweep -> waterfall PNG + strongest frequencies. Files only, no radio.

    python3 -m havokbox.helpers.sweep picture --dir ~/havok/kit --out sweep.png [--csv FILE]

Without --csv it uses the newest *.csv under --dir that looks like rtl_power output. The PNG is
written with zlib only (no matplotlib on the box). Prints one JSON object: the CSV used, the
picture's size, and up to 15 peaks (frequency, average and peak dB).
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import zlib

MAX_W, MAX_H = 1600, 1000
MAX_ROWS = 200_000


def find_csv(root: str) -> str | None:
    best, best_t = None, -1.0
    for dirpath, _d, files in os.walk(root):
        for f in files:
            if not f.endswith(".csv"):
                continue
            p = os.path.join(dirpath, f)
            try:
                t = os.path.getmtime(p)
                with open(p) as fh:
                    first = fh.readline()
            except OSError:
                continue
            if looks_like_rtl_power(first) and t > best_t:
                best, best_t = p, t
    return best


def looks_like_rtl_power(line: str) -> bool:
    parts = [x.strip() for x in line.split(",")]
    if len(parts) < 7:
        return False
    try:
        float(parts[2]); float(parts[3]); float(parts[4]); float(parts[6])
        return True
    except ValueError:
        return False


def parse(lines) -> tuple[list, float, float, float]:
    """-> (rows [(time_key, {bin_index: dB})], f_lo, f_hi, step)."""
    raw, f_lo, f_hi, step = [], None, None, None
    for n, line in enumerate(lines):
        if n >= MAX_ROWS:
            break
        p = [x.strip() for x in line.split(",")]
        if len(p) < 7:
            continue
        try:
            lo, hi, st = float(p[2]), float(p[3]), float(p[4])
            vals = [float(x) for x in p[6:] if x not in ("", "nan", "-nan")]
        except ValueError:
            continue
        if st <= 0 or not vals:
            continue
        raw.append((p[0] + " " + p[1], lo, st, vals))
        f_lo = lo if f_lo is None else min(f_lo, lo)
        f_hi = hi if f_hi is None else max(f_hi, hi)
        step = st if step is None else min(step, st)
    if not raw:
        return [], 0.0, 0.0, 0.0
    rows, index = [], {}
    for key, lo, st, vals in raw:
        if key not in index:
            index[key] = len(rows)
            rows.append((key, {}))
        cells = rows[index[key]][1]
        for i, v in enumerate(vals):
            b = int(round((lo + i * st - f_lo) / step))
            cells[b] = max(v, cells.get(b, v))
    return rows, f_lo, f_hi, step


def _color(x: float) -> tuple[int, int, int]:
    """0..1 -> black, blue, red, yellow, white."""
    stops = [(0, 0, 0), (0, 0, 180), (200, 0, 0), (255, 220, 0), (255, 255, 255)]
    x = min(1.0, max(0.0, x)) * (len(stops) - 1)
    i = min(int(x), len(stops) - 2)
    t = x - i
    a, b = stops[i], stops[i + 1]
    return tuple(int(a[k] + (b[k] - a[k]) * t) for k in range(3))


def png(width: int, height: int, rgb_rows) -> bytes:
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + bytes(r) for r in rgb_rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def picture(rows, f_lo, f_hi, step) -> tuple[bytes, int, int, list]:
    nbins = max(1, int(round((f_hi - f_lo) / step)))
    width = min(MAX_W, nbins)
    per_col = nbins / width
    stride = max(1, -(-len(rows) // MAX_H))
    sel = rows[::stride]
    allv = sorted(v for _k, c in sel for v in c.values())
    lo = allv[len(allv) * 5 // 100] if allv else -60.0
    hi = allv[min(len(allv) - 1, len(allv) * 995 // 1000)] if allv else 0.0
    span = (hi - lo) or 1.0
    img = []
    for _k, cells in sel:
        line = bytearray()
        for x in range(width):
            b0, b1 = int(x * per_col), max(int(x * per_col) + 1, int((x + 1) * per_col))
            vs = [cells[b] for b in range(b0, b1) if b in cells]
            line += bytes(_color(((max(vs) if vs else lo) - lo) / span))
        img.append(line)
    # peaks: average per bin over time, well above the median floor, neighbours merged
    sums, counts, peak = {}, {}, {}
    for _k, cells in rows:
        for b, v in cells.items():
            sums[b] = sums.get(b, 0.0) + v
            counts[b] = counts.get(b, 0) + 1
            peak[b] = max(v, peak.get(b, v))
    avg = {b: sums[b] / counts[b] for b in sums}
    floor = sorted(avg.values())[len(avg) // 2] if avg else 0.0
    hot = sorted((b for b, v in avg.items() if v >= floor + 10), key=lambda b: avg[b], reverse=True)
    peaks, taken = [], set()
    for b in hot:
        if any(abs(b - t) <= 3 for t in taken):
            continue
        taken.add(b)
        peaks.append({"freq_mhz": round((f_lo + b * step) / 1e6, 4), "avg_db": round(avg[b], 1),
                      "peak_db": round(peak[b], 1), "above_floor_db": round(avg[b] - floor, 1)})
        if len(peaks) >= 15:
            break
    return png(width, len(img), img) if img else b"", width, len(img), peaks


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="havokbox.helpers.sweep")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("picture")
    p.add_argument("--dir", default="~/havok/kit")
    p.add_argument("--csv")
    p.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    path = os.path.expanduser(a.csv) if a.csv else find_csv(os.path.expanduser(a.dir))
    if not path:
        print(json.dumps({"status": "error", "error": "no rtl_power sweep (.csv) found; run a sweep first"}))
        return 0
    try:
        with open(path) as fh:
            rows, f_lo, f_hi, step = parse(fh)
    except OSError as e:
        print(json.dumps({"status": "error", "error": str(e)[:200]}))
        return 0
    if not rows:
        print(json.dumps({"status": "error", "error": f"{path} has no sweep lines"}))
        return 0
    data, w, h, peaks = picture(rows, f_lo, f_hi, step)
    with open(a.out, "wb") as fh:
        fh.write(data)
    print(json.dumps({"status": "ok", "csv": path, "picture": a.out, "width": w, "height": h,
                      "range_mhz": [round(f_lo / 1e6, 3), round(f_hi / 1e6, 3)], "peaks": peaks}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
