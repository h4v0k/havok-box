"""Ham and two-way radio helpers for the RTL-SDR. RECEIVE ONLY: nothing here can transmit.

    python3 -m havokbox.helpers.radio bands --bands gmrs,2m,70cm --seconds 60 [--device SERIAL]
    python3 -m havokbox.helpers.radio aprs  --seconds 120 [--device SERIAL]

bands: rtl_power over each band; reports channels that stand out above that band's noise floor,
       named where they match a known channel (FRS/GMRS 1-22, MURS 1-5, NOAA WX 1-7, 2m/70cm
       calling, APRS).
aprs:  rtl_fm on 144.390 MHz piped into Dire Wolf; reports stations heard, with position when the
       packet carries one. APRS is a public amateur broadcast.

Parsers are pure functions so they're testable without a radio; main() prints one JSON object.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import statistics
import subprocess
import sys
import time

# name -> (start_mhz, end_mhz, bin_khz)
BANDS: dict[str, tuple[float, float, float]] = {
    "2m": (144.0, 148.0, 12.5),
    "1.25m": (222.0, 225.0, 12.5),
    "70cm": (420.0, 450.0, 12.5),
    "gmrs": (462.5, 467.8, 6.25),     # FRS/GMRS share these channels
    "murs": (151.8, 154.62, 6.25),
    "noaa": (162.39, 162.56, 6.25),
}
DEFAULT_BANDS = ("gmrs", "2m", "70cm", "murs", "noaa")


def _channels() -> dict[float, str]:
    ch: dict[float, str] = {}
    for i in range(7):
        ch[round(462.5625 + i * 0.025, 4)] = f"FRS/GMRS {i + 1}"
        ch[round(467.5625 + i * 0.025, 4)] = f"FRS/GMRS {i + 8}"
    for i in range(8):
        ch[round(462.5500 + i * 0.025, 4)] = f"FRS/GMRS {i + 15}"
    for i in range(8):                       # GMRS repeater inputs (+5 MHz)
        ch.setdefault(round(467.5500 + i * 0.025, 4), f"GMRS repeater input {i + 15}")
    for i, f in enumerate((151.820, 151.880, 151.940, 154.570, 154.600), 1):
        ch[f] = f"MURS {i}"
    for i, f in enumerate((162.400, 162.425, 162.450, 162.475, 162.500, 162.525, 162.550), 1):
        ch[f] = f"NOAA weather WX{i}"
    ch[144.390] = "APRS"
    ch[146.520] = "2m national simplex calling"
    ch[446.000] = "70cm national simplex calling"
    return ch


CHANNELS = _channels()


def label_for(mhz: float, tol_khz: float = 7.0) -> str:
    near = min(CHANNELS, key=lambda f: abs(f - mhz))
    if abs(near - mhz) * 1000 <= tol_khz:
        return CHANNELS[near]
    if 145.1 <= mhz <= 145.5 or 146.61 <= mhz <= 147.39:
        return "2m repeater output range"
    if 442.0 <= mhz <= 445.0:
        return "70cm repeater output range"
    for name, (lo, hi, _) in BANDS.items():
        if lo <= mhz <= hi:
            return f"{name} band"
    return ""


def build_power(band: str, seconds: int, device: str | None) -> list[str]:
    lo, hi, bin_khz = BANDS[band]
    dev = ["-d", device] if device else []
    return ["rtl_power", *dev, "-f", f"{lo:g}M:{hi:g}M:{bin_khz:g}k", "-i", "2",
            "-e", f"{max(4, int(seconds))}s", "/dev/stdout"]


def parse_power(text: str, band: str, margin_db: float = 10.0, limit: int = 12) -> dict:
    """Peak power per bin across sweeps; channels standing margin_db over the band's median floor."""
    best: dict[float, float] = {}
    for line in (text or "").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 7:
            continue
        try:
            lo, step = float(parts[2]), float(parts[4])
            dbs = [float(x) for x in parts[6:]]
        except ValueError:
            continue
        if step <= 0:
            continue
        for i, db in enumerate(dbs):
            mhz = round((lo + i * step) / 1e6, 4)
            best[mhz] = max(db, best.get(mhz, -999.0))
    if not best:
        return {"band": band, "noise_floor_db": None, "active": []}
    floor = statistics.median(best.values())
    hot = sorted((m, d) for m, d in best.items() if d >= floor + margin_db)
    clusters: list[list[tuple[float, float]]] = []
    for m, d in hot:                         # merge bins within 25 kHz into one signal
        if clusters and (m - clusters[-1][-1][0]) * 1000 <= 25:
            clusters[-1].append((m, d))
        else:
            clusters.append([(m, d)])
    active = []
    for c in clusters:
        m, d = max(c, key=lambda x: x[1])
        active.append({"mhz": round(m, 4), "db": round(d, 1), "above_floor_db": round(d - floor, 1),
                       "label": label_for(m)})
    active.sort(key=lambda a: -a["above_floor_db"])
    return {"band": band, "noise_floor_db": round(floor, 1), "active": active[:limit]}


APRS_LINE = re.compile(r"^\[[^\]]*\]\s+([A-Z0-9]{1,6}(?:-[0-9A-Z]{1,2})?)>([^:]+):(.*)$")
APRS_POS = re.compile(r"[!=/@](?:\d{6}[hz/])?(\d{2})(\d{2}\.\d{2})([NS]).(\d{3})(\d{2}\.\d{2})([EW])")


def parse_aprs(text: str, limit: int = 100) -> list[dict]:
    stations: dict[str, dict] = {}
    for line in (text or "").splitlines():
        m = APRS_LINE.match(line.strip())
        if not m:
            continue
        call, path, info = m.group(1), m.group(2), m.group(3)
        st = stations.setdefault(call, {"call": call, "packets": 0, "lat": None, "lon": None, "last": ""})
        st["packets"] += 1
        st["last"] = info[:80]
        st["via"] = path.split(",")[0][:16]
        p = APRS_POS.search(info)
        if p:
            lat = int(p.group(1)) + float(p.group(2)) / 60
            lon = int(p.group(4)) + float(p.group(5)) / 60
            st["lat"] = round(-lat if p.group(3) == "S" else lat, 4)
            st["lon"] = round(-lon if p.group(6) == "W" else lon, 4)
        if len(stations) >= limit:
            break
    return sorted(stations.values(), key=lambda s: -s["packets"])


def run_bands(bands: list[str], seconds: int, device: str | None) -> dict:
    per = max(4, seconds // max(1, len(bands)))
    out = []
    for b in bands:
        p = subprocess.run(build_power(b, per, device), capture_output=True, text=True, timeout=per + 30)
        out.append(parse_power(p.stdout, b))
    return {"bands": out}


def run_aprs(seconds: int, device: str | None) -> dict:
    if not shutil.which("direwolf"):
        return {"status": "error", "error": "direwolf is not installed"}
    dev = ["-d", device] if device else []
    fm = subprocess.Popen(["rtl_fm", *dev, "-f", "144.39M", "-s", "24000", "-"],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    dw = subprocess.Popen(["direwolf", "-r", "24000", "-D", "1", "-t", "0", "-q", "hd", "-"],
                          stdin=fm.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    fm.stdout.close()
    time.sleep(max(10, int(seconds)))
    for proc in (fm, dw):
        proc.terminate()
    try:
        text, _ = dw.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        dw.kill()
        text, _ = dw.communicate()
    fm.wait(timeout=5)
    return {"stations": parse_aprs(text)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="havokbox.helpers.radio")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bands")
    b.add_argument("--bands", default=",".join(DEFAULT_BANDS))
    b.add_argument("--seconds", type=int, default=60)
    b.add_argument("--device")
    a = sub.add_parser("aprs")
    a.add_argument("--seconds", type=int, default=120)
    a.add_argument("--device")
    args = ap.parse_args(argv)
    if args.device and not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", args.device):
        print(json.dumps({"status": "error", "error": "bad SDR serial"}))
        return 0
    try:
        if args.cmd == "bands":
            names = [x for x in args.bands.split(",") if x]
            if any(n not in BANDS for n in names):
                result = {"status": "error", "error": f"bands must be from {sorted(BANDS)}"}
            else:
                result = run_bands(names, args.seconds, args.device)
        else:
            result = run_aprs(args.seconds, args.device)
    except (OSError, subprocess.SubprocessError) as e:
        result = {"status": "error", "error": str(e)[:200]}
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
