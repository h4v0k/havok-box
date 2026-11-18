"""ADS-B helper: readsb (RTL-SDR, no network ports) -> aircraft.json -> JSON on stdout.

Usage: python3 -m havokbox.helpers.adsb --device SERIAL --seconds 60 --work-dir W
Receive only. readsb is run without --net, so no listening sockets are opened.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

MAX_AIRCRAFT = 200
_SERIAL = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def real_popen(argv: list[str]):
    return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _alt(a: dict):
    for k in ("alt_baro", "altitude"):
        if a.get(k) is not None:
            return a[k]
    return None


def parse_aircraft(obj) -> list[dict]:
    rows = obj.get("aircraft") if isinstance(obj, dict) else None
    out = []
    for a in rows if isinstance(rows, list) else []:
        if not isinstance(a, dict) or not a.get("hex"):
            continue
        out.append({"hex": str(a["hex"]).lower(), "flight": str(a.get("flight") or "").strip(),
                    "alt": _alt(a), "gs": a.get("gs"), "track": a.get("track"),
                    "lat": a.get("lat"), "lon": a.get("lon"), "squawk": a.get("squawk"),
                    "seen": a.get("seen")})
    return out[:MAX_AIRCRAFT]


def run(device_serial: str, seconds: int, work_dir: str, runner=real_popen, sleep=time.sleep,
        clock=time.time) -> dict:
    dev = device_serial or "0"
    if not _SERIAL.match(dev):
        raise ValueError("bad device serial")
    seconds = max(1, min(int(seconds), 600))
    os.makedirs(work_dir, exist_ok=True)
    out_dir = tempfile.mkdtemp(prefix="adsb_", dir=work_dir)
    try:
        proc = runner(["readsb", "--device-type", "rtlsdr", "--device", dev,
                       "--write-json", out_dir, "--quiet"])
        try:
            sleep(seconds)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001 - best effort; never leave readsb running
                try:
                    proc.kill()
                except Exception:  # noqa: BLE001
                    pass
        try:
            with open(os.path.join(out_dir, "aircraft.json")) as f:
                obj = json.load(f)
        except (OSError, ValueError):
            obj = {}
        return {"aircraft": parse_aircraft(obj)}
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", default="0")
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--work-dir", required=True)
    a = ap.parse_args(argv)
    try:
        res = run(a.device, a.seconds, a.work_dir)
    except (ValueError, OSError) as e:
        res = {"aircraft": [], "error": str(e)}
    sys.stdout.write(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
