"""BLE advertising scan helper: Sniffle sniffer -> pcap -> tshark fields -> JSON on stdout.

Usage: python3 -m havokbox.helpers.ble_scan --sniffle-dir D --port /dev/ttyUSB0 --seconds 30 --work-dir W
Logic lives in functions that take an injected runner(argv, timeout) -> stdout str.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

MAX_DEVICES = 64
_ADDR = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def real_runner(argv: list[str], timeout: float) -> str:
    """Run argv (never a shell); a timeout is not an error, partial output is kept."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except subprocess.TimeoutExpired as e:
        out = e.stdout
        return out.decode("utf-8", "replace") if isinstance(out, bytes) else (out or "")
    except OSError:
        return ""


def validate_port(port: str) -> str:
    p = os.path.normpath(port)
    if not p.startswith("/dev/") or ".." in port.split("/"):
        raise ValueError("port must be under /dev/")
    return p


def parse_tshark_fields(text: str) -> list[dict]:
    """Rows are addr<TAB>name<TAB>rssi; dedupe by addr, keep strongest rssi, cap at 64."""
    seen: dict[str, dict] = {}
    for line in (text or "").splitlines():
        parts = line.split("\t")
        addr = parts[0].strip().split(",")[0].lower() if parts else ""
        if not _ADDR.match(addr):
            continue
        name = parts[1].strip().split(",")[0] if len(parts) > 1 else ""
        rssi = None
        for col in parts[2:4]:   # btle_rf.signal_dbm (Sniffle DLT 256), then nordic_ble.rssi
            try:
                rssi = int(float(col.strip().split(",")[0]))
                break
            except ValueError:
                continue
        cur = seen.get(addr)
        if cur is None:
            seen[addr] = {"addr": addr, "name": name, "rssi": rssi, "seen": 1}
            continue
        cur["seen"] += 1
        if name and not cur["name"]:
            cur["name"] = name
        if rssi is not None and (cur["rssi"] is None or rssi > cur["rssi"]):
            cur["rssi"] = rssi
    devs = sorted(seen.values(), key=lambda d: (d["rssi"] is None, -(d["rssi"] or 0)))
    return devs[:MAX_DEVICES]


def scan(sniffle_dir: str, port: str, seconds: int, work_dir: str, runner=real_runner,
         now=time.time) -> dict:
    port = validate_port(port)
    seconds = max(1, int(seconds))
    run_dir = os.path.join(work_dir, "ble_" + time.strftime("%Y%m%d_%H%M%S", time.gmtime(now())))
    os.makedirs(run_dir, exist_ok=True)
    pcap = os.path.join(run_dir, "adv.pcap")
    script = os.path.join(sniffle_dir, "python_cli", "sniff_receiver.py")
    runner(["timeout", "-s", "INT", str(seconds), "python3", script, "-s", port, "-a", "-o", pcap],
           seconds + 15)
    out = runner(["tshark", "-r", pcap, "-T", "fields", "-E", "separator=/t",
                  "-e", "btle.advertising_address", "-e", "btcommon.eir_ad.entry.device_name",
                  "-e", "btle_rf.signal_dbm", "-e", "nordic_ble.rssi"], 60)
    return {"devices": parse_tshark_fields(out), "pcap": pcap}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sniffle-dir", required=True)
    ap.add_argument("--port", required=True)
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--work-dir", required=True)
    a = ap.parse_args(argv)
    try:
        res = scan(a.sniffle_dir, a.port, min(max(a.seconds, 1), 600), a.work_dir)
    except (ValueError, OSError) as e:
        res = {"devices": [], "error": str(e)}
    sys.stdout.write(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
