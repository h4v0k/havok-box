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


def _ints(col: str) -> list[int]:
    out = []
    for tok in col.split(","):
        tok = tok.strip().lower()
        if not tok:
            continue
        try:
            out.append(int(tok, 16) if tok.startswith("0x") or any(c in "abcdef" for c in tok) else int(tok))
        except ValueError:
            continue
    return out


def _hexes(col: str) -> list[str]:
    out = []
    for tok in col.split(","):
        tok = tok.strip().lower().replace(":", "")
        if tok and re.fullmatch(r"[0-9a-f]+", tok) and len(tok) % 2 == 0:
            out.append(tok[:64])
    return out


def _add_unique(dst: list, items: list, cap: int = 16) -> None:
    for i in items:
        if i not in dst and len(dst) < cap:
            dst.append(i)


def parse_tshark_fields(text: str) -> list[dict]:
    """Rows: addr, name, signal_dbm, nordic rssi, company_id, uuid_16, data, randomized_tx (tab separated).

    Dedupe by addr, keep strongest rssi, cap at 64. Repeated occurrences within a field are
    comma-joined by tshark; every occurrence is parsed and merged across rows.
    """
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
        col = lambda i: parts[i] if len(parts) > i else ""  # noqa: E731
        cids, u16, mfg = _ints(col(4)), _ints(col(5)), _hexes(col(6))
        rnd = any(t.strip().lower() in ("1", "true") for t in col(7).split(","))
        cur = seen.get(addr)
        if cur is None:
            cur = seen[addr] = {"addr": addr, "name": name, "rssi": rssi, "seen": 1,
                                "company_ids": [], "uuid16": [], "mfg_data": [], "random": rnd}
        else:
            cur["seen"] += 1
            if name and not cur["name"]:
                cur["name"] = name
            if rssi is not None and (cur["rssi"] is None or rssi > cur["rssi"]):
                cur["rssi"] = rssi
            cur["random"] = cur["random"] or rnd
        _add_unique(cur["company_ids"], cids)
        _add_unique(cur["uuid16"], u16)
        _add_unique(cur["mfg_data"], mfg)
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
                  "-e", "btle_rf.signal_dbm", "-e", "nordic_ble.rssi",
                  "-e", "btcommon.eir_ad.entry.company_id", "-e", "btcommon.eir_ad.entry.uuid_16",
                  "-e", "btcommon.eir_ad.entry.data", "-e", "btle.advertising_header.randomized_tx"], 60)
    devices = parse_tshark_fields(out)
    # Privacy: never keep raw captures once parsed.
    try:
        os.remove(pcap)
    except OSError:
        pass
    try:
        os.rmdir(run_dir)
    except OSError:
        pass
    return {"devices": devices, "pcap": None}


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
