"""Wi-Fi capture helper: airodump-ng / aircrack-ng / aireplay-ng orchestration for one AP.

Run as ``python3 -m havokbox.helpers.wifi_capture <watch|capture|capture-deauth> ...``; prints exactly
one JSON object. All real work lives in functions that take an injected runner/popen/clock/sleep so the
tests need no hardware and no radio. Every subprocess call is an argv list with a timeout; never a shell.
Lab-only: wraps standard installed tools against BSSIDs the gate has already checked are in the owner's
own scope file, under per-action human approval for anything beyond passive listening.
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time

BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
HANDSHAKE_RE = re.compile(r"\((\d+)\s+handshake", re.I)
MAX_CLIENTS = 64
PRE_DEAUTH_WAIT = 5  # seconds airodump runs before aireplay fires, so it's recording when the deauth lands


class HelperError(Exception):
    pass


# ---------------------------------------------------------------- real process plumbing (not exercised by tests)

def default_runner(argv: list[str], timeout: float) -> str:
    """Run argv to completion (or until timeout) and return stdout. A timeout here is expected for a
    bounded capture window, not a failure: whatever airodump-ng wrote to stdout/the capture dir still
    stands, so the partial stdout is returned rather than raised."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                            stdin=subprocess.DEVNULL, errors="replace")
        return p.stdout or ""
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        return out.decode("utf-8", "replace") if isinstance(out, bytes) else (out or "")


def default_popen(argv: list[str]):
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)


# ---------------------------------------------------------------- validation

def validate_bssid(bssid: str) -> str:
    if not isinstance(bssid, str) or not BSSID_RE.match(bssid):
        raise HelperError(f"invalid bssid: {bssid!r}")
    return bssid.lower()


def validate_mac(mac: str) -> str:
    if not isinstance(mac, str) or not BSSID_RE.match(mac):
        raise HelperError(f"invalid mac: {mac!r}")
    return mac.lower()


def validate_channel(channel: int) -> int:
    if not isinstance(channel, int) or not (1 <= channel <= 196):
        raise HelperError(f"invalid channel: {channel!r}")
    return channel


def validate_seconds(seconds: int, lo: int, hi: int) -> int:
    if not isinstance(seconds, int) or not (lo <= seconds <= hi):
        raise HelperError(f"invalid seconds: {seconds!r}")
    return seconds


# ---------------------------------------------------------------- airodump CSV parsing (watch)

def parse_airodump_csv(text: str, bssid: str) -> dict:
    """Parse an airodump-ng --output-format csv file. The file has two CSV sections separated by a
    blank line: AP rows, then station rows. Returns {"ap": {...} | None, "clients": [...]}."""
    bssid = bssid.lower()
    sections = text.split("\r\n\r\n")
    if len(sections) == 1:
        sections = text.split("\n\n")
    ap_text = sections[0] if sections else ""
    sta_text = sections[1] if len(sections) > 1 else ""

    ap = None
    for row in csv.reader(io.StringIO(ap_text)):
        if not row or not row[0].strip():
            continue
        row = [c.strip() for c in row]
        if row[0].lower() == bssid:
            ap = {
                "bssid": row[0].lower(),
                "channel": _to_int(row[3]) if len(row) > 3 else None,
                "power": _to_int(row[8]) if len(row) > 8 else None,
                "ssid": row[13].strip() if len(row) > 13 else None,
            }
            break

    clients = []
    for row in csv.reader(io.StringIO(sta_text)):
        if not row or not row[0].strip() or row[0].strip().lower() == "station mac":
            continue
        row = [c.strip() for c in row]
        if len(row) > 5 and row[5].lower() == bssid:
            clients.append({
                "mac": row[0].lower(),
                "power": _to_int(row[3]) if len(row) > 3 else None,
                "packets": _to_int(row[4]) if len(row) > 4 else None,
            })
            if len(clients) >= MAX_CLIENTS:
                break

    return {"ap": ap, "clients": clients}


def _to_int(v: str):
    try:
        return int(v.strip())
    except (ValueError, AttributeError):
        return None


def newest_csv(work_dir: str) -> str | None:
    files = glob.glob(os.path.join(work_dir, "**", "*.csv"), recursive=True)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


# ---------------------------------------------------------------- aircrack-ng handshake check

def parse_handshake_count(aircrack_output: str) -> int:
    m = HANDSHAKE_RE.search(aircrack_output or "")
    return int(m.group(1)) if m else 0


def sha256_file(path: str, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


# ---------------------------------------------------------------- argv builders (mirror tools/wifi.py build_*)

def airodump_watch_argv(iface: str, bssid: str, channel: int, out_prefix: str) -> list[str]:
    return ["airodump-ng", "--bssid", bssid, "-c", str(channel),
            "--output-format", "csv", "-w", out_prefix, iface]


def airodump_pcap_argv(iface: str, bssid: str, channel: int, out_prefix: str) -> list[str]:
    return ["airodump-ng", "--bssid", bssid, "-c", str(channel),
            "--output-format", "pcap", "-w", out_prefix, iface]


def aircrack_check_argv(capfile: str) -> list[str]:
    return ["aircrack-ng", capfile]


def aireplay_deauth_argv(iface: str, bssid: str, count: int, client: str | None) -> list[str]:
    argv = ["aireplay-ng", "-0", str(count), "-a", bssid]
    if client:
        argv += ["-c", client]
    argv.append(iface)
    return argv


# ---------------------------------------------------------------- session dir

def new_session_dir(work_dir: str, label: str, clock=time.time) -> str:
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(clock()))
    d = os.path.join(work_dir, f"wifi-{label}-{ts}")
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------- subcommands (pure-ish: deps injected)

def do_watch(iface: str, bssid: str, channel: int, seconds: int, work_dir: str,
             runner=default_runner, clock=time.time) -> dict:
    bssid = validate_bssid(bssid)
    channel = validate_channel(channel)
    seconds = validate_seconds(seconds, 10, 600)
    session_dir = new_session_dir(work_dir, "watch", clock)
    prefix = os.path.join(session_dir, "cap")
    runner(airodump_watch_argv(iface, bssid, channel, prefix), seconds)
    csv_path = newest_csv(session_dir)
    if not csv_path:
        return {"status": "error", "error": "no capture output produced"}
    with open(csv_path, "r", newline="", errors="replace") as f:
        parsed = parse_airodump_csv(f.read(), bssid)
    return {"status": "ok", "kind": "ap_watch", "bssid": bssid, "channel": channel,
            "ap": parsed["ap"], "clients": parsed["clients"]}


def _verify_capture(capfile: str, runner=default_runner) -> tuple[bool, int]:
    out = runner(aircrack_check_argv(capfile), 60)
    n = parse_handshake_count(out)
    pmkid = bool(re.search(r"with\s+PMKID", out or "", re.I))
    return (n > 0 or pmkid), n


def do_capture(iface: str, bssid: str, channel: int, seconds: int, work_dir: str,
                runner=default_runner, clock=time.time) -> dict:
    bssid = validate_bssid(bssid)
    channel = validate_channel(channel)
    seconds = validate_seconds(seconds, 30, 600)
    session_dir = new_session_dir(work_dir, "capture", clock)
    prefix = os.path.join(session_dir, "cap")
    runner(airodump_pcap_argv(iface, bssid, channel, prefix), seconds)
    capfile = _newest_pcap(session_dir)
    if not capfile:
        return {"status": "error", "error": "no capture file produced"}
    os.chmod(capfile, 0o600)
    handshake, _ = _verify_capture(capfile, runner)
    return {"status": "ok", "kind": "capture", "bssid": bssid, "file": capfile,
            "handshake": handshake, "sha256": sha256_file(capfile)}


def do_capture_deauth(iface: str, bssid: str, channel: int, seconds: int, work_dir: str,
                       count: int = 3, client: str | None = None,
                       popen=default_popen, runner=default_runner, sleep=time.sleep,
                       clock=time.time) -> dict:
    bssid = validate_bssid(bssid)
    channel = validate_channel(channel)
    seconds = validate_seconds(seconds, 30, 300)
    count = validate_seconds(count, 1, 10)
    if client:
        client = validate_mac(client)
    session_dir = new_session_dir(work_dir, "capture-deauth", clock)
    prefix = os.path.join(session_dir, "cap")

    proc = popen(airodump_pcap_argv(iface, bssid, channel, prefix))
    try:
        sleep(PRE_DEAUTH_WAIT)
        runner(aireplay_deauth_argv(iface, bssid, count, client), 30)
        sleep(max(seconds - PRE_DEAUTH_WAIT, 0))
    finally:
        # airodump must never outlive this helper, whatever happened above
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    capfile = _newest_pcap(session_dir)
    if not capfile:
        return {"status": "error", "error": "no capture file produced"}
    os.chmod(capfile, 0o600)
    handshake, _ = _verify_capture(capfile, runner)
    return {"status": "ok", "kind": "capture", "bssid": bssid, "file": capfile,
            "handshake": handshake, "sha256": sha256_file(capfile), "deauth_sent": count}


def _newest_pcap(work_dir: str) -> str | None:
    files = glob.glob(os.path.join(work_dir, "**", "*.cap"), recursive=True) + \
        glob.glob(os.path.join(work_dir, "**", "*.pcap"), recursive=True)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


# ---------------------------------------------------------------- CLI

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="wifi_capture")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--iface", required=True)
        sp.add_argument("--bssid", required=True)
        sp.add_argument("--channel", required=True, type=int)
        sp.add_argument("--seconds", required=True, type=int)
        sp.add_argument("--work-dir", required=True)

    sp_watch = sub.add_parser("watch")
    add_common(sp_watch)

    sp_cap = sub.add_parser("capture")
    add_common(sp_cap)

    sp_cd = sub.add_parser("capture-deauth")
    add_common(sp_cd)
    sp_cd.add_argument("--client", default=None)
    sp_cd.add_argument("--count", type=int, default=3)

    args = p.parse_args(argv)
    try:
        if args.cmd == "watch":
            result = do_watch(args.iface, args.bssid, args.channel, args.seconds, args.work_dir)
        elif args.cmd == "capture":
            result = do_capture(args.iface, args.bssid, args.channel, args.seconds, args.work_dir)
        elif args.cmd == "capture-deauth":
            result = do_capture_deauth(args.iface, args.bssid, args.channel, args.seconds,
                                        args.work_dir, count=args.count, client=args.client)
        else:
            result = {"status": "error", "error": f"unknown subcommand {args.cmd!r}"}
    except HelperError as e:
        result = {"status": "error", "error": str(e)}
    except Exception as e:  # noqa: BLE001 - never let the helper crash without a JSON line out
        result = {"status": "error", "error": f"{type(e).__name__}: {e}"}

    print(json.dumps(result))
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
