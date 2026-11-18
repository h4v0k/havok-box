"""Poisoning / rogue-AP helper: responder, mitm6, rogue AP (eaphammer) orchestration.

Run as ``python3 -m havokbox.helpers.poison <responder|mitm6|rogue_ap> ...``; prints exactly one
JSON object. All real work lives in functions that take an injected runner(argv, timeout) -> stdout
str, so tests need no hardware/root. Every subprocess call is an argv list wrapped in
``["timeout", str(seconds), ...]``; never a shell.

Lab-only, Test pack: the gate has already checked the network/domain/ssid are in the owner's own
explicit lab lists (networks.poison_allowed / scope domains / wifi.ssids) and that the action has
per-action approval, before this helper ever runs. This helper's own job is just the argv and the
safety invariants below:

- Anything captured (hashes, etc.) STAYS ON THE BOX. These functions return only a COUNT and a file
  path (chmod 0600) — never hash material, never usernames+hashes, never credential values. This
  helper never reads back or prints captured hash contents, and never cracks anything.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

IFACE_RE = re.compile(r"^[a-z][a-z0-9]{1,14}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
HASH_COUNT_RE = re.compile(r"\b(\d+)\s+hash(?:es)?\s+captured\b", re.I)
CLIENT_RE = re.compile(r"client\s+connect", re.I)


class HelperError(Exception):
    pass


# ---------------------------------------------------------------- real process plumbing (not exercised by tests)

def default_runner(argv: list[str], timeout: float) -> str:
    """Run argv to completion (or until the outer `timeout` wrapper kills it) and return stdout.
    A timeout here is expected for a bounded capture window, not a failure."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                            stdin=subprocess.DEVNULL, errors="replace")
        return p.stdout or ""
    except subprocess.TimeoutExpired as e:
        out = e.stdout
        return out.decode("utf-8", "replace") if isinstance(out, bytes) else (out or "")


# ---------------------------------------------------------------- validation

def validate_iface(iface: str) -> str:
    if not isinstance(iface, str) or not IFACE_RE.match(iface):
        raise HelperError(f"invalid iface: {iface!r}")
    return iface


def validate_domain(domain: str) -> str:
    if not isinstance(domain, str) or not DOMAIN_RE.match(domain):
        raise HelperError(f"invalid domain: {domain!r}")
    return domain.lower()


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise HelperError(f"invalid name: {name!r}")
    return name


def validate_ssid(ssid: str) -> str:
    # The gate already confirmed ssid is in the owner's own wifi.ssids; here we only block control
    # characters that could corrupt argv. argv is a list, so there is no shell to inject into.
    if not isinstance(ssid, str) or not (1 <= len(ssid) <= 32) or \
            any(ord(c) < 0x20 or ord(c) == 0x7f for c in ssid):
        raise HelperError(f"invalid ssid: {ssid!r}")
    return ssid


def validate_seconds(seconds: int, lo: int = 30, hi: int = 300) -> int:
    if not isinstance(seconds, int) or isinstance(seconds, bool) or not (lo <= seconds <= hi):
        raise HelperError(f"invalid seconds: {seconds!r}")
    return seconds


# ---------------------------------------------------------------- argv builders (mirror tools/kali_test.py build_*)

def responder_argv(iface: str, seconds: int) -> list[str]:
    # No -A: this is the poisoning mode (answers LLMNR/NBT-NS), not passive analyze.
    return ["timeout", str(seconds), "responder", "-I", iface]


def mitm6_argv(iface: str, domain: str, seconds: int) -> list[str]:
    return ["timeout", str(seconds), "mitm6", "-i", iface, "-d", domain]


def rogue_ap_argv(iface: str, ssid: str, seconds: int) -> list[str]:
    # eaphammer evil-twin of the owner's own SSID, for testing the owner's own clients.
    # Capture (if any) stays on box; this helper never relays or cracks.
    return ["timeout", str(seconds), "eaphammer", "--essid", ssid, "--interface", iface,
            "--captive-portal"]


# ---------------------------------------------------------------- session dir

def new_session_dir(work_dir: str, label: str, clock=time.time) -> str:
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(clock()))
    d = os.path.join(work_dir, f"poison-{label}-{ts}")
    os.makedirs(d, exist_ok=True)
    return d


def _newest_capture(session_dir: str) -> str | None:
    files = (glob.glob(os.path.join(session_dir, "**", "*"), recursive=True))
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def _secure_any_captures(session_dir: str) -> str | None:
    """chmod 0600 anything written under session_dir and return the newest file's path, or None.
    Never opens/reads the file contents."""
    newest = None
    newest_mtime = -1.0
    for path in glob.glob(os.path.join(session_dir, "**", "*"), recursive=True):
        if not os.path.isfile(path):
            continue
        os.chmod(path, 0o600)
        mtime = os.path.getmtime(path)
        if mtime > newest_mtime:
            newest_mtime, newest = mtime, path
    return newest


def _count_hashes(stdout: str) -> int:
    """Count-only: look for an explicit 'N hashes captured' style line. Never inspects or returns
    hash material itself."""
    m = HASH_COUNT_RE.search(stdout or "")
    return int(m.group(1)) if m else 0


def _count_clients(stdout: str) -> int:
    return len(CLIENT_RE.findall(stdout or ""))


# ---------------------------------------------------------------- subcommands

def do_responder(iface: str, seconds: int, work_dir: str, runner=default_runner,
                  clock=time.time) -> dict:
    iface = validate_iface(iface)
    seconds = validate_seconds(seconds)
    session_dir = new_session_dir(work_dir, "responder", clock)
    out = runner(responder_argv(iface, seconds), seconds + 5)
    captured = _secure_any_captures(session_dir)
    count = _count_hashes(out)
    if captured and count == 0:
        count = 1  # a file landed on disk even if the summary line wasn't matched; still count-only
    return {"status": "ok", "hashes_captured": count, "file": captured}


def do_mitm6(iface: str, domain: str, seconds: int, work_dir: str, runner=default_runner,
             clock=time.time) -> dict:
    iface = validate_iface(iface)
    domain = validate_domain(domain)
    seconds = validate_seconds(seconds)
    # mitm6 captures nothing itself; it pairs with ntlmrelayx, which we do NOT run.
    runner(mitm6_argv(iface, domain, seconds), seconds + 5)
    return {"status": "ok", "note": f"mitm6 ran for {seconds} s"}


def do_rogue_ap(iface: str, ssid: str, seconds: int, work_dir: str, runner=default_runner,
                 clock=time.time) -> dict:
    iface = validate_iface(iface)
    ssid = validate_ssid(ssid)
    seconds = validate_seconds(seconds)
    session_dir = new_session_dir(work_dir, "rogue-ap", clock)
    out = runner(rogue_ap_argv(iface, ssid, seconds), seconds + 5)
    _secure_any_captures(session_dir)  # anything the captive portal wrote stays on box, 0600
    clients = _count_clients(out)
    return {"status": "ok", "ssid": ssid, "clients_seen": clients}


# ---------------------------------------------------------------- CLI

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="poison")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp_r = sub.add_parser("responder")
    sp_r.add_argument("--iface", required=True)
    sp_r.add_argument("--seconds", required=True, type=int)
    sp_r.add_argument("--work-dir", required=True)

    sp_m = sub.add_parser("mitm6")
    sp_m.add_argument("--iface", required=True)
    sp_m.add_argument("--domain", required=True)
    sp_m.add_argument("--seconds", required=True, type=int)
    sp_m.add_argument("--work-dir", required=True)

    sp_a = sub.add_parser("rogue_ap")
    sp_a.add_argument("--iface", required=True)
    sp_a.add_argument("--ssid", required=True)
    sp_a.add_argument("--seconds", required=True, type=int)
    sp_a.add_argument("--work-dir", required=True)

    args = p.parse_args(argv)
    try:
        if args.cmd == "responder":
            result = do_responder(args.iface, args.seconds, args.work_dir)
        elif args.cmd == "mitm6":
            result = do_mitm6(args.iface, args.domain, args.seconds, args.work_dir)
        elif args.cmd == "rogue_ap":
            result = do_rogue_ap(args.iface, args.ssid, args.seconds, args.work_dir)
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
