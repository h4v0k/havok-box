"""Test pack: default-credential check, LAN poisoning, and a rogue AP against the owner's own SSID.

Every tool here is an ACTIVE category under the scope gate (``auth.attempt``, ``net.poison``,
``wifi.rogue_ap``) and so requires per-action human approval before it runs — the gate (already
built) enforces that the network/domain/ssid is in the owner's own explicit lab lists
(``networks.poison_allowed`` / scope ``domains`` / ``wifi.ssids``). This module is only the argv
wrappers and result shaping; it does not re-implement scope checks.

Hard safety invariants enforced here, not just documented:
- Poisoning durations are ALWAYS wrapped in ``["timeout", str(seconds), ...]`` inside the helper,
  seconds an int 30..300 (default 120).
- Anything captured (hashes, etc.) STAYS ON THE BOX: parsers return only a COUNT and a file path —
  never hash material, never usernames+hashes, never credential values.
- ``creds.default`` tests only a small bundled default-credential list via hydra (``-t 1``, 1
  thread, ``-w 1`` -> hydra's own >=1s wait between tries, ``-f`` stop on first success). It takes
  no user-supplied wordlist and is not a password cracker. The returned credential is never the
  actual value found.
- Nothing here cracks anything; captured material is left for the owner's own homelab if he wants
  to crack it there.
"""
from __future__ import annotations

import json
import re

from ..store import new_id

HELPER_ARGV = ["python3", "-m", "havokbox.helpers.poison"]

_HYDRA_SUCCESS_RE = re.compile(r"\[\d+\]\[\S+\]\s+host:\s*\S+\s+login:\s*\S+\s+password:\s*\S+", re.I)


def _int(v, lo, hi, default):
    try:
        if v is None or v == "" or isinstance(v, bool):
            return default
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def _load_helper_json(out: str):
    try:
        return json.loads(out)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------- creds.default

def build_creds_default(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    ip = target["ip"]
    service = target.get("service", "ssh")
    creds_file = hw.get("default_creds", "/opt/havokbox/default-creds.txt")
    # hydra: -C combined user:pass file (our bundled <=20 pair default-cred list), -t 1 (one
    # thread), -w 1 (>=1s between tries), -f (stop on first success found).
    return [["hydra", "-C", creds_file, "-t", "1", "-w", "1", "-f", "-o", "/dev/stdout", ip, service]]


def parse_creds(stdout: str, ip: str = "", service: str = "") -> dict:
    """Returns ONLY whether a default credential pair worked — never the credential itself,
    even though hydra's own stdout (in the fixture or in reality) contains it."""
    found = bool(_HYDRA_SUCCESS_RE.search(stdout or ""))
    return {"found": found, "service": service, "ip": ip}


def creds_default(task: dict, ctx) -> dict:
    target = task["target"]
    ip = target["ip"]
    service = target.get("service", "ssh")
    argv, = build_creds_default(target, ctx.mode, ctx.scope, ctx.hw)
    out = ctx.runner(argv)
    data = parse_creds(out, ip, service)
    return {
        "result_id": new_id(),
        "space": "wired",
        "kind": "creds_default",
        "summary": f"{ip} ({service}): default credential {'found' if data['found'] else 'not found'}",
        "data": data,
    }


# ---------------------------------------------------------------- net.poison.responder

def build_net_poison_responder(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    seconds = _int(target.get("seconds"), 30, 300, 120)
    return [HELPER_ARGV + ["responder", "--iface", hw["wired_iface"], "--seconds", str(seconds),
                           "--work-dir", hw["work_dir"]]]


def net_poison_responder(task: dict, ctx) -> dict:
    argv, = build_net_poison_responder(task["target"], ctx.mode, ctx.scope, ctx.hw)
    out = ctx.runner(argv)
    data = _load_helper_json(out) or {}
    count = int(data.get("hashes_captured") or 0) if isinstance(data, dict) else 0
    file_path = data.get("file") if isinstance(data, dict) else None
    return {
        "result_id": new_id(),
        "space": "wired",
        "kind": "poison",
        "summary": f"responder: {count} hash(es) captured" + (" (kept on box)" if count else ""),
        "data": {"action": "responder", "hashes_captured": count, "file": file_path},
    }


# ---------------------------------------------------------------- net.poison.mitm6

def build_net_poison_mitm6(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    domain = target["domain"]
    seconds = _int(target.get("seconds"), 30, 300, 120)
    return [HELPER_ARGV + ["mitm6", "--iface", hw["wired_iface"], "--domain", domain,
                           "--seconds", str(seconds), "--work-dir", hw["work_dir"]]]


def net_poison_mitm6(task: dict, ctx) -> dict:
    target = task["target"]
    argv, = build_net_poison_mitm6(target, ctx.mode, ctx.scope, ctx.hw)
    out = ctx.runner(argv)
    data = _load_helper_json(out) or {}
    note = data.get("note") if isinstance(data, dict) else None
    # mitm6 captures nothing itself; it pairs with ntlmrelayx, which we do NOT run.
    return {
        "result_id": new_id(),
        "space": "wired",
        "kind": "poison",
        "summary": note or f"mitm6 ran against {target['domain']}",
        "data": {"action": "mitm6", "domain": target["domain"], "note": note},
    }


# ---------------------------------------------------------------- wifi.rogue_ap

def build_wifi_rogue_ap(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    ssid = target["ssid"]
    seconds = _int(target.get("seconds"), 30, 300, 120)
    return [HELPER_ARGV + ["rogue_ap", "--iface", hw.get("wifi_mon_iface", ""), "--ssid", ssid,
                           "--seconds", str(seconds), "--work-dir", hw["work_dir"]]]


def wifi_rogue_ap(task: dict, ctx) -> dict:
    target = task["target"]
    argv, = build_wifi_rogue_ap(target, ctx.mode, ctx.scope, ctx.hw)
    out = ctx.runner(argv)
    data = _load_helper_json(out) or {}
    clients = int(data.get("clients_seen") or 0) if isinstance(data, dict) else 0
    ssid = data.get("ssid") if isinstance(data, dict) else target["ssid"]
    return {
        "result_id": new_id(),
        "space": "wifi",
        "kind": "rogue_ap",
        "summary": f"rogue AP {ssid}: {clients} client(s) seen",
        "data": {"ssid": ssid, "clients_seen": clients},
    }
