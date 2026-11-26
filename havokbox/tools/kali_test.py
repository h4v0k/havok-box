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

# Default-login check. One thread, 1 s between connections, stop on the first hit, short
# factory-default lists only (SecLists' Default-Credentials set when installed, else our bundled
# list). It is not a password guesser: no user wordlists, nothing cracked, and the password that
# worked is never returned or stored - only which account on which service still has its default.
DEFAULT_CREDS_DIR = "/usr/share/seclists/Passwords/Default-Credentials"
# service -> (port, hydra module, SecLists file prefix or None, protocol)
CRED_SERVICES = {
    "ftp": (21, "ftp", "ftp", "tcp"),
    "ssh": (22, "ssh", "ssh", "tcp"),
    "telnet": (23, "telnet", "telnet", "tcp"),
    "http": (80, "http-get", None, "tcp"),
    "https": (443, "https-get", None, "tcp"),
    "smb": (445, "smb", "windows", "tcp"),
    "mssql": (1433, "mssql", "mssql", "tcp"),
    "mysql": (3306, "mysql", "mysql", "tcp"),
    "rdp": (3389, "rdp", "windows", "tcp"),
    "postgres": (5432, "postgres", "postgres", "tcp"),
    "vnc": (5900, "vnc", "vnc", "tcp"),
    "snmp": (161, "snmp", None, "udp"),
}
# "common" leaves out Windows sharing and Remote Desktop: wrong guesses there can lock Windows
# accounts, so those two only run when picked on purpose.
COMMON = ["ftp", "ssh", "telnet", "mssql", "mysql", "postgres", "vnc"]
MAX_CHECKS = 64
_HYDRA_LOGIN_RE = re.compile(r"\[(\d+)\]\[(\S+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:", re.I)


def _cred_list(service: str, hw: dict, exists=None) -> tuple[str, str]:
    """(-C|-P, path): the default list for a service."""
    import os
    exists = exists or os.path.isfile
    if service == "snmp":
        return "-P", hw.get("snmp_communities", "/opt/havokbox/snmp-communities.txt")
    prefix = CRED_SERVICES[service][2]
    if prefix:
        path = f"{hw.get('default_creds_dir', DEFAULT_CREDS_DIR)}/{prefix}-betterdefaultpasslist.txt"
        if exists(path):
            return ("-P" if service == "vnc" else "-C"), path
    if service == "vnc":
        return "-P", hw.get("vnc_passwords", "/opt/havokbox/vnc-passwords.txt")
    return "-C", hw.get("default_creds", "/opt/havokbox/default-creds.txt")


def hydra_argv(ip: str, service: str, hw: dict, exists=None, port_override: int | None = None) -> list[str]:
    flag, path = _cred_list(service, hw, exists)
    port, module = CRED_SERVICES[service][:2]
    # -t 1 one connection at a time; -W 1 wait 1 s between connections; -w 5 response timeout;
    # -f stop at the first login that works; -I don't wait on an old restore file.
    argv = ["hydra", flag, path, "-t", "1", "-W", "1", "-w", "5", "-f", "-I", "-o", "/dev/stdout"]
    if port_override:
        argv += ["-s", str(port_override)]
    return argv + ([ip, module, "/"] if module in ("http-get", "https-get") else [ip, module])


def _services(target: dict) -> list[str]:
    s = target.get("service", "ssh")
    return COMMON if s == "common" else [s]


def _one_target(target: dict) -> None:
    ip, net = target.get("ip"), target.get("network")
    if bool(ip) == bool(net):
        raise ValueError("give either one host (ip) or a range (network), not both")
    if ":" in str(ip or net):
        raise ValueError("IPv6 isn't supported for default-login checks yet; use an IPv4 address")


def build_creds_default(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    services = _services(target)
    ip = target.get("ip")
    _one_target(target)
    port = target.get("port")
    if ip and len(services) == 1:
        return [hydra_argv(ip, services[0], hw, port_override=port)]
    # Range and/or several services: find which hosts actually have them open first, then try
    # defaults only there. The preview shows the port check plus one login check per service.
    net = target.get("network") or ip
    if port and len(services) == 1 and CRED_SERVICES[services[0]][3] == "tcp":
        tcp = [int(port)]                     # the service lives on a non-standard port
    else:
        tcp = sorted({CRED_SERVICES[s][0] for s in services if CRED_SERVICES[s][3] == "tcp"})
    udp = sorted({CRED_SERVICES[s][0] for s in services if CRED_SERVICES[s][3] == "udp"})
    ports = ",".join([f"T:{p}" for p in tcp] + [f"U:{p}" for p in udp])
    scan = ["nmap", "-Pn", "-n", "--open"] + (["-sS", "-sU"] if udp else []) + ["-p", ports]
    never = [str(n) for n in getattr(scope, "exclude", [])]
    if never:
        scan += ["--exclude", ",".join(never)]
    scan += ["-oX", "-", net]
    # Approval covers this plan: the port check, then these login checks on each host it finds.
    return [scan] + [hydra_argv("<each host with it open>", s, hw, port_override=port) for s in services]


def _open_services(xml_text: str, services: list[str], port: int | None = None) -> list[tuple[str, str]]:
    import xml.etree.ElementTree as ET
    by_port = {(CRED_SERVICES[s][0], CRED_SERVICES[s][3]): s for s in services}
    if port and len(services) == 1:
        by_port = {(int(port), "tcp"): services[0]}
    pairs = []
    try:
        root = ET.fromstring(xml_text or "<nmaprun/>")
    except ET.ParseError:
        return []
    for h in root.iter("host"):
        addr = next((a.get("addr") for a in h.iter("address") if a.get("addrtype") == "ipv4"), None)
        for p in h.iter("port"):
            st = p.find("state")
            try:
                key = (int(p.get("portid", 0)), p.get("protocol"))
            except ValueError:
                continue
            if addr and st is not None and st.get("state") == "open" and key in by_port:
                pairs.append((addr, by_port[key]))
    return pairs


def parse_creds(stdout: str, ip: str = "", service: str = "") -> dict:
    """Whether a default login worked and for which account name. Never the password."""
    logins = sorted({m.group(4) for m in _HYDRA_LOGIN_RE.finditer(stdout or "")})
    return {"found": bool(_HYDRA_SUCCESS_RE.search(stdout or "")), "service": service, "ip": ip,
            "accounts": logins}


def creds_default(task: dict, ctx) -> dict:
    target = task["target"]
    services = _services(target)
    ip = target.get("ip")
    steps = build_creds_default(target, ctx.mode, ctx.scope, ctx.hw)
    truncated = 0
    if ip and len(services) == 1:
        pairs = [(ip, services[0])]
        outs = [ctx.runner(steps[0])]
    else:
        found = [(h, sv) for h, sv in _open_services(ctx.runner(steps[0]), services, target.get("port"))
                 if ctx.scope.ip_in_scope(h)]          # re-check every host; fails closed
        truncated = max(0, len(found) - MAX_CHECKS)
        pairs = found[:MAX_CHECKS]
        outs = [ctx.runner(hydra_argv(h, s, ctx.hw, port_override=target.get("port"))) for h, s in pairs]
    checks = [parse_creds(o, h, s) for (h, s), o in zip(pairs, outs)]
    hits = [c for c in checks if c["found"]]
    where = target.get("network") or ip
    if not checks:
        summary = f"{where}: none of {', '.join(services)} are open, nothing to check"
    elif len(checks) == 1:
        c = checks[0]
        who = f" (account: {', '.join(c['accounts'])})" if c["accounts"] else ""
        summary = f"{c['ip']} ({c['service']}): default login {'WORKS' + who if c['found'] else 'not found'}"
    else:
        summary = f"{where}: default login works on {len(hits)} of {len(checks)} services checked"
    if truncated:
        summary += f" ({truncated} more skipped; run a smaller range)"
    return {"result_id": new_id(), "space": "wired", "kind": "creds_default", "summary": summary,
            "data": {"found": bool(hits), "checked": len(checks), "hits": hits, "skipped": truncated,
                     "clean": [{"ip": c["ip"], "service": c["service"]} for c in checks if not c["found"]],
                     "ip": ip, "service": target.get("service", "ssh")}}


# ---------------------------------------------------------------- creds.web_defaults

WEB_THROTTLE = ["-T2", "--max-parallelism", "1", "--max-hostgroup", "1", "--scan-delay", "1s"]


def build_creds_web_defaults(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    _one_target(target)
    net = target.get("network") or target["ip"]
    # one host and one probe at a time, a second apart; nmap tries each product's default once
    cmd = ["nmap", "-Pn", "-n", "--open", *WEB_THROTTLE, "-p", "80,443,8000,8080,8081,8443,8888",
           "--script", "http-default-accounts"]
    never = [str(n) for n in getattr(scope, "exclude", [])]
    if never:
        cmd += ["--exclude", ",".join(never)]
    return [cmd + ["-oX", "-", net]]


def parse_web_defaults(xml_text: str) -> list[dict]:
    """[{ip, port, product, path, accounts}] - account names only; passwords are dropped."""
    import xml.etree.ElementTree as ET
    out = []
    try:
        root = ET.fromstring(xml_text or "<nmaprun/>")
    except ET.ParseError:
        return []
    for h in root.iter("host"):
        addr = next((a.get("addr") for a in h.iter("address") if a.get("addrtype") == "ipv4"), "")
        for p in h.iter("port"):
            for sc in p.iter("script"):
                if sc.get("id") != "http-default-accounts":
                    continue
                product = path = None
                for line in (sc.get("output") or "").splitlines():
                    m = re.match(r"\s*\[(.+?)\] at (\S+)", line)
                    if m:
                        product, path = m.group(1), m.group(2)
                        continue
                    m = re.match(r"\s+([^:\s][^:]*):", line)
                    if m and product:
                        out.append({"ip": addr, "port": int(p.get("portid", 0)) if str(p.get("portid", "")).isdigit() else 0, "product": product[:60],
                                    "path": path[:120], "account": m.group(1).strip()[:40]})
    return out[:MAX_CHECKS]


def creds_web_defaults(task: dict, ctx) -> dict:
    argv, = build_creds_web_defaults(task["target"], ctx.mode, ctx.scope, ctx.hw)
    hits = parse_web_defaults(ctx.runner(argv))
    where = task["target"].get("network") or task["target"].get("ip")
    return {"result_id": new_id(), "space": "wired", "kind": "creds_default",
            "summary": f"{where}: factory-default web login works on {len(hits)} page(s)" if hits
            else f"{where}: no factory-default web logins found",
            "data": {"found": bool(hits), "hits": hits}}


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
