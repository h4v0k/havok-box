"""Wired-space tools: passive LAN listen, nmap vuln scripts, SMB share enum, web fingerprint.

Lab-only wrappers around standard installed tools. Parsers are pure and tolerant of junk/empty
output; the runner is injected so nothing here shells out during tests.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from ..store import new_id

CAP = 64

_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
_IP = r"\d{1,3}(?:\.\d{1,3}){3}"
_HDR = re.compile(rf"(?:^|\s)({_MAC}) > ({_MAC}),")
_ARP_REQ = re.compile(rf"who-has ({_IP}) (?:\({_MAC}\) )?tell ({_IP})")
_ARP_REP = re.compile(rf"Reply ({_IP}) is-at ({_MAC})")
_DHCP_SRV = re.compile(rf"({_IP})\.67 > {_IP}\.68: .*?(?:BOOTP/DHCP, Reply|DHCP-Message[^\n]*?(?:Offer|ACK))")
_MDNS_NAME = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9_-]*\.local)\b")
_VULN = re.compile(r"(?<!NOT )VULNERABLE")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _int(v, lo, hi, default):
    try:
        if v is None or v == "" or isinstance(v, bool):
            return default
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------- wired.listen

def build_listen(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    seconds = _int((target or {}).get("seconds"), 10, 600, 60)
    return [["timeout", str(seconds), "tcpdump", "-i", hw["wired_iface"], "-nn", "-e", "-l",
             "arp or udp port 67 or udp port 68 or udp port 5353"]]


def parse_listen(stdout: str) -> dict:
    ip_macs: dict[str, list[str]] = {}
    dhcp: dict[str, str | None] = {}   # server ip -> mac
    mdns: dict[str, str] = {}          # ip? not known; collect names
    names: list[str] = []
    for line in (stdout or "").splitlines():
        hdr = _HDR.search(line)
        src_mac = hdr.group(1).lower() if hdr else None
        m = _ARP_REQ.search(line)
        if m:
            ip = m.group(2)
            if src_mac and ip != "0.0.0.0":
                ip_macs.setdefault(ip, [])
                if src_mac not in ip_macs[ip]:
                    ip_macs[ip].append(src_mac)
            continue
        m = _ARP_REP.search(line)
        if m:
            ip, mac = m.group(1), m.group(2).lower()
            lst = ip_macs.setdefault(ip, [])
            if mac not in lst:
                lst.append(mac)
            continue
        m = _DHCP_SRV.search(line)
        if m:
            dhcp.setdefault(m.group(1), src_mac)
            continue
        if "5353" in line or "mDNS" in line:
            for n in _MDNS_NAME.findall(line):
                if n not in names:
                    names.append(n)
    hosts = [{"ip": ip, "mac": macs[0]} for ip, macs in ip_macs.items()]
    anomalies = []
    for ip, macs in ip_macs.items():
        if len(macs) > 1:
            anomalies.append({"type": "arp_conflict", "ip": ip, "macs": macs[:8],
                              "detail": f"{ip} claimed by {len(macs)} MACs (possible ARP spoofing)"})
    if len(dhcp) > 1:
        anomalies.append({"type": "multiple_dhcp_servers",
                          "servers": [{"ip": ip, "mac": mac} for ip, mac in dhcp.items()][:8],
                          "detail": f"{len(dhcp)} DHCP servers answered (possible rogue DHCP)"})
    return {"hosts": hosts[:CAP], "anomalies": anomalies[:CAP], "mdns_names": names[:CAP],
            "dhcp_servers": [{"ip": ip, "mac": mac} for ip, mac in dhcp.items()][:CAP]}


def listen(task: dict, ctx) -> dict:
    steps = build_listen(task["target"], ctx.mode, ctx.scope, ctx.hw)
    outs = [ctx.runner(argv) for argv in steps]
    p = parse_listen(outs[0] if outs else "")
    n, a = len(p["hosts"]), len(p["anomalies"])
    return {"result_id": new_id(), "space": "wired", "kind": "hosts",
            "summary": f"{n} host(s) heard passively, {a} anomaly" if a == 1
            else f"{n} host(s) heard passively, {a} anomalies",
            "data": {"network": None, "hosts": p["hosts"], "anomalies": p["anomalies"],
                     "dhcp_servers": p["dhcp_servers"], "mdns_names": p["mdns_names"]}}


# ---------------------------------------------------------------- nmap.vuln

def build_vuln(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    ip = target["ip"]
    if mode == "stealth":
        return [["nmap", "-sS", "-T2", "--top-ports", "100", "--script", "vuln",
                 "--host-timeout", "800s", "-oX", "-", ip]]
    return [["nmap", "-sV", "--script", "vuln", "-T4", "--host-timeout", "800s", "-oX", "-", ip]]


def parse_vuln(xml: str) -> list[dict]:
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, TypeError, ValueError):
        return []
    out = []

    def add(script, port):
        output = script.get("output") or ""
        if not _VULN.search(output):
            return
        cves = []
        for c in _CVE.findall(output):
            c = c.upper()
            if c not in cves:
                cves.append(c)
        out.append({"id": script.get("id"), "port": port,
                    "output": output.strip()[:200], "cves": cves[:16]})

    for h in root.findall("host"):
        ports = h.find("ports")
        if ports is not None:
            for p in ports.findall("port"):
                try:
                    pn = int(p.get("portid"))
                except (TypeError, ValueError):
                    pn = None
                for s in p.findall("script"):
                    add(s, pn)
        hs = h.find("hostscript")
        if hs is not None:
            for s in hs.findall("script"):
                add(s, None)
    return out[:CAP]


def vuln(task: dict, ctx) -> dict:
    steps = build_vuln(task["target"], ctx.mode, ctx.scope, ctx.hw)
    outs = [ctx.runner(argv) for argv in steps]
    findings = parse_vuln(outs[0] if outs else "")
    ip = task["target"]["ip"]
    return {"result_id": new_id(), "space": "wired", "kind": "vulns",
            "summary": f"{ip}: {len(findings)} vulnerable finding(s)",
            "data": {"ip": ip, "findings": findings}}


# ---------------------------------------------------------------- smb.enum

def build_smb(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    return [["smbclient", "-N", "-g", "-L", f"//{target['ip']}"]]


def parse_smb(stdout: str) -> dict:
    shares = []
    anonymous = None
    errors = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if "Anonymous login successful" in line:
            anonymous = True
            continue
        m = re.search(r"NT_STATUS_[A-Z0-9_]+", line)
        if m:
            if m.group(0) not in errors:
                errors.append(m.group(0))
            continue
        parts = line.split("|")
        if len(parts) >= 2 and parts[0] in ("Disk", "IPC", "Printer"):
            shares.append({"type": parts[0], "name": parts[1],
                           "comment": parts[2] if len(parts) > 2 else ""})
    if errors and anonymous is None:
        anonymous = False
    return {"shares": shares[:CAP], "anonymous": anonymous, "errors": errors[:16]}


def smb_enum(task: dict, ctx) -> dict:
    steps = build_smb(task["target"], ctx.mode, ctx.scope, ctx.hw)
    outs = [ctx.runner(argv) for argv in steps]
    p = parse_smb(outs[0] if outs else "")
    ip = task["target"]["ip"]
    extra = ", anonymous OK" if p["anonymous"] else (f", {p['errors'][0]}" if p["errors"] else "")
    return {"result_id": new_id(), "space": "wired", "kind": "smb_shares",
            "summary": f"{ip}: {len(p['shares'])} SMB share(s){extra}",
            "data": {"ip": ip, **p}}


# ---------------------------------------------------------------- web.scan

def _web_url(target: dict) -> str:
    port = _int(target.get("port"), 1, 65535, 80)
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{target['ip']}:{port}/"


def build_web(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    # Never follow redirects: the gate only checked this ip, a 302 could point anywhere.
    return [["whatweb", "-q", "--color=never", "--no-errors", "--follow-redirect=never",
             "-a", "1" if mode == "stealth" else "3", "--log-json=/dev/stdout", _web_url(target)]]


def _web_records(stdout: str) -> list[dict]:
    text = (stdout or "").strip()
    recs: list = []
    if not text:
        return []
    try:
        data = json.loads(text)
        recs = data if isinstance(data, list) else [data]
    except ValueError:
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line in ("[", "]", ""):
                continue
            try:
                recs.append(json.loads(line))
            except ValueError:
                continue
    return [r for r in recs if isinstance(r, dict)]


def parse_web(stdout: str) -> list[dict]:
    out = []
    for r in _web_records(stdout):
        plugins = r.get("plugins")
        techs, title = [], None
        if isinstance(plugins, dict):
            for name, info in plugins.items():
                if name == "Title" and isinstance(info, dict):
                    t = info.get("string")
                    title = t[0] if isinstance(t, list) and t else (t if isinstance(t, str) else None)
                    continue
                ver = None
                if isinstance(info, dict):
                    v = info.get("version")
                    if isinstance(v, list) and v:
                        ver = str(v[0])
                    elif isinstance(v, (str, int, float)):
                        ver = str(v)
                techs.append(f"{name} {ver}" if ver else str(name))
        out.append({"url": r.get("target"), "status": r.get("http_status"),
                    "title": title, "technologies": techs[:CAP]})
    return out[:CAP]


def web_scan(task: dict, ctx) -> dict:
    steps = build_web(task["target"], ctx.mode, ctx.scope, ctx.hw)
    outs = [ctx.runner(argv) for argv in steps]
    recs = parse_web(outs[0] if outs else "")
    url = _web_url(task["target"])
    first = recs[0] if recs else {"url": url, "status": None, "title": None, "technologies": []}
    return {"result_id": new_id(), "space": "wired", "kind": "web",
            "summary": f"{url}: {first['status'] or '?'}, {len(first['technologies'])} technologies",
            "data": {"url": first["url"] or url, "status": first["status"], "title": first["title"],
                     "technologies": first["technologies"]}}
