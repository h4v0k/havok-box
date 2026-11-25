"""Lab-network discovery: find which networks the box is sitting on, then which hosts are up.

net.local  — passive: reads the box's own interfaces and routes (`ip -j addr`, `ip -j route`).
             Nothing leaves the box.
net.find   — recon.local: host discovery only (no ports). On a subnet the box is attached to it
             uses arp-scan; on a typed range it uses `nmap -sn`. Both always pass the never-list.

The gate lets net.find run without approval ONLY when the task says `connected: true`. That claim
is not trusted: this tool re-reads the interfaces and refuses if the range isn't really attached.
"""
from __future__ import annotations

import ipaddress
import json
import re

from ..store import new_id

_ARP_LINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})\s*(.*)$")
_SKIP_IFACES = ("lo",)
CAP = 256


# ---------------------------------------------------------------- parsing

def parse_addrs(stdout: str) -> list[dict]:
    """`ip -j -4 addr` -> [{iface, ip, network, prefix}] for private IPv4 addresses (no loopback)."""
    try:
        data = json.loads(stdout or "[]")
    except ValueError:
        return []
    out = []
    for link in data if isinstance(data, list) else []:
        iface = link.get("ifname", "")
        if iface in _SKIP_IFACES or "UP" not in (link.get("flags") or []):
            continue
        for a in link.get("addr_info") or []:
            if a.get("family") != "inet":
                continue
            try:
                itf = ipaddress.ip_interface(f"{a.get('local')}/{a.get('prefixlen')}")
            except ValueError:
                continue
            if itf.ip.is_loopback or itf.ip.is_link_local:
                continue
            out.append({"iface": iface, "ip": str(itf.ip), "network": str(itf.network),
                        "prefix": itf.network.prefixlen, "private": itf.ip.is_private})
    return out


def parse_routes(stdout: str) -> list[dict]:
    """`ip -j -4 route` -> [{dst, via, dev}] (default route included as dst='default')."""
    try:
        data = json.loads(stdout or "[]")
    except ValueError:
        return []
    out = []
    for r in data if isinstance(data, list) else []:
        out.append({"dst": r.get("dst", ""), "via": r.get("gateway"), "dev": r.get("dev", "")})
    return out


def parse_arp_scan(stdout: str) -> list[dict]:
    hosts, seen = [], set()
    for line in (stdout or "").splitlines():
        m = _ARP_LINE.match(line.strip())
        if not m or m.group(1) in seen:
            continue
        seen.add(m.group(1))
        hosts.append({"ip": m.group(1), "mac": m.group(2).lower(),
                      "vendor": (m.group(3) or "").strip()[:64] or None})
        if len(hosts) >= CAP:
            break
    return hosts


def candidates(addrs: list[dict], never: list) -> list[dict]:
    """Attached networks, marked usable or not (and why), for the 'pick your lab' list."""
    out, seen = [], set()
    for a in addrs:
        net = ipaddress.ip_network(a["network"])
        if a["network"] in seen:
            continue
        seen.add(a["network"])
        why = None
        if not net.is_private:
            why = "not a private range"
        elif net.prefixlen < 16:
            why = "larger than a /16"
        elif any(net.subnet_of(ex) or net.overlaps(ex) for ex in never if ex.version == net.version):
            why = "on the never list"
        out.append({"network": a["network"], "iface": a["iface"], "box_ip": a["ip"],
                    "usable": why is None, "why_not": why})
    return out


# ---------------------------------------------------------------- net.local

def build_local(target: dict, mode: str, scope, hw: dict) -> list[list[str]]:
    return [["ip", "-j", "-4", "addr"], ["ip", "-j", "-4", "route"]]


def local(task: dict, ctx) -> dict:
    steps = build_local(task.get("target") or {}, ctx.mode, ctx.scope, ctx.hw)
    outs = [ctx.runner(argv) for argv in steps]
    addrs = parse_addrs(outs[0] if outs else "")
    routes = parse_routes(outs[1] if len(outs) > 1 else "")
    nets = candidates(addrs, list(ctx.scope.exclude))
    usable = sum(1 for n in nets if n["usable"])
    return {"result_id": new_id(), "space": "wired", "kind": "networks",
            "summary": f"box is on {len(nets)} network(s), {usable} usable as a lab",
            "data": {"networks": nets, "routes": routes[:CAP]}}


# ---------------------------------------------------------------- net.find

def _attached(addrs: list[dict], net) -> dict | None:
    for a in addrs:
        if ipaddress.ip_network(a["network"]) == net or net.subnet_of(ipaddress.ip_network(a["network"])):
            return a
    return None


def build_find(target: dict, mode: str, scope, hw: dict, iface: str | None = None) -> list[list[str]]:
    net = str(ipaddress.ip_network(target["network"], strict=False))
    excludes = [str(e) for e in scope.exclude]
    overlaps_never = any(ipaddress.ip_network(net).overlaps(e) for e in scope.exclude
                         if e.version == ipaddress.ip_network(net).version)
    if target.get("connected") is True and not overlaps_never:
        # arp-scan can't skip addresses, so a range that overlaps the never list uses nmap instead.
        cmd = ["arp-scan", "--interface", iface or hw.get("wired_iface", "eth0"),
               "--retry", "2", "--plain", net]
        return [cmd]
    cmd = ["nmap", "-sn", "-n"]
    if iface:
        cmd += ["-e", iface]
    if excludes:
        cmd += ["--exclude", ",".join(excludes)]
    cmd += ["-oX", "-", net]
    return [cmd]


def find(task: dict, ctx) -> dict:
    target = task.get("target") or {}
    net = ipaddress.ip_network(target["network"], strict=False)
    iface = None
    if target.get("connected") is True:
        # Re-check the claim the gate relied on: the range must really be attached right now.
        addrs = parse_addrs(ctx.runner(["ip", "-j", "-4", "addr"]))
        hit = _attached(addrs, net)
        if hit is None:
            return {"result_id": new_id(), "space": "wired", "kind": "error",
                    "summary": f"refused: {net} is not attached to the box (connected claim false)",
                    "data": {"network": str(net), "refused": True}}
        iface = hit["iface"]
    steps = build_find(target, ctx.mode, ctx.scope, ctx.hw, iface=iface)
    out = ctx.runner(steps[0])
    if steps[0][0] == "arp-scan":
        hosts = parse_arp_scan(out)
        never = list(ctx.scope.exclude)
        hosts = [h for h in hosts
                 if not any(ipaddress.ip_address(h["ip"]) in ex for ex in never)]
    else:
        from . import nmap as _nmap
        try:
            found = _nmap.parse_discovery(out)
        except Exception:   # empty/garbled XML -> no hosts, not a crash
            found = []
        hosts = [{"ip": h.get("ip"), "mac": h.get("mac"), "vendor": None} for h in found][:CAP]
    return {"result_id": new_id(), "space": "wired", "kind": "hosts",
            "summary": f"{len(hosts)} host(s) up on {net}",
            "data": {"network": str(net), "hosts": hosts, "method": steps[0][0]}}
