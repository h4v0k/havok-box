"""nmap wrappers: host discovery (standard mode) and service scan (stealth vs standard flags).

Parsers take nmap's XML (-oX -) so they're testable without running nmap. The runner is injected
by the orchestrator, so nothing here shells out during tests.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ..store import new_id


def build_discovery_cmd(network: str, excludes: list[str] | None = None) -> list[str]:
    # Standard, active host discovery. Stealth discovery is a separate passive listener tool.
    cmd = ["nmap", "-sn"]
    if excludes:
        cmd += ["--exclude", ",".join(e.split("/")[0] for e in excludes)]
    cmd += ["-oX", "-", network]
    return cmd


def build_services_cmd(ip: str, mode: str) -> list[str]:
    if mode == "stealth":
        return ["nmap", "-sS", "-T1", "--scan-delay", "200ms", "--top-ports", "100", "-f", "-oX", "-", ip]
    return ["nmap", "-sV", "-sC", "-T4", "-oX", "-", ip]


def parse_discovery(xml: str) -> list[dict]:
    hosts = []
    root = ET.fromstring(xml)
    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = None
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
        if ip:
            hosts.append({"ip": ip, "mac": mac})
    return hosts


def parse_services(xml: str) -> list[dict]:
    out = []
    root = ET.fromstring(xml)
    for h in root.findall("host"):
        ip = None
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
        ports = h.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            out.append({
                "ip": ip,
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "service": svc.get("name") if svc is not None else None,
                "version": (svc.get("product") if svc is not None else None),
            })
    return out


def discovery(task: dict, ctx) -> dict:
    network = task["target"]["network"]
    excludes = [str(e) for e in ctx.scope.exclude]  # a sweep can never touch excluded hosts
    xml = ctx.runner(build_discovery_cmd(network, excludes))
    hosts = parse_discovery(xml)
    return {
        "result_id": new_id(),
        "space": "wired",
        "kind": "hosts",
        "summary": f"{len(hosts)} host(s) up on {network}",
        "data": {"network": network, "hosts": hosts},
    }


def services(task: dict, ctx) -> dict:
    ip = task["target"]["ip"]
    xml = ctx.runner(build_services_cmd(ip, ctx.mode))
    svcs = parse_services(xml)
    openp = ", ".join(str(s["port"]) for s in svcs) or "none"
    return {
        "result_id": new_id(),
        "space": "wired",
        "kind": "services",
        "summary": f"{ip}: {len(svcs)} open port(s) ({openp})",
        "data": {"ip": ip, "services": svcs},
    }
