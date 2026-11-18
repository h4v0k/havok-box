"""Tool registry. Tier and argv are fixed here in code, never taken from a proposal.

Each tool declares typed parameters. build() validates them and returns the exact
argv plus every target that argv touches. The gate checks those targets.
No tool takes a hostname, a file of targets, or free-form flags.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable

from .scope import Target, norm_mac, ScopeError

PASSIVE, ACTIVE, INTRUSIVE = "passive", "active", "intrusive"
IFACE_RE = re.compile(r"^[a-z][a-z0-9]{1,14}$")
PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?){0,31}$")


class ArgError(ValueError):
    pass


def p_iface(v):
    if not isinstance(v, str) or not IFACE_RE.match(v):
        raise ArgError(f"bad interface name: {v!r}")
    return v


def p_cidr(v):
    try:
        return str(ipaddress.ip_network(str(v), strict=True))
    except ValueError as e:
        raise ArgError(f"bad network: {v!r}") from e


def p_ports(v):
    v = str(v)
    if not PORTS_RE.match(v) or any(int(n) > 65535 for n in re.split(r"[,-]", v)):
        raise ArgError(f"bad port list: {v!r}")
    return v


def p_mac(v):
    try:
        return norm_mac(v)
    except ScopeError as e:
        raise ArgError(str(e)) from e


def p_int(lo, hi):
    def f(v):
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ArgError(f"expected a whole number from {lo} to {hi}, got {v!r}")
        return v
    return f


@dataclass(frozen=True)
class ToolSpec:
    name: str
    tier: str
    params: dict                      # name -> validator
    build: Callable[[dict], tuple]    # clean args -> (argv, [Target])
    summary: str

    def prepare(self, args: dict) -> tuple[dict, list, list]:
        if not isinstance(args, dict):
            raise ArgError("args must be a mapping")
        extra = set(args) - set(self.params)
        missing = set(self.params) - set(args)
        if extra or missing:
            raise ArgError(f"{self.name}: unexpected {sorted(extra)}, missing {sorted(missing)}")
        clean = {k: self.params[k](args[k]) for k in sorted(self.params)}
        argv, targets = self.build(clean)
        return clean, list(argv), list(targets)


REGISTRY: dict[str, ToolSpec] = {}


def register(spec: ToolSpec):
    if spec.tier not in (PASSIVE, ACTIVE, INTRUSIVE):
        raise ValueError(spec.tier)
    REGISTRY[spec.name] = spec


register(ToolSpec(
    "wifi_survey", PASSIVE, {"iface": p_iface, "seconds": p_int(10, 3600)},
    lambda a: (["timeout", str(a["seconds"]), "kismet", "--no-ncurses", "-c", a["iface"]], []),
    "Listen for Wi-Fi access points and clients (receive only)."))

register(ToolSpec(
    "lan_watch", PASSIVE, {"iface": p_iface, "seconds": p_int(10, 3600)},
    lambda a: (["tshark", "-i", a["iface"], "-a", f"duration:{a['seconds']}", "-f", "arp or (udp port 67 or udp port 68)",
                "-T", "ek"], []),
    "Watch ARP and DHCP traffic for spoofing and rogue DHCP servers (receive only)."))

register(ToolSpec(
    "arp_scan", ACTIVE, {"iface": p_iface, "network": p_cidr},
    lambda a: (["arp-scan", "-I", a["iface"], a["network"]], [Target("cidr", a["network"])]),
    "Find live hosts on a local network."))

register(ToolSpec(
    "nmap_discovery", ACTIVE, {"network": p_cidr},
    lambda a: (["nmap", "-n", "-sn", "-oX", "-", a["network"]], [Target("cidr", a["network"])]),
    "Ping sweep of a network."))

register(ToolSpec(
    "nmap_services", ACTIVE, {"network": p_cidr, "ports": p_ports},
    lambda a: (["nmap", "-n", "-sV", "-p", a["ports"], "-oX", "-", a["network"]], [Target("cidr", a["network"])]),
    "Service and version scan of chosen ports."))
