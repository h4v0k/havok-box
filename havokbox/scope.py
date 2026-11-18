"""Scope model and gate — the single authority for what a task may touch.

Pure, non-AI, fail-closed. The gate never says "allowed" unless the task's target is
explicitly in scope for its category; a missing or empty target list is a refusal, not a
pass. Active categories always come back needing approval.

`load_scope()` reads config/scope.yaml (PyYAML, a runtime dep on the Pi). The gate logic
itself works on a plain dict, so it is testable without YAML.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

PASSIVE = "recon.passive"
DISCOVERY = "recon.discovery"
NETWORK_CATEGORIES = {"recon.active", "auth.attempt", "exploit.tool"}
WIFI_CATEGORIES = {"wifi.deauth", "wifi.inject"}
RF_TX_CATEGORIES = {"rf.replay", "rf.transmit"}
KNOWN = {PASSIVE, DISCOVERY} | NETWORK_CATEGORIES | WIFI_CATEGORIES | RF_TX_CATEGORIES


@dataclass(frozen=True)
class Decision:
    allowed: bool
    needs_approval: bool
    reason: str


class Scope:
    def __init__(self, data: dict):
        nets = data.get("networks") or {}
        self.include = [ipaddress.ip_network(c, strict=False) for c in nets.get("include", [])]
        self.exclude = [ipaddress.ip_network(c, strict=False) for c in nets.get("exclude", [])]
        wifi = data.get("wifi") or {}
        self.bssids = {b.lower() for b in (wifi.get("bssids") or [])}
        self.ssids = set(wifi.get("ssids") or [])
        rf = data.get("rf") or {}
        self.ble = {a.lower() for a in (rf.get("ble_addresses") or [])}
        self.subghz = {str(s) for s in (rf.get("subghz_ids") or [])}
        self.tx_bands = [
            (float(b["min_mhz"]), float(b["max_mhz"])) for b in (rf.get("tx_bands") or [])
        ]
        self.auto_allow = set(data.get("auto_allow") or [])
        self.approval_required = set(data.get("approval_required") or [])

    def ip_in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(addr in n for n in self.exclude):
            return False
        return any(addr in n for n in self.include)

    def network_in_scope(self, cidr: str) -> bool:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        # A fully-excluded network is refused. A network that merely *contains* an excluded
        # host is still in scope — those hosts are skipped at scan time via nmap --exclude.
        if any(net.subnet_of(ex) for ex in self.exclude):
            return False
        return any(net.subnet_of(inc) for inc in self.include)

    def freq_allowed(self, mhz: float) -> bool:
        return any(lo <= mhz <= hi for lo, hi in self.tx_bands)


class Gate:
    """Decide a single proposed task against the scope. Fail-closed."""

    def __init__(self, scope: Scope):
        self.scope = scope

    def evaluate(self, task: dict) -> Decision:
        category = task.get("category")
        target = task.get("target") or {}

        if category not in KNOWN:
            return Decision(False, False, f"unknown category: {category!r}")

        if category == PASSIVE:
            if PASSIVE in self.scope.auto_allow:
                return Decision(True, False, "passive recon, auto-allowed")
            return Decision(False, False, "recon.passive not in auto_allow")

        if category == DISCOVERY:
            net = (task.get("target") or {}).get("network")
            if not net or not self.scope.network_in_scope(net):
                return Decision(False, False, f"network {net!r} not within networks.include (or excluded)")
            if DISCOVERY in self.scope.auto_allow:
                return Decision(True, False, f"host discovery on in-scope {net}, auto-allowed")
            return self._approval(DISCOVERY, f"host discovery on {net}")

        if category in NETWORK_CATEGORIES:
            ip = target.get("ip")
            if not ip or not self.scope.ip_in_scope(ip):
                return Decision(False, False, f"target ip {ip!r} not in networks.include (or excluded)")
            return self._approval(category, f"{category} on in-scope {ip}")

        if category in WIFI_CATEGORIES:
            bssid = (target.get("bssid") or "").lower()
            if not bssid or bssid not in self.scope.bssids:
                return Decision(False, False, f"target bssid {bssid or '(none)'!r} not in wifi.bssids")
            return self._approval(category, f"{category} on in-scope {bssid}")

        if category in RF_TX_CATEGORIES:
            dev = str(target.get("id") or "").lower()
            if not (dev in self.scope.ble or dev in self.scope.subghz):
                return Decision(False, False, f"target rf id {dev or '(none)'!r} not in rf scope")
            freq = target.get("freq_mhz")
            if freq is None or not self.scope.freq_allowed(float(freq)):
                return Decision(False, False, f"freq {freq!r} MHz not within any rf.tx_bands entry")
            return self._approval(category, f"{category} on {dev} at {freq} MHz")

        return Decision(False, False, "unhandled category")  # unreachable; fail-closed

    def _approval(self, category: str, why: str) -> Decision:
        # Active categories are allowed to proceed only to the approval step.
        return Decision(True, True, f"in scope, needs approval: {why}")
