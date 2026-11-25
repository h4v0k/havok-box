"""Scope model and gate — the single authority for what a task may touch.

Pure, non-AI, fail-closed. The gate never says "allowed" unless the task's target is
explicitly in scope for its category; a missing or empty target list is a refusal, not a
pass. Active categories always come back needing approval.

`load_scope()` reads config/scope.yaml (PyYAML, a runtime dep on the Pi). The gate logic
itself works on a plain dict, so it is testable without YAML.
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass

PASSIVE = "recon.passive"
DISCOVERY = "recon.discovery"
# Finding the lab before an engagement exists: host discovery only (ARP / ping, no ports) on a
# PRIVATE range no bigger than a /16 that isn't on the never list (networks.exclude). The box's own
# connected subnets are auto-allowed (the tool re-checks the claim); a typed range needs approval.
LOCAL = "recon.local"
NETWORK_CATEGORIES = {"recon.active", "auth.attempt", "exploit.tool"}
# wifi.capture: listening for one AP's handshake/PMKID. Passive on air, but it collects auth
# material, so it is bound to an in-scope BSSID and needs approval like the active ones.
WIFI_CATEGORIES = {"wifi.deauth", "wifi.inject", "wifi.capture"}
BLE_CATEGORIES = {"ble.active"}          # connecting to a BLE device (GATT enumeration)
RF_TX_CATEGORIES = {"rf.replay", "rf.transmit"}
# Kali Test pack. net.poison (LLMNR/NBT-NS/mDNS poisoning, mitm6) is bound to an ISOLATED lab VLAN
# the owner lists separately in networks.poison_allowed — NOT the general include list. wifi.rogue_ap
# is bound to the owner's own wifi.ssids. Both need approval and are refused during wardrive/sentry.
POISON = "net.poison"
ROGUE_AP = "wifi.rogue_ap"
KNOWN = ({PASSIVE, DISCOVERY, LOCAL} | NETWORK_CATEGORIES | WIFI_CATEGORIES | BLE_CATEGORIES
         | RF_TX_CATEGORIES | {POISON, ROGUE_AP})


@dataclass(frozen=True)
class Decision:
    allowed: bool
    needs_approval: bool
    reason: str


class Scope:
    def __init__(self, data: dict, engagement_path: str | None = None, clock=time.time):
        self._base_name = str(data.get("name") or "")
        nets = data.get("networks") or {}
        self._base_include = [ipaddress.ip_network(c, strict=False) for c in nets.get("include", [])]
        self.engagement_path = engagement_path
        self._clock = clock
        self.exclude = [ipaddress.ip_network(c, strict=False) for c in nets.get("exclude", [])]
        wifi = data.get("wifi") or {}
        self.bssids = {b.lower() for b in (wifi.get("bssids") or [])}
        self.ssids = set(wifi.get("ssids") or [])
        rf = data.get("rf") or {}
        self.ble = {a.lower() for a in (rf.get("ble_addresses") or [])}
        self.subghz = {str(s).lower() for s in (rf.get("subghz_ids") or [])}
        self.tx_bands = [
            (float(b["min_mhz"]), float(b["max_mhz"])) for b in (rf.get("tx_bands") or [])
        ]
        # Isolated lab VLAN(s) for poisoning — deliberately separate from include (fail-closed if unset)
        self.poison_allowed = [ipaddress.ip_network(c, strict=False)
                               for c in (nets.get("poison_allowed") or [])]
        self.domains = {d.lower() for d in (data.get("domains") or [])}
        self.auto_allow = set(data.get("auto_allow") or [])
        self.approval_required = set(data.get("approval_required") or [])

    # ---- engagement (time-boxed lab scope; see havokbox/engagement.py) ----
    def engagement(self) -> dict | None:
        from .engagement import read
        return read(self.engagement_path, self._clock)

    def _engagement_networks(self) -> list:
        eng = self.engagement()
        if not eng:
            return []
        from .engagement import EngagementError, validate_networks
        try:   # re-check on every read: a hand-edited file can't smuggle in a public or never range
            nets = validate_networks(eng.get("networks") or [], self.exclude, bool(eng.get("allow_public")))
        except EngagementError:
            return []
        return [ipaddress.ip_network(n) for n in nets]

    @property
    def include(self) -> list:
        return self._base_include + self._engagement_networks()

    @property
    def name(self) -> str:
        eng = self.engagement()
        return str(eng["name"]) if eng else self._base_name

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

    def network_poison_allowed(self, cidr: str) -> bool:
        """True only if the whole network is inside an explicit poison_allowed VLAN (never include)."""
        if not self.poison_allowed:
            return False
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        return any(net.subnet_of(a) for a in self.poison_allowed)

    def ip_poison_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in a for a in self.poison_allowed)


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
                return Decision(False, False, f"network {net!r} not in the engagement (or on the never list)")
            if DISCOVERY in self.scope.auto_allow:
                return Decision(True, False, f"host discovery on in-scope {net}, auto-allowed")
            return self._approval(DISCOVERY, f"host discovery on {net}")

        if category == LOCAL:
            return self._local(target)

        if category in NETWORK_CATEGORIES:
            ip = target.get("ip")
            if not ip or not self.scope.ip_in_scope(ip):
                return Decision(False, False, f"target ip {ip!r} not in the engagement (or on the never list)")
            return self._approval(category, f"{category} on in-scope {ip}")

        if category in WIFI_CATEGORIES:
            bssid = (target.get("bssid") or "").lower()
            if not bssid or bssid not in self.scope.bssids:
                return Decision(False, False, f"target bssid {bssid or '(none)'!r} not in wifi.bssids")
            return self._approval(category, f"{category} on in-scope {bssid}")

        if category in BLE_CATEGORIES:
            addr = str(target.get("addr") or "").lower()
            if not addr or addr not in self.scope.ble:
                return Decision(False, False, f"target ble addr {addr or '(none)'!r} not in rf.ble_addresses")
            return self._approval(category, f"{category} on in-scope {addr}")

        if category == POISON:
            net = target.get("network")
            if not net or not self.scope.network_poison_allowed(net):
                return Decision(False, False,
                                f"network {net!r} not in networks.poison_allowed (isolated lab VLAN only)")
            dom = target.get("domain")
            if dom is not None and str(dom).lower() not in self.scope.domains:
                return Decision(False, False, f"domain {dom!r} not in scope domains")
            return self._approval(category, f"poisoning on isolated VLAN {net}")

        if category == ROGUE_AP:
            ssid = target.get("ssid")
            if not ssid or ssid not in self.scope.ssids:
                return Decision(False, False, f"ssid {ssid!r} not in wifi.ssids (your own SSIDs only)")
            return self._approval(category, f"rogue AP for your SSID {ssid}")

        if category in RF_TX_CATEGORIES:
            dev = str(target.get("id") or "").lower()
            if not (dev in self.scope.ble or dev in self.scope.subghz):
                return Decision(False, False, f"target rf id {dev or '(none)'!r} not in rf scope")
            freq = target.get("freq_mhz")
            if freq is None or not self.scope.freq_allowed(float(freq)):
                return Decision(False, False, f"freq {freq!r} MHz not within any rf.tx_bands entry")
            return self._approval(category, f"{category} on {dev} at {freq} MHz")

        return Decision(False, False, "unhandled category")  # unreachable; fail-closed

    def _local(self, target: dict) -> Decision:
        net_s = target.get("network")
        try:
            net = ipaddress.ip_network(str(net_s), strict=False)
        except ValueError:
            return Decision(False, False, f"network {net_s!r} is not a CIDR range")
        if not net.is_private or net.is_loopback or net.is_link_local:
            return Decision(False, False, f"{net} is not a private range; lab discovery is private-only")
        if net.prefixlen < (16 if net.version == 4 else 48):
            return Decision(False, False, f"{net} is larger than a /16")
        if any(net.subnet_of(ex) for ex in self.scope.exclude if ex.version == net.version):
            return Decision(False, False, f"{net} is on the never-touch list (networks.exclude)")
        if target.get("connected") is True:
            return Decision(True, False, f"host discovery on the box's own subnet {net}")
        return self._approval(LOCAL, f"host discovery (no ports) on {net}")

    def _approval(self, category: str, why: str) -> Decision:
        # Active categories are allowed to proceed only to the approval step.
        return Decision(True, True, f"in scope, needs approval: {why}")


def load_scope(path: str = "config/scope.yaml", engagement_path: str | None = None) -> Scope:
    """Read the scope file. A missing or empty file is an error, never an empty-but-valid scope."""
    import yaml  # runtime dep on the Pi

    with open(path) as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or not data:
        raise ValueError(f"scope file {path} is empty or not a mapping")
    return Scope(data, engagement_path=engagement_path)
