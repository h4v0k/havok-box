"""Box runtime config (not scope — scope lives only in config/scope.yaml).

Read from a JSON file (default config/box.json) with HAVOKBOX_* env overrides for secrets.
Everything risky defaults OFF: the Console is disabled, the API commander is disabled until a
key and a spend cap are set.
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field

MODES = ("stealth", "standard")


@dataclass
class BoxConfig:
    db_path: str = "/data/havokbox/box.db"
    scope_path: str = "config/scope.yaml"
    token: str = ""                          # dashboard bearer token; empty = refuse everything
    lan_cidrs: list = field(default_factory=lambda: ["192.168.4.0/24"])  # box-LAN (its own AP / hotspot)
    default_mode: str = "stealth"
    session_limit_s: int = 4 * 3600          # watchdog ends the session after this
    tool_timeout_s: int = 900                # one hung tool can't block the job queue for hours
    # Console (web terminal) — escape hatch, OFF by default.
    console_enabled: bool = False
    console_port: int = 7681
    console_iface: str = "wlan0"
    console_password: str = ""               # separate from the dashboard token; required to run
    box_address: str = "192.168.4.1"         # address handed out in the console link
    evidence_dir: str = "/data/havokbox/evidence"
    # API commander — OFF until key + cap are set.
    commander_model: str = "claude-haiku-5-5"   # cheap default; configurable
    commander_max_calls_per_day: int = 0     # 0 = disabled (spend cap; req 8)
    anthropic_api_key: str = ""
    drain_interval_s: int = 30
    # TLS — fails closed: the server won't start without cert+key unless explicitly allowed.
    tls_cert: str = "/data/havokbox/tls/box.crt"
    tls_key: str = "/data/havokbox/tls/box.key"
    allow_insecure_http: bool = False
    source_path: str = ""
    hw: dict = field(default_factory=dict)  # interface/serial overrides; see tools.DEFAULT_HW
    # Phase 2: one-way read-only snapshot to Cloudflare. Empty URL = publishing off.
    publish_url: str = ""                    # e.g. https://havok-box-snapshot.<you>.workers.dev
    publish_token: str = ""                  # write-only ingest token (HAVOKBOX_PUBLISH_TOKEN)
    publish_evidence_limit: int = 2000
    box_name: str = "havok-box"
    # Wardrive (receive-only). "mine": your own device MACs/BLE addresses (phone, watch, car).
    wardrive_mine: list = field(default_factory=list)
    wardrive_retention_days: int = 7
    # Drive Guard (Phase 5)
    guard_token: str = ""                    # tablet token: reaches /api/guard/* only
    discord_webhook: str = ""                # env HAVOKBOX_DISCORD_WEBHOOK only (never in box.json)
    discord_map_links: bool = False          # car position in phone alerts: opt-in (Guard #8)
    guard_quiet_zones: list = field(default_factory=list)   # [{"lat","lon","radius_m"}] home/work
    sentry_limit_s: int = 14 * 3600
    alpr_path: str = "/data/havokbox/alpr.json"
    # Phase 6
    lab_gateway: str = ""                    # baseline drift: ARP-spoof check on the gateway
    pinned_static: list = field(default_factory=list)   # other static IPs to watch
    rayhunter_url: str = ""                  # e.g. http://192.168.1.1:8080 (USB tether); off when empty

    def hardware(self) -> dict:
        from .tools import DEFAULT_HW
        return {**DEFAULT_HW, **(self.hw or {})}                    # where this config was loaded from (for re-reads)

    @classmethod
    def load(cls, path: str | None = None, env=None) -> "BoxConfig":
        env = os.environ if env is None else env
        path = path or env.get("HAVOKBOX_CONFIG", "config/box.json")
        data = {}
        if path and os.path.exists(path):
            with open(path) as fh:
                data = json.load(fh)
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        cfg = cls(**known)
        cfg.source_path = path or ""
        if env.get("HAVOKBOX_TOKEN"):
            cfg.token = env["HAVOKBOX_TOKEN"]
        if env.get("HAVOKBOX_CONSOLE_PASSWORD"):
            cfg.console_password = env["HAVOKBOX_CONSOLE_PASSWORD"]
        if env.get("HAVOKBOX_PUBLISH_TOKEN"):
            cfg.publish_token = env["HAVOKBOX_PUBLISH_TOKEN"]
        if env.get("HAVOKBOX_GUARD_TOKEN"):
            cfg.guard_token = env["HAVOKBOX_GUARD_TOKEN"]
        cfg.discord_webhook = env.get("HAVOKBOX_DISCORD_WEBHOOK", "")   # env only, by design
        if env.get("ANTHROPIC_API_KEY"):
            cfg.anthropic_api_key = env["ANTHROPIC_API_KEY"]
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.default_mode not in MODES:
            raise ValueError(f"default_mode must be one of {MODES}")
        for c in self.lan_cidrs:
            ipaddress.ip_network(c, strict=False)
        if self.publish_url and not self.publish_url.startswith("https://"):
            raise ValueError("publish_url must be https://")
        if self.session_limit_s <= 0:
            raise ValueError("session_limit_s must be > 0")

    def console_enabled_now(self) -> bool:
        """Re-read the console flag from disk every time — never cached (design-check #11)."""
        if not self.source_path:
            return self.console_enabled
        try:
            with open(self.source_path) as fh:
                return bool(json.load(fh).get("console_enabled", False))
        except (OSError, ValueError):
            return False  # unreadable config -> console off

    def tls_ready(self) -> bool:
        return os.path.exists(self.tls_cert) and os.path.exists(self.tls_key)

    def on_lan(self, client_ip: str | None) -> bool:
        try:
            addr = ipaddress.ip_address(client_ip or "")
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(c, strict=False) for c in self.lan_cidrs)
