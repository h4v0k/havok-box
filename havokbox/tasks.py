"""One builder for every proposal (design-check #6, #7, #1).

Planner and commander output are both rebuilt here from registry data, so nothing a model or a
rule emits reaches the store as-is:
- id from new_id(); category from the registry; mode from the finding;
- target restricted to the tool's declared params (unknown keys REJECTED, not stripped),
  validated, and canonicalised (lowercase BSSIDs, canonical IPs/CIDRs);
- step_kind derived from tool + canonical target, so both paths dedupe onto the same row;
- label generated in code — LLM text is never displayed.

`task_digest` binds an approval to the exact command: SHA-256 over
{tool, category, target, mode, preview argv}.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json

from .store import new_id
from .tools import validate_params

LABELS = {
    "nmap.discovery": "Discover hosts on {network}",
    "nmap.services": "Scan services on {ip}",
    "nmap.vuln": "Vuln scan (NSE) on {ip}",
    "smb.enum": "Enumerate SMB on {ip}",
    "web.scan": "Scan web service {ip}:{port}",
    "wired.listen": "Listen for hosts (passive)",
    "kismet.scan": "Scan Wi-Fi",
    "wifi.watch": "Watch AP {bssid} (ch {channel})",
    "wifi.capture": "Capture handshake on {bssid} (passive)",
    "wifi.capture_deauth": "Capture handshake on {bssid} (with deauth)",
    "wifi.deauth": "Deauth on {bssid}",
    "ble.scan": "Scan BLE",
    "ble.gatt": "Enumerate GATT services on {addr}",
    "sdr.survey": "Spectrum survey",
    "sdr.decode": "Decode IoT ({freq})",
    "subghz.scan": "Scan sub-GHz",
    "subghz.replay": "Replay {id} at {freq_mhz} MHz",
    "marauder.scan": "Scan Wi-Fi (ESP)",
    "marauder.deauth": "Deauth (ESP) on {bssid}",
    "air.adsb": "Aircraft (ADS-B)",
    "air.ais": "Ships (AIS)",
    "responder.analyze": "Listen for name requests (Responder -A)",
    "p0f.listen": "Passive OS fingerprint (p0f)",
    "cleartext.find": "Find cleartext services",
    "ipv6.listen": "Watch for new IPv6 hosts",
    "nuclei.scan": "Nuclei detection scan on {ip}",
    "tls.scan": "TLS scan {ip}",
    "web.content": "Web content discovery {ip}",
    "smb.nxc": "SMB null-session enum {ip}",
    "ldap.anon": "Anonymous LDAP {ip}",
    "snmp.enum": "SNMP enum {ip}",
    "exploit.lookup": "Exploit-DB lookup: {query}",
    "creds.default": "Default-credential check {ip} ({service})",
    "net.poison.responder": "LLMNR/NBT-NS poison on {network}",
    "net.poison.mitm6": "mitm6 on {network} ({domain})",
    "wifi.rogue_ap": "Rogue AP for {ssid}",
}
# Label suffixes for optional params that change what the action does.
LABEL_SUFFIX = {"client": " → client {client}"}


class TaskError(ValueError):
    pass


def canonical_target(spec, target) -> dict:
    if target is None:
        target = {}
    if not isinstance(target, dict):
        raise TaskError("target must be an object")
    unknown = set(target) - set(spec.params)
    if unknown:
        raise TaskError(f"unknown target keys for {spec.name}: {sorted(unknown)}")
    ok, why = validate_params(spec, target)
    if not ok:
        raise TaskError(why)
    out = {}
    for k, v in target.items():
        kind = spec.params[k]["type"]
        if kind == "ip":
            v = str(ipaddress.ip_address(v))
        elif kind == "cidr":
            v = str(ipaddress.ip_network(v, strict=False))
        elif kind == "bssid":
            v = str(v).lower()
        out[k] = v
    return out


def step_kind(tool: str, target: dict) -> str:
    return tool + ":" + ",".join(f"{k}={target[k]}" for k in sorted(target))


def make_task(registry: dict, tool: str, target, mode: str, result_id: str,
              suggested: bool = False, source: str = "planner") -> dict:
    spec = registry.get(tool)
    if spec is None:
        raise TaskError(f"tool not registered: {tool!r}")
    if mode not in ("stealth", "standard"):
        raise TaskError(f"bad mode: {mode!r}")
    tgt = canonical_target(spec, target)
    sk = step_kind(spec.name, tgt)
    try:
        label = LABELS.get(spec.name, spec.name).format(**tgt)
        for key, fmt in LABEL_SUFFIX.items():
            if key in tgt:
                label += fmt.format(**tgt)
        if spec.name in ("wifi.deauth", "marauder.deauth") and "client" not in tgt:
            label += " (broadcast)"
    except (KeyError, IndexError):
        label = spec.name
    return {"id": new_id(), "category": spec.category, "tool": spec.name, "target": tgt,
            "mode": mode, "step_kind": sk, "label": label, "suggested": bool(suggested),
            "source": source, "_rid": result_id, "_step": sk}


def task_digest(task: dict, argv: list[str] | None) -> str:
    blob = json.dumps({"tool": task.get("tool"), "category": task.get("category"),
                       "target": task.get("target") or {}, "mode": task.get("mode"),
                       "argv": argv}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()
