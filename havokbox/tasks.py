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
    "nmap.discovery": "Find devices on {network}",
    "net.local": "Which networks is the box on",
    "net.find": "Find devices on {network} (no ports)",
    "nmap.services": "Scan services on {ip}",
    "nmap.vuln": "Check {ip} for known weaknesses",
    "smb.enum": "Look at Windows file sharing on {ip}",
    "web.scan": "Check the website on {ip}:{port}",
    "wired.listen": "Listen for devices on the wire (no sending)",
    "kismet.scan": "Survey Wi-Fi networks",
    "wifi.watch": "Watch Wi-Fi network {bssid} (channel {channel})",
    "wifi.capture": "Listen for a Wi-Fi login handshake on {bssid}",
    "wifi.capture_deauth": "Get a Wi-Fi login handshake on {bssid} (kicks clients)",
    "wifi.deauth": "Kick clients off Wi-Fi network {bssid}",
    "ble.scan": "Find Bluetooth devices",
    "ble.gatt": "Read what Bluetooth device {addr} offers",
    "sdr.survey": "Find busy radio frequencies",
    "sdr.decode": "Decode sensor signals at {freq}",
    "subghz.scan": "Listen for remotes and key fobs",
    "subghz.replay": "Replay remote {id} at {freq_mhz} MHz",
    "marauder.scan": "Survey Wi-Fi (ESP32 board)",
    "marauder.deauth": "Kick Wi-Fi clients off {bssid} (ESP32 board)",
    "air.adsb": "Aircraft overhead",
    "radio.bands": "Who's talking on ham/business radio",
    "radio.aprs": "Ham radio position reports (144.39 MHz)",
    "mesh.nodes": "LoRa mesh radios nearby",
    "responder.analyze": "Listen for Windows name lookups (no replies)",
    "p0f.listen": "Guess device types from traffic (no sending)",
    "cleartext.find": "Find services that send passwords unencrypted",
    "ipv6.listen": "Watch for new IPv6 devices",
    "nuclei.scan": "Check {ip} against known-issue templates",
    "tls.scan": "Check encryption settings on {ip}",
    "web.content": "Find hidden web pages on {ip}",
    "smb.nxc": "Windows file sharing without a login on {ip}",
    "ldap.anon": "Read the Windows domain directory without a login on {ip}",
    "snmp.enum": "Read network-device info on {ip}",
    "exploit.lookup": "Look up public exploits for: {query}",
    "creds.default": "Try factory-default logins on {where} ({service})",
    "creds.web_defaults": "Try factory-default web-admin logins on {where}",
    "net.poison.responder": "Answer Windows name lookups on {network} (lab VLAN only)",
    "net.poison.mitm6": "Pose as the IPv6 router on {network} ({domain})",
    "wifi.rogue_ap": "Broadcast a copy of Wi-Fi network {ssid}",
}
# One plain-English sentence per action, shown under its button.
HELP = {
    "net.local": "Reads the box's own network ports and routes. Sends nothing.",
    "net.find": "Finds which addresses are in use on a network (address lookups or ping, no port checks).",
    "nmap.discovery": "Checks which addresses in the range answer, without looking at their services.",
    "nmap.services": "Finds open ports on the device and works out what program and version runs on each.",
    "nmap.vuln": "Runs nmap's checking scripts for known weaknesses. Some checks are intrusive; nothing is exploited.",
    "smb.enum": "Asks the Windows file-sharing service for its version, name and shares.",
    "web.scan": "Looks at the web server for outdated software and common misconfigurations.",
    "wired.listen": "Listens on the network cable to learn which devices are there. Sends nothing.",
    "kismet.scan": "Lists nearby Wi-Fi networks and the devices connected to them, just by listening.",
    "wifi.watch": "Follows one Wi-Fi network to see its clients and traffic levels. Listen-only.",
    "wifi.capture": "Waits for a device to log in to the Wi-Fi so the handshake is saved. Listen-only.",
    "wifi.capture_deauth": "Briefly disconnects clients so they log in again and the handshake is saved.",
    "wifi.deauth": "Sends disconnect messages to the network's clients. Only for your own Wi-Fi.",
    "ble.scan": "Lists Bluetooth Low Energy devices that are advertising nearby.",
    "ble.gatt": "Connects to the device and lists the data and settings it exposes. Doesn't change anything.",
    "sdr.survey": "Sweeps the radio spectrum and shows which frequencies are active.",
    "sdr.decode": "Decodes weather stations, tire sensors, door sensors and similar devices on that frequency.",
    "subghz.scan": "Listens for garage remotes, key fobs and other low-frequency devices and saves what it hears.",
    "subghz.replay": "Transmits a saved remote signal once. Only for remotes on your Known devices list.",
    "marauder.scan": "Surveys Wi-Fi with the ESP32 add-on board.",
    "marauder.deauth": "Sends disconnect messages from the ESP32 board. Only for your own Wi-Fi.",
    "air.adsb": "Shows aircraft broadcasting their position, received on the SDR.",
    "radio.bands": "Listens across ham, GMRS and business bands and lists which channels are busy.",
    "radio.aprs": "Decodes ham radio position and status reports on 144.39 MHz.",
    "mesh.nodes": "Lists Meshtastic LoRa radios your node has heard.",
    "responder.analyze": "Watches for Windows name lookups that could be abused. Doesn't answer them.",
    "p0f.listen": "Guesses operating systems from the traffic it sees. Sends nothing.",
    "cleartext.find": "Finds services like FTP, Telnet and plain HTTP logins that send passwords unencrypted.",
    "ipv6.listen": "Watches for devices announcing new IPv6 addresses.",
    "nuclei.scan": "Checks the device against a library of known-issue templates. Detection only.",
    "tls.scan": "Checks the encryption versions, ciphers and certificate the service offers.",
    "web.content": "Tries common page and folder names to find content that isn't linked.",
    "smb.nxc": "Checks what Windows file sharing reveals without a username or password.",
    "ldap.anon": "Reads basic Windows domain information that's open without logging in.",
    "snmp.enum": "Reads device details using the default 'public' community string.",
    "exploit.lookup": "Searches the local Exploit-DB copy for public exploits matching what you type. Looks only.",
    "creds.default": "Tries a short list of factory-default usernames and passwords, one at a time with a pause. "
                     "'common' covers SSH, FTP, Telnet, databases and VNC; Windows sharing (smb) and Remote "
                     "Desktop (rdp) only run when picked, because wrong guesses can lock Windows accounts. A range "
                     "first checks which services are open, then tries logins on each host it finds. Reports which "
                     "account works, never the password. Needs your approval.",
    "creds.web_defaults": "Tries factory-default logins on web admin pages (routers, printers, cameras) with "
                          "nmap's http-default-accounts script. Reports the account name only. Needs your approval.",
    "net.poison.responder": "Answers Windows name lookups to capture login hashes. Only on your isolated lab VLAN.",
    "net.poison.mitm6": "Pretends to be the IPv6 router to see Windows traffic. Only on your isolated lab VLAN.",
    "wifi.rogue_ap": "Broadcasts a lookalike of your own Wi-Fi network to see which devices try to join.",
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
    if spec.category == "auth.attempt" and tgt.get("ip") and tgt.get("network"):
        raise TaskError("give either one device (ip) or a range (network), not both")
    sk = step_kind(spec.name, tgt)
    try:
        fill = dict(tgt)
        fill.setdefault("where", tgt.get("ip") or tgt.get("network") or "")
        fill.setdefault("service", "ssh")
        label = LABELS.get(spec.name, spec.name).format(**fill)
        for key, fmt in LABEL_SUFFIX.items():
            if key in tgt:
                label += fmt.format(**tgt)
        if spec.name in ("wifi.deauth", "marauder.deauth") and "client" not in tgt:
            label += " (broadcast)"
    except (KeyError, IndexError):
        label = spec.name
    return {"id": new_id(), "category": spec.category, "tool": spec.name, "target": tgt,
            "mode": mode, "step_kind": sk, "label": label, "help": HELP.get(spec.name, ""), "suggested": bool(suggested),
            "source": source, "_rid": result_id, "_step": sk}


def task_digest(task: dict, argv: list[str] | None) -> str:
    blob = json.dumps({"tool": task.get("tool"), "category": task.get("category"),
                       "target": task.get("target") or {}, "mode": task.get("mode"),
                       "argv": argv}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()
