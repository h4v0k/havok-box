"""The tool manifest: the single place that says which tools exist, what gate category each
runs under, and what typed params each takes. The orchestrator runs only what's declared here.
"""
from __future__ import annotations

from . import ToolSpec, ble, flipper, kismet, marauder, nmap, sdr, wifi, wired


def default_registry() -> dict[str, ToolSpec]:
    specs = [
        ToolSpec(
            name="nmap.discovery",
            category="recon.discovery",
            params={"network": {"type": "cidr", "required": True}},
            fn=nmap.discovery,
            space="wired",
            build=lambda t, mode, scope, hw: [nmap.build_discovery_cmd(
                t["network"], [str(e) for e in scope.exclude])],
        ),
        ToolSpec(
            name="nmap.services",
            category="recon.active",
            params={"ip": {"type": "ip", "required": True}},
            fn=nmap.services,
            space="wired",
            build=lambda t, mode, scope, hw: [nmap.build_services_cmd(t["ip"], mode)],
        ),
        ToolSpec(
            name="kismet.scan",
            category="recon.passive",
            params={},
            fn=kismet.scan,
            space="wifi",
            build=lambda t, mode, scope, hw: [list(kismet.KISMET_CMD)],
        ),
        # ---- wired -------------------------------------------------------
        ToolSpec(name="wired.listen", category="recon.passive", space="wired",
                 params={"seconds": {"type": "int", "min": 10, "max": 600}},
                 fn=wired.listen, build=lambda t, mode, scope, hw: wired.build_listen(t, mode, scope, hw)),
        ToolSpec(name="nmap.vuln", category="recon.active", space="wired",
                 params={"ip": {"type": "ip", "required": True}},
                 fn=wired.vuln, build=lambda t, mode, scope, hw: wired.build_vuln(t, mode, scope, hw)),
        ToolSpec(name="smb.enum", category="recon.active", space="wired",
                 params={"ip": {"type": "ip", "required": True}},
                 fn=wired.smb_enum, build=lambda t, mode, scope, hw: wired.build_smb(t, mode, scope, hw)),
        ToolSpec(name="web.scan", category="recon.active", space="wired",
                 params={"ip": {"type": "ip", "required": True},
                         "port": {"type": "int", "min": 1, "max": 65535}},
                 fn=wired.web_scan, build=lambda t, mode, scope, hw: wired.build_web(t, mode, scope, hw)),
        # ---- Wi-Fi (Alfa) ------------------------------------------------
        ToolSpec(name="wifi.watch", category="recon.passive", space="wifi",
                 params={"bssid": {"type": "bssid", "required": True},
                         "channel": {"type": "int", "min": 1, "max": 196, "required": True},
                         "seconds": {"type": "int", "min": 10, "max": 600}},
                 fn=wifi.watch, build=lambda t, mode, scope, hw: wifi.build_watch(t, mode, scope, hw)),
        ToolSpec(name="wifi.capture", category="wifi.capture", space="wifi",
                 params={"bssid": {"type": "bssid", "required": True},
                         "channel": {"type": "int", "min": 1, "max": 196, "required": True},
                         "seconds": {"type": "int", "min": 30, "max": 600}},
                 fn=wifi.capture, build=lambda t, mode, scope, hw: wifi.build_capture(t, mode, scope, hw)),
        ToolSpec(name="wifi.capture_deauth", category="wifi.deauth", space="wifi",
                 params={"bssid": {"type": "bssid", "required": True},
                         "channel": {"type": "int", "min": 1, "max": 196, "required": True},
                         "client": {"type": "mac"},
                         "count": {"type": "int", "min": 1, "max": 10},
                         "seconds": {"type": "int", "min": 30, "max": 300}},
                 fn=wifi.capture_deauth, build=lambda t, mode, scope, hw: wifi.build_capture_deauth(t, mode, scope, hw)),
        ToolSpec(name="wifi.deauth", category="wifi.deauth", space="wifi",
                 params={"bssid": {"type": "bssid", "required": True},
                         "channel": {"type": "int", "min": 1, "max": 196, "required": True},
                         "client": {"type": "mac"},
                         "count": {"type": "int", "min": 1, "max": 64}},
                 fn=wifi.deauth, build=lambda t, mode, scope, hw: wifi.build_deauth(t, mode, scope, hw)),
        # ---- BLE ---------------------------------------------------------
        ToolSpec(name="ble.scan", category="recon.passive", space="ble",
                 params={"seconds": {"type": "int", "min": 10, "max": 300}},
                 fn=ble.scan, build=lambda t, mode, scope, hw: ble.build_scan(t, mode, scope, hw)),
        ToolSpec(name="ble.gatt", category="ble.active", space="ble",
                 params={"addr": {"type": "mac", "required": True},
                         "addr_type": {"type": "choice", "choices": ["public", "random"]}},
                 fn=ble.gatt, build=lambda t, mode, scope, hw: ble.build_gatt(t, mode, scope, hw)),
        # ---- RTL-SDR -----------------------------------------------------
        ToolSpec(name="sdr.survey", category="recon.passive", space="sdr",
                 params={"start_mhz": {"type": "number", "min": 24, "max": 1766},
                         "end_mhz": {"type": "number", "min": 24, "max": 1766},
                         "seconds": {"type": "int", "min": 10, "max": 600}},
                 fn=sdr.survey, build=lambda t, mode, scope, hw: sdr.build_survey(t, mode, scope, hw)),
        ToolSpec(name="sdr.decode", category="recon.passive", space="sdr",
                 params={"freq": {"type": "choice", "choices": ["315M", "433.92M", "915M"]},
                         "seconds": {"type": "int", "min": 10, "max": 600}},
                 fn=sdr.decode, build=lambda t, mode, scope, hw: sdr.build_decode(t, mode, scope, hw)),
        # ---- Flipper sub-GHz --------------------------------------------
        ToolSpec(name="subghz.scan", category="recon.passive", space="subghz",
                 params={"freq_mhz": {"type": "number", "min": 300, "max": 928},
                         "seconds": {"type": "int", "min": 5, "max": 300}},
                 fn=flipper.scan, build=lambda t, mode, scope, hw: flipper.build_scan(t, mode, scope, hw)),
        ToolSpec(name="subghz.replay", category="rf.replay", space="subghz",
                 params={"id": {"type": "name", "required": True},
                         "freq_mhz": {"type": "number", "min": 300, "max": 928, "required": True}},
                 fn=flipper.replay, build=lambda t, mode, scope, hw: flipper.build_replay(t, mode, scope, hw)),
        # ---- Marauder (ESP32) -------------------------------------------
        ToolSpec(name="marauder.scan", category="recon.passive", space="esp",
                 params={"seconds": {"type": "int", "min": 5, "max": 120}},
                 fn=marauder.scan, build=lambda t, mode, scope, hw: marauder.build_scan(t, mode, scope, hw)),
        ToolSpec(name="marauder.deauth", category="wifi.deauth", space="esp",
                 params={"bssid": {"type": "bssid", "required": True},
                         "channel": {"type": "int", "min": 1, "max": 14, "required": True},
                         "client": {"type": "mac"},
                         "seconds": {"type": "int", "min": 5, "max": 60}},
                 fn=marauder.deauth, build=lambda t, mode, scope, hw: marauder.build_deauth(t, mode, scope, hw)),
    ]
    return {s.name: s for s in specs}
