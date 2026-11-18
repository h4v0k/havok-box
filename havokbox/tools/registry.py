"""The tool manifest: the single place that says which tools exist, what gate category each
runs under, and what typed params each takes. The orchestrator runs only what's declared here.
"""
from __future__ import annotations

from . import ToolSpec, air, ble, flipper, kali_recon, kali_test, kismet, marauder, nmap, sdr, wifi, wired


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
            build=lambda t, mode, scope, hw: [kismet.build_cmd(hw)],
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
        # ---- ADS-B / AIS (second dongle if configured; else shares the main SDR lane) ----
        ToolSpec(name="air.adsb", category="recon.passive", space="sdr2",
                 params={"seconds": {"type": "int", "min": 10, "max": 600}},
                 fn=air.adsb, build=lambda t, mode, scope, hw: air.build_adsb(t, mode, scope, hw)),
        ToolSpec(name="air.ais", category="recon.passive", space="sdr2",
                 params={"seconds": {"type": "int", "min": 10, "max": 600}},
                 fn=air.ais, build=lambda t, mode, scope, hw: air.build_ais(t, mode, scope, hw)),
    ]
    _add_kali_recon(specs)
    _add_kali_test(specs)
    for s in specs:
        s.binary = getattr(s, "binary", None)
    return {s.name: s for s in specs}


def _spec(binary, phase, **kw):
    s = ToolSpec(**kw)
    s.binary = binary
    s.phase = phase
    return s


def _add_kali_test(specs):
    """Kali Test pack — active, approval-gated, refused during wardrive/sentry/survey (passive_only).
    net.poison is bound by the gate to networks.poison_allowed (isolated lab VLAN); wifi.rogue_ap to
    the owner's own wifi.ssids. Capture stays on the box (count only); the box never cracks."""
    import havokbox.tools.kali_test as kt
    secs = {"seconds": {"type": "int", "min": 30, "max": 300, "default": 120}}
    specs += [
        _spec("hydra", "test", name="creds.default", category="auth.attempt", space="wired",
              params={"ip": {"type": "ip", "required": True},
                      "service": {"type": "choice", "choices": ["ssh", "ftp", "smb", "http"], "default": "ssh"}},
              fn=kt.creds_default, build=lambda t, m, sc, hw: kt.build_creds_default(t, m, sc, hw)),
        _spec(None, "test", name="net.poison.responder", category="net.poison", space="wired",
              params={"network": {"type": "cidr", "required": True}, **secs},
              fn=kt.net_poison_responder, build=lambda t, m, sc, hw: kt.build_net_poison_responder(t, m, sc, hw)),
        _spec(None, "test", name="net.poison.mitm6", category="net.poison", space="wired",
              params={"network": {"type": "cidr", "required": True},
                      "domain": {"type": "str", "required": True}, **secs},
              fn=kt.net_poison_mitm6, build=lambda t, m, sc, hw: kt.build_net_poison_mitm6(t, m, sc, hw)),
        _spec(None, "test", name="wifi.rogue_ap", category="wifi.rogue_ap", space="wifi",
              params={"ssid": {"type": "name", "required": True}, **secs},
              fn=kt.wifi_rogue_ap, build=lambda t, m, sc, hw: kt.build_wifi_rogue_ap(t, m, sc, hw)),
    ]


def _add_kali_recon(specs):
    """Kali Recon/Enumerate pack. Reachable from the Tools panel (manual_tool) and the planner;
    each hidden when its binary isn't installed (inventory)."""
    import havokbox.tools.kali_recon as kr
    ip = {"ip": {"type": "ip", "required": True}}
    def secs(n):
        return {"seconds": {"type": "int", "min": 10, "max": n}}
    specs += [
        _spec("responder", "recon", name="responder.analyze", category="recon.passive", space="wired",
              params=secs(600), fn=kr.responder_analyze,
              build=lambda t, m, sc, hw: kr.build_responder(t, m, sc, hw)),
        _spec("p0f", "recon", name="p0f.listen", category="recon.passive", space="wired",
              params=secs(600), fn=kr.p0f_listen, build=lambda t, m, sc, hw: kr.build_p0f(t, m, sc, hw)),
        _spec("tshark", "recon", name="cleartext.find", category="recon.passive", space="wired",
              params=secs(300), fn=kr.cleartext_find, build=lambda t, m, sc, hw: kr.build_cleartext(t, m, sc, hw)),
        _spec("detect-new-ip6", "recon", name="ipv6.listen", category="recon.passive", space="wired",
              params=secs(300), fn=kr.ipv6_listen, build=lambda t, m, sc, hw: kr.build_ipv6(t, m, sc, hw)),
        _spec("nuclei", "enumerate", name="nuclei.scan", category="recon.active", space="wired",
              params=ip, fn=kr.nuclei_scan, build=lambda t, m, sc, hw: kr.build_nuclei(t, m, sc, hw)),
        _spec("testssl.sh", "enumerate", name="tls.scan", category="recon.active", space="wired",
              params=ip, fn=kr.tls_scan, build=lambda t, m, sc, hw: kr.build_tls(t, m, sc, hw)),
        _spec("feroxbuster", "enumerate", name="web.content", category="recon.active", space="wired",
              params=ip, fn=kr.web_content, build=lambda t, m, sc, hw: kr.build_web_content(t, m, sc, hw)),
        _spec("netexec", "enumerate", name="smb.nxc", category="recon.active", space="wired",
              params=ip, fn=kr.smb_nxc, build=lambda t, m, sc, hw: kr.build_smb_nxc(t, m, sc, hw)),
        _spec("ldapsearch", "enumerate", name="ldap.anon", category="recon.active", space="wired",
              params=ip, fn=kr.ldap_anon, build=lambda t, m, sc, hw: kr.build_ldap(t, m, sc, hw)),
        _spec("onesixtyone", "enumerate", name="snmp.enum", category="recon.active", space="wired",
              params=ip, fn=kr.snmp_enum, build=lambda t, m, sc, hw: kr.build_snmp(t, m, sc, hw)),
        _spec("searchsploit", "report", name="exploit.lookup", category="recon.passive", space="report",
              params={"query": {"type": "name", "required": True}}, fn=kr.exploit_lookup,
              build=lambda t, m, sc, hw: kr.build_exploit_lookup(t, m, sc, hw)),
    ]
