"""Cross-tool integration: every registered tool previews, gates and plans consistently."""
import json
import unittest

from havokbox.planner import plan
from havokbox.preview import argv_for
from havokbox.scope import Gate, Scope
from havokbox.tasks import make_task
from havokbox.tools.registry import default_registry

SCOPE = Scope({
    "networks": {"include": ["10.10.0.0/24"], "exclude": ["10.10.0.1/32"],
                 "poison_allowed": ["10.10.0.0/24"]},   # test scope: overlap so one sample fits both
    "wifi": {"ssids": ["LAB-NET"], "bssids": ["aa:bb:cc:dd:ee:ff"]},
    "domains": ["lab.local"],
    "rf": {"ble_addresses": ["c0:ff:ee:00:00:01"], "subghz_ids": ["gate_fob"],
           "tx_bands": [{"min_mhz": 433.05, "max_mhz": 434.79}]},
    "auto_allow": ["recon.passive"],
})
SAMPLE = {
    "ip": "10.10.0.50", "network": "10.10.0.0/24", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6,
    "client": "11:11:11:11:11:11", "addr": "c0:ff:ee:00:00:01", "id": "gate_fob",
    "freq_mhz": 433.92, "port": 80, "query": "apache", "domain": "lab.local",
    "ssid": "LAB-NET", "service": "ssh",
}
SHELLS = {"sh", "bash", "/bin/sh", "/bin/bash", "zsh"}


def sample_target(spec):
    return {k: SAMPLE[k] for k, m in spec.params.items() if m.get("required")}


class RegistryIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.reg = default_registry()

    def test_every_tool_previews_with_defaults_and_no_shell(self):
        for name, spec in self.reg.items():
            for mode in ("stealth", "standard"):
                t = make_task(self.reg, name, sample_target(spec), mode, "r")
                steps = argv_for(t, SCOPE, self.reg)
                self.assertTrue(steps, f"{name}/{mode} has no preview")
                for argv in steps:
                    self.assertTrue(all(isinstance(a, str) for a in argv), f"{name}: non-str argv")
                    self.assertNotIn(argv[0], SHELLS, f"{name} runs a shell")
                    self.assertNotIn("-c", argv[:2], f"{name} looks like sh -c")
                # deterministic: same task -> same argv (the approval digest depends on it)
                self.assertEqual(steps, argv_for(t, SCOPE, self.reg))

    def test_gate_categories_are_known_and_scoped(self):
        g = Gate(SCOPE)
        for name, spec in self.reg.items():
            d = g.evaluate(make_task(self.reg, name, sample_target(spec), "stealth", "r"))
            self.assertTrue(d.allowed, f"{name}: {d.reason}")
            self.assertEqual(d.needs_approval, spec.category != "recon.passive", name)

    def test_active_tools_refuse_out_of_scope_targets(self):
        g = Gate(SCOPE)
        bad = {"ip": "8.8.8.8", "bssid": "de:ad:be:ef:00:00", "addr": "de:ad:be:ef:00:01",
               "ssid": "xfinitywifi", "domain": "evil.example", "network": "8.8.8.0/24",
               "id": "someone_elses", "network": "8.8.8.0/24"}
        for name, spec in self.reg.items():
            if spec.category == "recon.passive":
                continue
            tgt = sample_target(spec)
            for k in tgt:
                if k in bad:
                    tgt[k] = bad[k]
            self.assertFalse(g.evaluate(make_task(self.reg, name, tgt, "stealth", "r")).allowed, name)

    def test_replay_refused_outside_tx_band(self):
        t = make_task(self.reg, "subghz.replay", {"id": "gate_fob", "freq_mhz": 315.0}, "stealth", "r")
        self.assertFalse(Gate(SCOPE).evaluate(t).allowed)

    def test_every_planner_tool_is_registered(self):
        import inspect, re
        from havokbox import planner
        for tool in set(re.findall(r'_p\("([a-z_.]+)"', inspect.getsource(planner))):
            self.assertIn(tool, self.reg)


class PlannerFlowTest(unittest.TestCase):
    def tools(self, finding, mode="stealth"):
        return [(p["tool"], json.dumps(p["target"], sort_keys=True)) for p in plan([finding], SCOPE, mode)]

    def test_ap_watch_in_scope_proposes_capture_by_mode(self):
        f = {"kind": "ap_watch", "data": {"bssid": "AA:BB:CC:DD:EE:FF", "channel": 6,
                                          "clients": [{"mac": "11:11:11:11:11:11"}]}}
        stealth = {t for t, _ in self.tools(f, "stealth")}
        standard = {t for t, _ in self.tools(f, "standard")}
        self.assertIn("wifi.capture", stealth)
        self.assertNotIn("wifi.capture_deauth", stealth)
        self.assertIn("wifi.capture_deauth", standard)
        self.assertIn("wifi.deauth", stealth)

    def test_out_of_scope_ap_gets_no_test_steps(self):
        f = {"kind": "ap_watch", "data": {"bssid": "de:ad:be:ef:00:00", "channel": 6, "clients": []}}
        self.assertEqual(self.tools(f), [])

    def test_passive_hosts_only_in_scope(self):
        f = {"kind": "hosts", "data": {"hosts": [{"ip": "10.10.0.50"}, {"ip": "10.10.0.1"},
                                                 {"ip": "192.168.9.9"}]}}
        self.assertEqual([t for t, _ in self.tools(f)], ["nmap.services"])

    def test_services_lead_to_smb_web_vuln(self):
        f = {"kind": "services", "data": {"ip": "10.10.0.50", "services": [
            {"ip": "10.10.0.50", "port": 445, "service": "microsoft-ds"},
            {"ip": "10.10.0.50", "port": 8080, "service": "http-proxy"}]}}
        self.assertEqual({t for t, _ in self.tools(f)}, {"smb.enum", "web.scan", "nmap.vuln"})

    def test_ble_and_subghz_only_scoped_targets(self):
        ble = {"kind": "ble_devices", "data": {"devices": [{"addr": "C0:FF:EE:00:00:01"},
                                                           {"addr": "de:ad:be:ef:00:01"}]}}
        self.assertEqual(len(self.tools(ble)), 1)
        sub = {"kind": "subghz", "data": {"captures": [{"id": "gate_fob", "freq_mhz": 433.92},
                                                       {"id": "neighbor", "freq_mhz": 433.92}]}}
        self.assertEqual([t for t, _ in self.tools(sub)], ["subghz.replay"])


if __name__ == "__main__":
    unittest.main()


class ReviewFixTest(unittest.TestCase):
    def test_whatweb_never_follows_redirects(self):
        from havokbox.tools import wired
        for mode in ("stealth", "standard"):
            argv = wired.build_web({"ip": "10.10.0.50", "port": 80}, mode, SCOPE, {})[0]
            self.assertIn("--follow-redirect=never", argv)
            self.assertIn("-q", argv)

    def test_nmap_vuln_has_host_timeout(self):
        from havokbox.tools import wired
        for mode in ("stealth", "standard"):
            self.assertIn("--host-timeout", wired.build_vuln({"ip": "10.10.0.50"}, mode, SCOPE, {})[0])

    def test_capture_deauth_kills_airodump_when_aireplay_fails(self):
        import tempfile
        from havokbox.helpers import wifi_capture

        class P:
            terminated = False
            def terminate(self): P.terminated = True
            def wait(self, timeout=None): return 0
            def kill(self): pass

        def boom(argv, timeout):
            raise FileNotFoundError("aireplay-ng")
        with self.assertRaises(FileNotFoundError):
            wifi_capture.do_capture_deauth("wlan1mon", "aa:bb:cc:dd:ee:ff", 6, 30, tempfile.mkdtemp(),
                                           popen=lambda a: P(), runner=boom, sleep=lambda s: None)
        self.assertTrue(P.terminated)

    def test_pmkid_counts_as_captured(self):
        from havokbox.helpers import wifi_capture
        ok, n = wifi_capture._verify_capture("x", runner=lambda a, t: "WPA (0 handshake, with PMKID)")
        self.assertTrue(ok)

    def test_aireplay_sending_lines_counted(self):
        from havokbox.tools import wifi
        out = ("12:00:01  Sending 64 directed DeAuth (code 7). STMAC: [11:11:11:11:11:11] [ 0| 0 ACKs]\n"
               "12:00:02  Sending 64 directed DeAuth (code 7). STMAC: [11:11:11:11:11:11] [ 1| 0 ACKs]\n")
        self.assertEqual(wifi.parse_deauth_sent(out), 128)

    def test_marauder_selected_line_parses(self):
        from havokbox.helpers import marauder
        aps = marauder.parse_ap_list("[0][CH:6] LAB-NET -48 (selected)\n[1][CH:11] Other -70")
        self.assertEqual(len(aps), 2)

    def test_ap_watch_proposes_esp_deauth_on_24ghz(self):
        f = {"kind": "ap_watch", "data": {"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "clients": []}}
        self.assertIn("marauder.deauth", {p["tool"] for p in plan([f], SCOPE, "stealth")})
        f["data"]["channel"] = 36
        self.assertNotIn("marauder.deauth", {p["tool"] for p in plan([f], SCOPE, "stealth")})

    def test_subghz_ids_case_insensitive(self):
        sc = Scope({"rf": {"subghz_ids": ["Gate_Fob"], "tx_bands": [{"min_mhz": 433, "max_mhz": 435}]},
                    "auto_allow": ["recon.passive"]})
        f = {"kind": "subghz", "data": {"captures": [{"id": "Gate_Fob", "freq_mhz": 433.92}]}}
        steps = plan([f], sc)
        self.assertEqual(len(steps), 1)
        reg = default_registry()
        t = make_task(reg, "subghz.replay", steps[0]["target"], "stealth", "r")
        self.assertTrue(Gate(sc).evaluate(t).allowed)

    def test_ble_rssi_from_sniffle_field(self):
        from havokbox.helpers import ble_scan
        devs = ble_scan.parse_tshark_fields("c0:ff:ee:00:00:01\tLock\t-52\t\nc0:ff:ee:00:00:02\t\t\t-70\n")
        self.assertEqual(devs[0]["rssi"], -52)
        self.assertEqual(devs[1]["rssi"], -70)

    def test_flipper_key_on_next_line_attached(self):
        from havokbox.helpers import flipper
        recs = flipper.parse_received("Princeton 24bit\nKey:0x00ABCD\n")
        self.assertEqual(recs[0]["key"], "0x00ABCD")

    def test_kismet_raw_rest_shape(self):
        from havokbox.tools import kismet
        raw = [{"kismet.device.base.type": "Wi-Fi AP", "kismet.device.base.macaddr": "AA:BB:CC:DD:EE:FF",
                "kismet.device.base.commonname": "LAB-NET", "kismet.device.base.channel": "6",
                "kismet.device.base.signal": {"kismet.common.signal.last_signal": -40}},
               {"kismet.device.base.type": "Wi-Fi Client", "kismet.device.base.macaddr": "11:11:11:11:11:11"}]
        aps, clients = kismet.parse_devices(raw)
        self.assertEqual(aps[0]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(aps[0]["signal"], -40)
        self.assertEqual(len(clients), 1)
