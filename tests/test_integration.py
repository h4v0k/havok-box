"""Cross-tool integration: every registered tool previews, gates and plans consistently."""
import json
import unittest

from havokbox.planner import plan
from havokbox.preview import argv_for
from havokbox.scope import Gate, Scope
from havokbox.tasks import make_task
from havokbox.tools.registry import default_registry

SCOPE = Scope({
    "networks": {"include": ["10.10.0.0/24"], "exclude": ["10.10.0.1/32"]},
    "wifi": {"ssids": ["LAB-NET"], "bssids": ["aa:bb:cc:dd:ee:ff"]},
    "rf": {"ble_addresses": ["c0:ff:ee:00:00:01"], "subghz_ids": ["gate_fob"],
           "tx_bands": [{"min_mhz": 433.05, "max_mhz": 434.79}]},
    "auto_allow": ["recon.passive"],
})
SAMPLE = {
    "ip": "10.10.0.50", "network": "10.10.0.0/24", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6,
    "client": "11:11:11:11:11:11", "addr": "c0:ff:ee:00:00:01", "id": "gate_fob",
    "freq_mhz": 433.92, "port": 80,
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
