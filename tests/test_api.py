import json
import unittest

from havokbox.api import Api
from havokbox.orchestrator import Orchestrator
from havokbox.scope import Scope
from havokbox.store import Store
from havokbox.tools.registry import default_registry

DISCOVERY_XML = '<nmaprun><host><status state="up"/><address addr="10.10.0.50" addrtype="ipv4"/></host></nmaprun>'
SERVICES_XML = ('<nmaprun><host><address addr="10.10.0.50" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
                '</ports></host></nmaprun>')
DEVICES = json.dumps([
    {"type": "AP", "ssid": "LAB-NET", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6},
    {"type": "AP", "ssid": "LAB-NET", "bssid": "11:22:33:44:55:66", "channel": 6},
])

SCOPE = {
    "name": "lab",
    "networks": {"include": ["10.10.0.0/24"], "exclude": ["10.10.0.1/32"]},
    "wifi": {"ssids": ["LAB-NET"], "bssids": ["aa:bb:cc:dd:ee:ff"]},
    "auto_allow": ["recon.passive", "recon.discovery"],
    "approval_required": ["recon.active", "wifi.deauth"],
}


def runner(cmd):
    if cmd[0] == "curl":
        return DEVICES
    return DISCOVERY_XML if "-sn" in cmd else SERVICES_XML


class ApiTest(unittest.TestCase):
    def setUp(self):
        scope = Scope(SCOPE)
        self.store = Store(":memory:")
        self.api = Api(scope, self.store, Orchestrator(scope, self.store, default_registry(), runner))

    def tearDown(self):
        self.store.close()

    def test_wired_scan_creates_finding_and_proposal(self):
        r = self.api.scan("wired", "standard")
        self.assertEqual(r["status"], "ok")
        st = self.api.state()
        self.assertEqual(len(st["findings"]), 1)
        self.assertEqual(len(st["proposals"]), 1)
        self.assertTrue(st["proposals"][0]["needs_approval"])

    def test_run_without_approval_awaits(self):
        self.api.scan("wired", "standard")
        tid = self.api.state()["proposals"][0]["task_id"]
        self.assertEqual(self.api.run(tid)["status"], "awaiting_approval")
        self.assertEqual(len(self.api.state()["findings"]), 1)  # services did not run

    def test_approve_then_run_executes(self):
        self.api.scan("wired", "standard")
        p = self.api.state()["proposals"][0]
        tid = p["task_id"]
        self.assertEqual(self.api.approve(tid, "wrong")["status"], "stale")
        self.assertEqual(self.api.approve(tid, p["digest"])["status"], "granted")
        self.assertEqual(self.api.run(tid)["status"], "ok")
        kinds = {f["kind"] for f in self.api.state()["findings"]}
        self.assertEqual(kinds, {"hosts", "services"})

    def test_wifi_scan_flags_evil_twin_without_dead_capture_button(self):
        r = self.api.scan("wifi")
        self.assertEqual(r["status"], "ok")
        st = self.api.state()
        survey = [f for f in st["findings"] if f["kind"] == "wifi_survey"][0]
        self.assertEqual(len(survey["data"]["evil_twins"]), 1)
        # the capture tool isn't registered yet, so no dead button is proposed (design: no orphans)
        self.assertFalse(any(p["category"] == "wifi.deauth" for p in st["proposals"]))


if __name__ == "__main__":
    unittest.main()
