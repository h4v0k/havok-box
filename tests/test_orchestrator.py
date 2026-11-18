import unittest

from havokbox.orchestrator import Orchestrator
from havokbox.scope import Scope
from havokbox.store import Store
from havokbox.tools.registry import default_registry

DISCOVERY_XML = '<nmaprun><host><status state="up"/><address addr="10.10.0.50" addrtype="ipv4"/></host></nmaprun>'
SERVICES_XML = ('<nmaprun><host><address addr="10.10.0.50" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
                '</ports></host></nmaprun>')

SCOPE = {
    "name": "lab",
    "networks": {"include": ["10.10.0.0/24"], "exclude": ["10.10.0.1/32"]},
    "auto_allow": ["recon.passive", "recon.discovery"],
    "approval_required": ["recon.active"],
}


def runner(cmd):
    return DISCOVERY_XML if "-sn" in cmd else SERVICES_XML


class OrchestratorTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.orch = Orchestrator(Scope(SCOPE), self.store, default_registry(), runner)

    def tearDown(self):
        self.store.close()

    def test_category_tool_mismatch_refused(self):
        # tool nmap.services is recon.active; a task claiming recon.passive must be refused
        r = self.orch.execute({
            "id": "m1", "category": "recon.passive", "tool": "nmap.services",
            "target": {"ip": "10.10.0.50"},
        })
        self.assertEqual(r["status"], "refused")
        self.assertEqual(self.store.findings(), [])

    def test_out_of_scope_discovery_refused(self):
        r = self.orch.execute({
            "id": "t1", "category": "recon.discovery", "tool": "nmap.discovery",
            "target": {"network": "192.168.99.0/24"},
        })
        self.assertEqual(r["status"], "refused")
        self.assertEqual(self.store.findings(), [])

    def test_in_scope_discovery_auto_runs(self):
        r = self.orch.execute({
            "id": "t2", "category": "recon.discovery", "tool": "nmap.discovery",
            "target": {"network": "10.10.0.0/24"}, "mode": "standard",
        })
        self.assertEqual(r["status"], "ok")
        self.assertEqual(len(self.store.findings()), 1)

    def test_active_awaits_then_runs_after_approval(self):
        task = {"id": "t3", "category": "recon.active", "tool": "nmap.services",
                "target": {"ip": "10.10.0.50"}, "mode": "stealth"}
        self.assertEqual(self.orch.execute(task)["status"], "awaiting_approval")
        self.assertEqual(self.store.findings(), [])        # nothing ran
        self.store.grant_approval("t3", "recon.active", {"ip": "10.10.0.50"})
        self.assertEqual(self.orch.execute(task)["status"], "ok")
        self.assertEqual(len(self.store.findings()), 1)

    def test_approval_not_reusable_by_second_task(self):
        self.store.grant_approval("t4", "recon.active", {"ip": "10.10.0.50"})
        a = {"id": "t4", "category": "recon.active", "tool": "nmap.services", "target": {"ip": "10.10.0.50"}}
        b = {"id": "t5", "category": "recon.active", "tool": "nmap.services", "target": {"ip": "10.10.0.50"}}
        self.assertEqual(self.orch.execute(a)["status"], "ok")               # consumes t4
        self.assertEqual(self.orch.execute(b)["status"], "awaiting_approval")  # b has none
        self.assertEqual(self.orch.execute(a)["status"], "awaiting_approval")  # t4 already consumed


if __name__ == "__main__":
    unittest.main()
