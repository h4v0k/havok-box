import unittest

from havokbox.store import Store


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def tearDown(self):
        self.s.close()

    def test_finding_idempotent(self):
        self.assertTrue(self.s.add_finding("r1", "wired", "hosts", "2 up", {}, "stealth"))
        self.assertFalse(self.s.add_finding("r1", "wired", "hosts", "2 up", {}, "stealth"))
        self.assertEqual(len(self.s.findings()), 1)

    def test_proposal_idempotent(self):
        self.assertTrue(self.s.add_proposal("r1", "scan_services", {"x": 1}))
        self.assertFalse(self.s.add_proposal("r1", "scan_services", {"x": 1}))
        self.assertEqual(len(self.s.proposals()), 1)

    def test_approval_one_shot(self):
        self.s.grant_approval("t1", "wifi.deauth", {"bssid": "aa"})
        self.assertTrue(self.s.consume_approval("t1"))
        self.assertFalse(self.s.consume_approval("t1"))  # already consumed

    def test_consume_without_grant_fails(self):
        self.assertFalse(self.s.consume_approval("nope"))

    def test_void_unconsumed_only(self):
        self.s.grant_approval("t1", "wifi.deauth", {})
        self.s.grant_approval("t2", "wifi.deauth", {})
        self.assertTrue(self.s.consume_approval("t1"))
        self.assertEqual(self.s.void_unconsumed_approvals(), 1)  # only t2 voided
        self.assertFalse(self.s.consume_approval("t2"))  # gone

    def test_drain_idempotent_on_retry(self):
        self.s.enqueue("r1", "analysis", {"finding": "r1"})
        q = self.s.pending_queue()[0]
        self.s.drain(q["id"], "r1", "scan_services", {"tool": "nmap.services"})
        self.s.drain(q["id"], "r1", "scan_services", {"tool": "nmap.services"})  # retry
        self.assertEqual(len(self.s.proposals()), 1)      # no double-apply
        self.assertEqual(self.s.pending_queue(), [])      # marked done


if __name__ == "__main__":
    unittest.main()
