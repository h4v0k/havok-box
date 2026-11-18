import unittest

from havokbox.preview import command_for
from tests.helpers import make


class AuthTest(unittest.TestCase):
    def test_token_required_and_constant_compare(self):
        h, store, *_ = make()
        self.assertTrue(h.authorized("Bearer s3cret"))
        for bad in (None, "", "s3cret", "Bearer nope", "Basic s3cret", "Bearer "):
            self.assertFalse(h.authorized(bad), bad)
        store.close()

    def test_empty_token_config_fails_closed(self):
        h, store, *_ = make(token="")
        self.assertFalse(h.authorized("Bearer "))
        self.assertFalse(h.authorized("Bearer anything"))
        store.close()


class FlowTest(unittest.TestCase):
    def setUp(self):
        self.h, self.store, self.runner, self.scope, _ = make()

    def tearDown(self):
        self.store.close()

    def drain_jobs(self):
        while self.h.jobs.run_one(timeout=0):
            pass

    def test_scan_is_queued_then_runs(self):
        code, r = self.h.scan({"space": "wired", "mode": "standard"})
        self.assertEqual((code, r["status"]), (202, "queued"))
        self.assertEqual(self.h.state()[1]["findings"], [])
        self.drain_jobs()
        st = self.h.state()[1]
        self.assertEqual(len(st["findings"]), 1)
        self.assertEqual(st["phase"], "enumerate")
        self.assertEqual(st["jobs"][0]["status"], "ok")
        self.assertIsNone(st["running"])

    def test_bad_inputs_rejected(self):
        self.assertEqual(self.h.scan({"space": "ble"})[0], 400)
        self.assertEqual(self.h.scan({"space": "wired", "mode": "loud"})[0], 400)
        self.assertEqual(self.h.scan(None)[0], 400)
        self.assertEqual(self.h.mode({"mode": "yolo"})[0], 400)
        self.assertEqual(self.h.approve({})[0], 400)
        self.assertEqual(self.h.approve({"task_id": 5})[0], 400)
        self.assertEqual(self.h.run({"task_id": "x" * 65})[0], 400)
        self.assertEqual(self.h.approve({"task_id": "nope"})[0], 404)
        self.assertEqual(self.h.run({"task_id": "nope"})[0], 404)
        self.assertEqual(self.h.jobs.q.qsize(), 0)

    def test_default_mode_is_stealth_and_toggle(self):
        self.assertEqual(self.h.state()[1]["mode"], "stealth")
        self.assertEqual(self.h.mode({"mode": "standard"})[0], 200)
        self.assertEqual(self.h.state()[1]["mode"], "standard")

    def _proposal(self):
        self.h.scan({"space": "wired", "mode": "standard"})
        self.drain_jobs()
        return self.h.state()[1]["proposals"][0]

    def test_preview_matches_the_command_that_runs(self):
        p = self._proposal()
        self.assertTrue(p["needs_approval"] and p["runnable"])
        self.assertEqual(p["mode"], "standard")
        self.h.mode({"mode": "stealth"})        # toggling later must not change a frozen proposal
        p2 = self.h.state()[1]["proposals"][0]
        self.assertEqual(p2["command"], p["command"])
        self.h.approve({"task_id": p["task_id"]})
        self.h.run({"task_id": p["task_id"]})
        self.drain_jobs()
        import shlex
        self.assertEqual(shlex.join(self.runner.cmds[-1]), p["command"])
        self.assertIn("-T4", p["command"])

    def test_run_without_approval_does_not_execute(self):
        p = self._proposal()
        before = len(self.runner.cmds)
        self.h.run({"task_id": p["task_id"]})
        self.drain_jobs()
        self.assertEqual(len(self.runner.cmds), before)
        self.assertEqual(self.h.state()[1]["jobs"][0]["status"], "awaiting_approval")

    def test_approval_is_one_shot(self):
        p = self._proposal()
        self.h.approve({"task_id": p["task_id"]})
        self.h.run({"task_id": p["task_id"]})
        self.drain_jobs()
        before = len(self.runner.cmds)
        # proposal is now executed, so a replay is not_found; even re-running the raw task needs a fresh approval
        self.assertEqual(self.h.run({"task_id": p["task_id"]})[0], 404)
        self.assertEqual(len(self.runner.cmds), before)

    def test_approve_logs_exact_command(self):
        p = self._proposal()
        self.h.approve({"task_id": p["task_id"]})
        ev = [e for e in self.store.evidence() if e["kind"] == "approved"]
        self.assertEqual(len(ev), 1)
        self.assertIn(p["command"], ev[0]["detail"])

    def test_unregistered_tool_proposal_is_not_runnable(self):
        self.h.scan({"space": "wifi"})
        self.drain_jobs()
        cap = [p for p in self.h.state()[1]["proposals"] if p["category"] == "wifi.deauth"]
        self.assertTrue(cap)
        self.assertFalse(cap[0]["runnable"])
        self.assertIsNone(cap[0]["command"])
        self.assertFalse(cap[0]["in_scope"])        # evil twin BSSID is not ours
        self.assertFalse(cap[0]["suggested"])       # never glow a step the gate will refuse
        self.assertEqual(self.h.state()[1]["phase"], "test")

    def test_state_has_no_counts_for_badges(self):
        st = self.h.state()[1]
        self.assertIsInstance(st["commander_pending"], bool)

    def test_finding_creates_commander_queue_digest_without_raw_output(self):
        self.h.scan({"space": "wifi"})
        self.drain_jobs()
        q = self.store.pending_queue()
        self.assertEqual(len(q), 1)
        self.assertNotIn("aps", q[0]["payload"])
        self.assertIn("evil_twins", q[0]["payload"])
        self.assertTrue(self.h.state()[1]["commander_pending"])

    def test_job_crash_is_contained(self):
        self.h.jobs.submit("boom", lambda: 1 / 0)
        self.drain_jobs()
        self.assertEqual(self.h.state()[1]["jobs"][0]["status"], "error")
        self.assertTrue(any(e["kind"] == "error" for e in self.store.evidence()))


class ReviewFixesTest(unittest.TestCase):
    def test_stealth_wired_refuses_instead_of_sweeping(self):
        h, store, runner, *_ = make()
        code, r = h.scan({"space": "wired", "mode": "stealth"})
        self.assertEqual((code, r["status"]), (409, "unavailable"))
        self.assertEqual(h.jobs.q.qsize(), 0)
        self.assertEqual(runner.cmds, [])
        store.close()

    def test_discovery_needing_approval_becomes_approvable_proposal(self):
        from tests.helpers import SCOPE
        import copy
        from havokbox.scope import Scope
        h, store, runner, *_ = make()
        sc = copy.deepcopy(SCOPE); sc["auto_allow"] = ["recon.passive"]   # the shipped example
        h.api.scope = Scope(sc); h.api.orch.scope = h.api.scope
        from havokbox.scope import Gate
        h.api.orch.gate = Gate(h.api.scope)
        h.scan({"space": "wired", "mode": "standard"})
        while h.jobs.run_one(timeout=0):
            pass
        self.assertEqual(h.state()[1]["jobs"][0]["status"], "needs_approval")
        p = h.state()[1]["proposals"][0]
        self.assertTrue(p["needs_approval"] and p["runnable"])
        self.assertIn("nmap -sn", p["command"])
        h.approve({"task_id": p["task_id"]}); h.run({"task_id": p["task_id"]})
        while h.jobs.run_one(timeout=0):
            pass
        self.assertEqual(len(h.state()[1]["findings"]), 1)
        store.close()

    def test_evidence_recent_is_bounded_newest_first(self):
        h, store, *_ = make()
        for i in range(80):
            store.log("x", str(i))
        ev = h.state()[1]["evidence"]
        self.assertEqual(len(ev), 50)
        self.assertEqual(ev[0]["detail"], "79")
        store.close()


class ConsoleTest(unittest.TestCase):
    def test_off_by_default(self):
        h, store, *_ = make()
        self.assertFalse(h.cfg.console_enabled)
        self.assertEqual(h.console("192.168.4.20", "box:8080")[0], 404)
        self.assertFalse(h.state()[1]["console_enabled"])
        store.close()

    def test_lan_only_and_logged(self):
        h, store, *_ = make(console_enabled=True)
        self.assertEqual(h.console("192.168.4.20", "box")[0], 503)   # no console password set
        h.cfg.console_password = "pw"
        self.assertEqual(h.console("10.0.0.9", "box")[0], 403)
        self.assertEqual(h.console(None, "box")[0], 403)
        code, r = h.console("192.168.4.20", "evil.example:8080")
        self.assertEqual(code, 200)
        self.assertEqual(r["url"], "http://192.168.4.1:7681/")   # configured, never the Host header
        kinds = [e["kind"] for e in store.evidence()]
        self.assertIn("refused", kinds)
        self.assertIn("console", kinds)
        store.close()


class PreviewTest(unittest.TestCase):
    def test_unknown_or_bad_target(self):
        _, store, _, scope, _ = make()
        self.assertIsNone(command_for({"tool": "nope"}, scope))
        self.assertIsNone(command_for({"tool": "nmap.services", "target": {}}, scope))
        self.assertIn("--exclude 10.10.0.1", command_for(
            {"tool": "nmap.discovery", "target": {"network": "10.10.0.0/24"}}, scope))
        store.close()


if __name__ == "__main__":
    unittest.main()
