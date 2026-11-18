import copy
import json
import os
import shlex
import tempfile
import unittest

from havokbox.preview import command_for
from havokbox.scope import Gate, Scope
from tests.helpers import SCOPE, make


def drain(h):
    while h.jobs.run_one():
        pass


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
        self.h, self.store, self.runner, self.scope, self.reg = make()

    def tearDown(self):
        self.store.close()

    def _proposal(self):
        self.h.scan({"space": "wired", "mode": "standard"})
        drain(self.h)
        return self.h.state()[1]["proposals"][0]

    def _approve_run(self, p):
        self.assertEqual(self.h.approve({"task_id": p["task_id"], "digest": p["digest"]})[0], 200)
        self.assertEqual(self.h.run({"task_id": p["task_id"]})[0], 202)
        drain(self.h)

    def test_scan_is_queued_on_its_lane_then_runs(self):
        code, r = self.h.scan({"space": "wired", "mode": "standard"})
        self.assertEqual((code, r["status"]), (202, "queued"))
        self.assertEqual(self.h.state()[1]["findings"], [])
        self.assertEqual(self.h.job(r["job_id"])[1]["lane"], "wired")
        drain(self.h)
        st = self.h.state()[1]
        self.assertEqual(len(st["findings"]), 1)
        self.assertEqual(st["phase"], "enumerate")
        self.assertEqual(self.h.job(r["job_id"])[1]["status"], "ok")
        self.assertEqual(st["running"], [])
        self.assertEqual(self.h.job("nope")[0], 404)

    def test_scan_mode_is_bound_in_the_request(self):
        self.h.scan({"space": "wired", "mode": "standard"})
        self.h.mode({"mode": "stealth"})          # flip before the job runs
        drain(self.h)
        self.assertEqual(self.h.state()[1]["findings"][0]["mode"], "standard")

    def test_bad_inputs_rejected(self):
        self.assertEqual(self.h.scan({"space": "ble"})[0], 400)
        self.assertEqual(self.h.scan({"space": "wired", "mode": "loud"})[0], 400)
        self.assertEqual(self.h.scan(None)[0], 400)
        self.assertEqual(self.h.mode({"mode": "yolo"})[0], 400)
        self.assertEqual(self.h.approve({"task_id": "x"})[0], 400)            # digest required
        self.assertEqual(self.h.approve({"task_id": 5, "digest": "d"})[0], 400)
        self.assertEqual(self.h.run({"task_id": "x" * 65})[0], 400)
        self.assertEqual(self.h.approve({"task_id": "nope", "digest": "d"})[0], 404)
        self.assertEqual(self.h.run({"task_id": "nope"})[0], 404)
        self.assertEqual(self.h.jobs.pending(), 0)

    def test_default_mode_is_stealth_and_toggle(self):
        self.assertEqual(self.h.state()[1]["mode"], "stealth")
        self.assertEqual(self.h.mode({"mode": "standard"})[0], 200)
        self.assertEqual(self.h.state()[1]["mode"], "standard")

    def test_preview_matches_the_command_that_runs(self):
        p = self._proposal()
        self.assertTrue(p["needs_approval"] and p["runnable"])
        self.assertEqual(p["mode"], "standard")
        self.h.mode({"mode": "stealth"})          # toggling later must not change a frozen proposal
        self.assertEqual(self.h.state()[1]["proposals"][0]["command"], p["command"])
        self._approve_run(p)
        self.assertEqual(shlex.join(self.runner.cmds[-1]), p["command"])

    def test_run_without_approval_is_409_and_nothing_queued(self):
        p = self._proposal()
        before = len(self.runner.cmds)
        code, r = self.h.run({"task_id": p["task_id"]})
        self.assertEqual((code, r["reason"]), (409, "approve first"))
        self.assertEqual(self.h.jobs.pending(), 0)
        self.assertEqual(len(self.runner.cmds), before)

    def test_approve_refuses_a_stale_digest(self):
        p = self._proposal()
        code, r = self.h.approve({"task_id": p["task_id"], "digest": "0" * 64})
        self.assertEqual((code, r["status"]), (409, "stale"))
        self.assertEqual(self.h.run({"task_id": p["task_id"]})[0], 409)

    def test_approval_voided_if_command_changes_before_run(self):
        p = self._proposal()
        self.h.approve({"task_id": p["task_id"], "digest": p["digest"]})
        # the scope changes under an open approval (e.g. a new exclude) -> preview argv changes
        sc = copy.deepcopy(SCOPE); sc["networks"]["exclude"].append("10.10.0.2/32")
        # services argv doesn't use excludes, so change the mode in the stored task instead
        row = self.store.proposals()[0]
        t = json.loads(row["task"]); t["mode"] = "stealth"
        self.store.cx.execute("UPDATE proposals SET task=? WHERE id=?", (json.dumps(t), row["id"]))
        self.assertEqual(self.h.run({"task_id": p["task_id"]})[0], 409)
        before = len(self.runner.cmds)
        self.assertEqual(self.h.api.run(p["task_id"])["status"], "refused")
        self.assertEqual(len(self.runner.cmds), before)
        self.assertIsNone(self.store.open_approval(p["task_id"]))

    def test_approval_is_one_shot(self):
        p = self._proposal()
        self._approve_run(p)
        before = len(self.runner.cmds)
        self.assertEqual(self.h.run({"task_id": p["task_id"]})[0], 404)   # executed, gone
        self.assertEqual(len(self.runner.cmds), before)

    def test_reapprove_after_failed_run_gets_a_fresh_approval(self):
        p = self._proposal()
        self.h.approve({"task_id": p["task_id"], "digest": p["digest"]})
        self.runner.fail = True                   # tool crashes after consuming the approval
        self.h.run({"task_id": p["task_id"]}); drain(self.h)
        self.runner.fail = False
        self.assertIsNone(self.store.open_approval(p["task_id"]))
        self.assertEqual(self.h.approve({"task_id": p["task_id"], "digest": p["digest"]})[0], 200)
        self.assertIsNotNone(self.store.open_approval(p["task_id"]))
        self.assertEqual(self.h.run({"task_id": p["task_id"]})[0], 202)
        self.assertTrue(any("re-approval" in e["detail"] for e in self.store.evidence()))

    def test_approve_logs_exact_command(self):
        p = self._proposal()
        self.h.approve({"task_id": p["task_id"], "digest": p["digest"]})
        ev = [e for e in self.store.evidence() if e["kind"] == "approved"]
        self.assertEqual(len(ev), 1)
        self.assertIn(p["command"], ev[0]["detail"])

    def test_unregistered_tool_is_never_proposed(self):
        self.h.scan({"space": "wifi"}); drain(self.h)
        st = self.h.state()[1]
        self.assertFalse(any(p["category"] == "wifi.deauth" for p in st["proposals"]))
        self.assertTrue(any(e["kind"] == "skipped" for e in self.store.evidence()))

    def test_labels_are_code_generated(self):
        p = self._proposal()
        self.assertEqual(p["label"], "Scan services on 10.10.0.50")

    def test_state_has_no_counts_for_badges(self):
        self.assertIsInstance(self.h.state()[1]["commander_pending"], bool)

    def test_finding_creates_commander_queue_digest_without_raw_output(self):
        self.h.scan({"space": "wifi"}); drain(self.h)
        q = self.store.pending_queue()
        self.assertEqual(len(q), 1)
        self.assertNotIn('"aps"', q[0]["payload"])
        self.assertIn("evil_twins", q[0]["payload"])

    def test_job_crash_is_contained(self):
        self.h.jobs.submit("boom", lambda: 1 / 0)
        drain(self.h)
        self.assertEqual(self.h.state()[1]["jobs"][0]["status"], "error")


class ScanGateTest(unittest.TestCase):
    def test_stealth_wired_refuses_instead_of_sweeping(self):
        h, store, runner, *_ = make()
        code, r = h.scan({"space": "wired", "mode": "stealth"})
        self.assertEqual((code, r["status"]), (409, "unavailable"))
        self.assertEqual(h.jobs.pending(), 0)
        self.assertEqual(runner.cmds, [])
        store.close()

    def test_discovery_needing_approval_becomes_approvable_proposal(self):
        h, store, runner, *_ = make()
        sc = copy.deepcopy(SCOPE); sc["auto_allow"] = ["recon.passive"]   # the shipped example
        h.api.scope = Scope(sc); h.api.orch.scope = h.api.scope; h.api.orch.gate = Gate(h.api.scope)
        code, r = h.scan({"space": "wired", "mode": "standard"})
        self.assertEqual((code, r["status"]), (200, "needs_approval"))
        p = h.state()[1]["proposals"][0]
        self.assertEqual(p["task_id"], r["task_id"])
        self.assertTrue(p["needs_approval"] and p["runnable"])
        self.assertIn("nmap -sn", p["command"])
        h.approve({"task_id": p["task_id"], "digest": p["digest"]})
        h.run({"task_id": p["task_id"]}); drain(h)
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
        self.assertEqual(h.console("192.168.4.20")[0], 404)
        self.assertFalse(h.state()[1]["console_enabled"])
        store.close()

    def test_flag_is_reread_from_disk(self):
        d = tempfile.mkdtemp(); path = os.path.join(d, "box.json")
        h, store, *_ = make()
        h.cfg.source_path = path
        with open(path, "w") as fh:
            json.dump({"console_enabled": True}, fh)
        self.assertTrue(h.state()[1]["console_enabled"])
        with open(path, "w") as fh:
            json.dump({"console_enabled": False}, fh)
        self.assertFalse(h.state()[1]["console_enabled"])
        store.close()

    def test_lan_only_tls_required_and_logged(self):
        d = tempfile.mkdtemp()
        cert, key = os.path.join(d, "c"), os.path.join(d, "k")
        h, store, *_ = make(console_enabled=True, tls_cert=cert, tls_key=key)
        h.cfg.console_password = "pw"
        self.assertEqual(h.console("10.0.0.9")[0], 403)
        self.assertEqual(h.console(None)[0], 403)
        self.assertEqual(h.console("192.168.4.20")[0], 503)      # no TLS cert yet
        open(cert, "w").close(); open(key, "w").close()
        code, r = h.console("192.168.4.20")
        self.assertEqual(code, 200)
        self.assertEqual(r["url"], "https://192.168.4.1:7681/")
        kinds = [e["kind"] for e in store.evidence()]
        self.assertIn("refused", kinds)
        self.assertIn("console", kinds)
        store.close()


class TlsTest(unittest.TestCase):
    def test_fails_closed(self):
        from havokbox.config import BoxConfig
        from havokbox.server import SECURITY_HEADERS, tls_args
        cfg = BoxConfig(tls_cert="/nope/c", tls_key="/nope/k")
        with self.assertRaises(SystemExit):
            tls_args(cfg)
        cfg.allow_insecure_http = True
        self.assertEqual(tls_args(cfg), {})
        self.assertEqual(SECURITY_HEADERS["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", SECURITY_HEADERS["Content-Security-Policy"])


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
