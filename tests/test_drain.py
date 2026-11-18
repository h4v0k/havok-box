import json
import unittest

from havokbox.commander import ApiCommander, SpendCapReached, parse_tasks
from havokbox.drain import Drainer
from tests.helpers import make


class FakeCommander:
    enabled = True

    def __init__(self, replies):
        self.replies = list(replies)
        self.seen = []

    def propose(self, digest):
        self.seen.append(digest)
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


class DrainTest(unittest.TestCase):
    def setUp(self):
        self.h, self.store, self.runner, self.scope, self.reg = make()
        self.h.scan({"space": "wired", "mode": "standard"})
        while self.h.jobs.run_one(timeout=0):
            pass
        self.planner_count = len(self.store.proposals())

    def tearDown(self):
        self.store.close()

    def drainer(self, replies, online=True):
        self.cmd = FakeCommander(replies)
        return Drainer(self.store, self.cmd, self.reg, self.scope, online=lambda: online)

    def test_offline_keeps_queue(self):
        d = self.drainer([[]], online=False)
        self.assertEqual(d.drain_once(), 0)
        self.assertEqual(len(self.store.pending_queue()), 1)
        self.assertEqual(self.cmd.seen, [])

    def test_online_drains_and_adds_sanitised_proposals(self):
        d = self.drainer([[
            {"tool": "nmap.services", "target": {"ip": "10.10.0.50", "evil": "x"}, "label": "AI scan"},
            {"tool": "nmap.services", "target": {"ip": "8.8.8.8"}},            # out of scope
            {"tool": "nmap.services", "target": {"ip": "10.10.0.1"}},          # excluded
            {"tool": "rm -rf", "target": {}},                                  # unknown tool
        ]])
        self.assertEqual(d.drain_once(), 1)
        self.assertEqual(self.store.pending_queue(), [])
        ai = [json.loads(p["task"]) for p in self.store.proposals() if p["step_kind"].startswith("ai:")]
        self.assertEqual(len(ai), 1)
        t = ai[0]
        self.assertEqual(t["category"], "recon.active")       # forced from registry
        self.assertEqual(t["target"], {"ip": "10.10.0.50"})   # stripped to spec
        self.assertEqual(t["mode"], "standard")
        self.assertTrue(t["suggested"])
        self.assertEqual(sum(1 for e in self.store.evidence() if e["kind"] == "refused"), 2)
        st = self.h.state()[1]
        self.assertTrue(any(p["source"] == "commander" for p in st["proposals"]))
        self.assertFalse(st["commander_pending"])

    def test_commander_category_lie_is_ignored(self):
        d = self.drainer([[{"tool": "nmap.services", "category": "recon.passive",
                            "target": {"ip": "10.10.0.50"}}]])
        d.drain_once()
        p = [p for p in self.h.state()[1]["proposals"] if p["source"] == "commander"][0]
        self.assertEqual(p["category"], "recon.active")
        self.assertTrue(p["needs_approval"])

    def test_commander_cannot_reuse_an_existing_task_id(self):
        existing = self.h.state()[1]["proposals"][0]["task_id"]
        self.h.approve({"task_id": existing})
        d = self.drainer([[{"id": existing, "tool": "nmap.services", "target": {"ip": "10.10.0.51"}}]])
        d.drain_once()
        ai = [p for p in self.h.state()[1]["proposals"] if p["source"] == "commander"][0]
        self.assertNotEqual(ai["task_id"], existing)

    def test_empty_reply_marks_done(self):
        d = self.drainer([[]])
        self.assertEqual(d.drain_once(), 1)
        self.assertEqual(self.store.pending_queue(), [])
        self.assertEqual(len(self.store.proposals()), self.planner_count)

    def test_api_error_leaves_entry_queued(self):
        d = self.drainer([OSError("timeout")])
        self.assertEqual(d.drain_once(), 0)
        self.assertEqual(len(self.store.pending_queue()), 1)

    def test_redrain_is_idempotent(self):
        reply = [{"tool": "nmap.services", "target": {"ip": "10.10.0.50"}}]
        q = self.store.pending_queue()[0]
        d = self.drainer([reply, reply])
        d.drain_once()
        n = len(self.store.proposals())
        # simulate a crash after the API call but "before" done: re-open the entry and drain again
        self.store.cx.execute("UPDATE offline_queue SET done=NULL WHERE id=?", (q["id"],))
        d.drain_once()
        self.assertEqual(len(self.store.proposals()), n)

    def test_spend_cap_stops_and_logs_once(self):
        d = self.drainer([SpendCapReached("cap"), SpendCapReached("cap")])
        d.drain_once(); d.drain_once()
        self.assertEqual(sum(1 for e in self.store.evidence() if e["kind"] == "commander"), 1)
        self.assertEqual(len(self.store.pending_queue()), 1)

    def test_disabled_commander_never_called(self):
        d = self.drainer([[]])
        self.cmd.enabled = False
        self.assertEqual(d.drain_once(), 0)
        self.assertEqual(self.cmd.seen, [])


class CommanderTest(unittest.TestCase):
    def test_disabled_without_key_or_cap(self):
        self.assertFalse(ApiCommander("", "m", 10, {}).enabled)
        self.assertFalse(ApiCommander("k", "m", 0, {}).enabled)

    def test_daily_cap_and_reset(self):
        now = [0.0]
        sent = []
        tr = lambda body: (sent.append(body), {"content": [{"type": "text", "text": '{"tasks": []}'}]})[1]
        c = ApiCommander("k", "claude-opus-5-5", 2, {}, transport=tr, clock=lambda: now[0])
        c.propose({"summary": "x"}); c.propose({"summary": "x"})
        with self.assertRaises(SpendCapReached):
            c.propose({"summary": "x"})
        now[0] += 86400
        c.propose({"summary": "x"})
        self.assertEqual(len(sent), 3)
        self.assertEqual(sent[0]["model"], "claude-opus-5-5")
        self.assertLessEqual(sent[0]["max_tokens"], 1000)

    def test_parse_tasks_tolerates_junk(self):
        self.assertEqual(parse_tasks("no json"), [])
        self.assertEqual(parse_tasks('{"tasks": "nope"}'), [])
        self.assertEqual(parse_tasks('Sure! {"tasks": [{"tool": "a"}, 3]}'), [{"tool": "a"}])


if __name__ == "__main__":
    unittest.main()
