import json
import unittest

from havokbox.commander import SpendCapReached
from havokbox.session_report import SessionReporter, session_digest
from havokbox.store import Store

HASH = "admin::LAB:1122334455667788:deadbeefcafe0123456789abcdef"


class FakeCmd:
    def __init__(self, enabled=True, cap=False, text="Summary of the session."):
        self.enabled, self.cap, self.model = enabled, cap, "m"
        self.max_tokens, self.sent, self.charged = 600, [], 0
        self.text = text
        self.transport = self._t

    def _t(self, body):
        self.sent.append(body)
        return {"content": [{"type": "text", "text": self.text}]}

    def _charge(self):
        if self.cap:
            raise SpendCapReached("cap")
        self.charged += 1


def seeded():
    s = Store(":memory:")
    s.add_finding("r1", "lan", "services", "10.0.0.5 open 22,445",
                  {"host": "10.0.0.5", "ports": [22, 445], "password": "hunter2",
                              "raw": "RAWTOOLOUTPUT"}, "m")
    s.add_finding("r2", "lan", "poison", "captured 1 auth", {"ntlm": HASH}, "m")
    s.add_finding("r3", "lan", "creds_default", "default login on 10.0.0.9",
                  {"user": "admin", "password": "admin"}, "m")
    s.add_finding("r4", "wifi", "rogue_ap", "ap up", {"hash": HASH}, "m")
    s.add_finding("r5", "lan", "nuclei", "cve found", {"hash": HASH, "id": "CVE-1"}, "m")
    s.add_proposal("r1", "step", {"tool": "nmap", "category": "active"})
    s.log("scan", "x")
    return s


class T(unittest.TestCase):
    def test_digest_excludes_secrets(self):
        s = seeded()
        d = session_digest(s)
        j = json.dumps(d)
        for bad in (HASH, "deadbeef", "hunter2", "RAWTOOLOUTPUT", "admin"):
            self.assertNotIn(bad, j)
        by = {n["kind"]: n for n in d["notable"]}
        for k in ("poison", "creds_default", "rogue_ap"):
            self.assertNotIn("data", by[k])
        self.assertEqual(by["nuclei"]["data"], {"id": "CVE-1"})
        self.assertEqual(by["services"]["data"]["ports"], [22, 445])
        self.assertEqual(d["attack_path"][0]["tool"], "nmap")
        self.assertEqual(d["evidence_kinds"], {"scan": 1})

    def test_disabled(self):
        r = SessionReporter(seeded(), FakeCmd(enabled=False))
        self.assertEqual(r.generate(), {"status": "disabled"})

    def test_generate_stores_and_sends_clean(self):
        c = FakeCmd()
        r = SessionReporter(seeded(), c)
        out = r.generate()
        self.assertEqual((out["status"], out["text"]), ("ok", "Summary of the session."))
        self.assertEqual(c.charged, 1)
        self.assertNotIn(HASH, json.dumps(c.sent))
        self.assertEqual(r.latest()["text"], out["text"])
        self.assertEqual(r.latest()["id"], out["id"])

    def test_capped_stores_nothing(self):
        r = SessionReporter(seeded(), FakeCmd(cap=True))
        self.assertEqual(r.generate(), {"status": "capped"})
        self.assertEqual(r.list(), [])
        self.assertIsNone(r.latest())

    def test_list_order_and_size_limit(self):
        s = seeded()
        for i in range(300):
            s.add_finding(f"x{i}", "lan", "services", "s" * 190, {"a": "b" * 100}, "m")
        self.assertLessEqual(len(json.dumps(session_digest(s, cap=300))), 16 * 1024)
        r = SessionReporter(s, FakeCmd())
        r.generate(); r.generate()
        ids = [x["id"] for x in r.list(10)]
        self.assertEqual(ids, sorted(ids, reverse=True))
        self.assertEqual(len(r.list(1)), 1)


if __name__ == "__main__":
    unittest.main()
