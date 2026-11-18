import hashlib
import json
import os
import tempfile
import unittest

from havokbox.drain import Drainer
from havokbox.publisher import PublishError, Publisher, publish_pending, request_publish
from tests.helpers import make


class FakeIngest:
    """Stands in for the Worker: newer-only versions, hash check. Records every call."""
    def __init__(self, status=None):
        self.calls, self.latest, self.status = [], 0, status

    def __call__(self, url, body, headers):
        self.calls.append((url, body, headers))
        if self.status:
            return self.status, "nope"
        v = int(headers["X-Snapshot-Version"])
        if hashlib.sha256(body).hexdigest() != headers["X-Snapshot-SHA256"]:
            return 400, "hash"
        if v <= self.latest:
            return 409, "stale"
        self.latest = v
        return 201, json.dumps({"version": v})


class PublisherTest(unittest.TestCase):
    def setUp(self):
        self.h, self.store, *_ = make()
        self.h.scan({"space": "wired", "mode": "standard"})
        while self.h.jobs.run_one():
            pass
        self.dir = tempfile.mkdtemp()
        self.now = [1_800_000_000.0]
        self.ingest = FakeIngest()
        self.pub = Publisher(self.store, "https://snap.example.workers.dev/", "write-tok",
                             os.path.join(self.dir, "state.json"), scope_name="lab",
                             transport=self.ingest, clock=lambda: self.now[0])

    def tearDown(self):
        self.store.close()

    def test_snapshot_contents_and_headers(self):
        r = self.pub.publish_now()
        url, body, headers = self.ingest.calls[0]
        self.assertEqual(url, "https://snap.example.workers.dev/ingest")
        self.assertEqual(headers["Authorization"], "Bearer write-tok")
        doc = json.loads(body)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["version"], r["version"])
        self.assertEqual(doc["scope_name"], "lab")
        self.assertEqual(len(doc["findings"]), 1)
        self.assertEqual(doc["attack_path"][0]["status"], "pending")
        self.assertTrue(any(e["kind"] == "ran" for e in doc["evidence"]))
        self.assertTrue(any(e["kind"] == "publish" for e in self.store.evidence()))

    def test_versions_strictly_increase_even_if_state_lost(self):
        v1 = self.pub.publish_now()["version"]
        v2 = self.pub.publish_now()["version"]
        self.assertGreater(v2, v1)
        os.remove(self.pub.state_path)          # state file lost: time-based floor keeps it monotonic
        self.now[0] += 5
        self.assertGreater(self.pub.publish_now()["version"], v2)

    def test_never_reads_from_cloudflare(self):
        self.pub.publish_now()
        for url, body, headers in self.ingest.calls:
            self.assertTrue(url.endswith("/ingest"))
            self.assertIsNotNone(body)          # every call is a POST with a body

    def test_rejection_raises_and_state_unchanged(self):
        self.pub.transport = FakeIngest(status=401)
        with self.assertRaises(PublishError):
            self.pub.publish_now()
        self.assertEqual(self.pub.state(), {})

    def test_disabled_without_url_or_token(self):
        self.assertFalse(Publisher(self.store, "", "t", "/tmp/x").enabled)
        self.assertFalse(Publisher(self.store, "https://x", "", "/tmp/x").enabled)

    def test_oversize_evidence_trimmed(self):
        import havokbox.publisher as P
        orig = P.MAX_BYTES
        P.MAX_BYTES = 6000
        try:
            for i in range(300):
                self.store.log("x", "y" * 50)
            doc = json.loads(self.pub.build(1))
            self.assertTrue(doc.get("evidence_truncated"))
        finally:
            P.MAX_BYTES = orig


class PublishFlowTest(PublisherTest):
    def test_handler_queues_and_publishes(self):
        self.h.publisher = self.pub
        code, r = self.h.publish()
        self.assertEqual(code, 202)
        while self.h.jobs.run_one():
            pass
        st = self.h.state()[1]["publish"]
        self.assertTrue(st["enabled"])
        self.assertFalse(st["pending"])
        self.assertEqual(st["viewer_url"], "https://snap.example.workers.dev/")

    def test_not_configured_is_409(self):
        self.h.publisher = Publisher(self.store, "", "", "/tmp/none")
        self.assertEqual(self.h.publish()[0], 409)
        self.assertFalse(self.h.state()[1]["publish"]["enabled"])

    def test_offline_publish_waits_then_drains_once(self):
        self.h.publisher = self.pub
        self.pub.transport = FakeIngest(status=503)  # push fails: stays queued
        self.h.publish()
        self.h.publish()
        while self.h.jobs.run_one():
            pass
        self.assertTrue(self.h.state()[1]["publish"]["pending"])
        self.pub.transport = self.ingest            # back online
        online = [False]
        d = Drainer(self.store, type("C", (), {"enabled": False})(), {}, self.h.api.scope,
                    online=lambda: online[0], clock=lambda: 0, publisher=self.pub)
        self.assertEqual(d.drain_once(), 0)          # offline: nothing sent
        online[0] = True
        self.assertEqual(d.drain_once(), 2)          # both triggers cleared by ONE publish
        self.assertEqual(len(self.ingest.calls), 1)
        self.assertFalse(self.h.state()[1]["publish"]["pending"])


if __name__ == "__main__":
    unittest.main()
