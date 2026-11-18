import json
import os
import tempfile
import unittest

from havokbox.scope import Scope
from havokbox.server import Jobs
from havokbox.store import Store
from havokbox.survey import SurveyError, SurveyService

A, B = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"


def dev(mac, rssi, ts):
    return {"kismet.device.base.macaddr": mac, "kismet.device.base.type": "Wi-Fi AP",
            "kismet.device.base.signal": {"kismet.common.signal.last_signal": rssi},
            "kismet.device.base.last_time": ts}


class Fake:
    """Fake Kismet: per poll, each mac yields (rssi, ts); ts advances unless stale."""
    def __init__(self, rssis, stale=()):
        self.rssis, self.stale, self.t, self.polls = rssis, set(stale), 1000, 0
        self.now = 0.0

    def runner(self, argv, timeout):
        self.polls += 1
        self.t += 1
        out = []
        for mac, seq in self.rssis.items():
            i = min(self.polls - 1, len(seq) - 1)
            ts = 1000 if mac in self.stale else self.t
            out.append(dev(mac, seq[i], ts))
        return json.dumps(out)

    def sleep(self, s):
        self.now += s

    def mono(self):
        return self.now


class SurveyTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.d.name, "box.db")
        self.store = Store(self.path)
        self.jobs = Jobs(self.store, start=False)
        self.scope = Scope({"name": "t", "wifi": {"bssids": [A, B]},
                            "auto_allow": [], "approval_required": []})
        self.fake = Fake({A: [-60, -62, -64, -66], B: [-80, -81, -82, -83]})
        self.svc = self._svc(self.fake)

    def _svc(self, fake):
        return SurveyService(self.store, self.path, self.jobs, self.scope, {}, fake.runner,
                             clock=lambda: 5.0, sleep=fake.sleep, mono=fake.mono)

    def tearDown(self):
        self.store.close()
        self.d.cleanup()

    def test_out_of_scope_refused(self):
        with self.assertRaises(ValueError):
            self.svc.start("x", [A, "de:ad:be:ef:00:00"])
        with self.assertRaises(ValueError):
            self.svc.start("x", [])
        with self.assertRaises(ValueError):
            self.svc.start("x", [A], grid_w=1)
        self.assertNotIn("wifi", self.jobs.held)

    def test_lane_conflict_and_never_releases_wardrive(self):
        self.assertTrue(self.jobs.hold(["wifi"], owner="wardrive"))
        with self.assertRaisesRegex(SurveyError, "radio busy"):
            self.svc.start("x", [A])
        self.jobs.release(["wifi"], owner="survey")
        self.assertEqual(self.jobs.held.get("wifi"), "wardrive")
        self.assertEqual(self.svc.list(), [])

    def test_measure_median_early_stop_and_stop_releases(self):
        sid = self.svc.start("floor1", [A.upper(), B], 4, 4)
        self.assertEqual(self.jobs.held["wifi"], "survey")
        with self.assertRaises(SurveyError):
            self.svc.start("again", [A])
        r = self.svc.measure(1, 2)
        self.assertEqual(r[A], {"median": -62.0, "n": 3})
        self.assertEqual(r[B], {"median": -81.0, "n": 3})
        self.assertEqual(self.fake.polls, 3)          # early stop at 3 fresh samples
        with self.assertRaises(ValueError):
            self.svc.measure(4, 0)
        self.svc.stop()
        self.assertNotIn("wifi", self.jobs.held)
        with self.assertRaises(SurveyError):
            self.svc.measure(0, 0)
        self.assertEqual(self.svc.list()[0]["status"], "done")
        self.assertEqual(sid, self.svc.list()[0]["id"])

    def test_stale_samples_not_counted(self):
        fake = Fake({A: [-60] * 20, B: [-70] * 20}, stale={B})
        svc = self._svc(fake)
        svc.start("s", [A, B])
        r = svc.measure(0, 0)
        self.assertGreaterEqual(r[A]["n"], 3)
        self.assertEqual(r[B], {"median": None, "n": 1})   # only the first sight is fresh
        self.assertEqual(len(svc.heatmap(svc.list()[0]["id"])["cells"]), 1)
        self.assertLessEqual(fake.now, 15.0)

    def test_heatmap_weak_csv_delete_abort(self):
        sid = self.svc.start("s", [A, B], 3, 3)
        self.svc.measure(0, 0)
        self.fake.polls = 0
        self.svc.measure(0, 0)                          # upsert, not duplicate
        with self.assertRaises(SurveyError):
            self.svc.delete(sid)
        hm = self.svc.heatmap(sid)
        self.assertEqual(hm["grid"], [3, 3])
        self.assertEqual(hm["bssids"], sorted([A, B]))
        self.assertEqual(len(hm["cells"]), 2)
        self.assertEqual([c["bssid"] for c in hm["weak"]], [B])
        lines = self.svc.csv(sid).splitlines()
        self.assertEqual(lines[0], "bssid,x,y,median_rssi,n")
        self.assertEqual(len(lines), 3)
        self.assertEqual(self.svc.abort_running(), 1)   # simulated boot
        self.assertEqual(self.svc.list()[0]["status"], "aborted")
        self.svc.delete(sid)
        self.assertEqual(self.svc.list(), [])


if __name__ == "__main__":
    unittest.main()
