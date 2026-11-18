import unittest

from havokbox.wardrive import followme, trackers

A = (27.95, -82.46)
B = (27.995, -82.46)    # ~5 km north
C = (27.959, -82.46)    # ~1 km north


def stop(pt, s, e):
    return {"lat": pt[0], "lon": pt[1], "start": s, "end": e}


def obs(pt, ts, rssi=-85):
    return {"ts": ts, "lat": pt[0], "lon": pt[1], "rssi": rssi}


STOPS = [stop(A, 0, 600), stop(B, 1200, 1800)]


class TrackerTest(unittest.TestCase):
    def test_findmy(self):
        sep = {"company_ids": [0x4C], "mfg_data": ["4c0012190000"]}
        sep2 = {"company_ids": [0x4C], "mfg_data": ["121900ff"]}
        near = {"company_ids": [0x4C], "mfg_data": ["4c00120200"]}
        other = {"company_ids": [0x4C], "mfg_data": ["4c0010050000"]}
        self.assertEqual(trackers.classify(sep), "findmy_separated")
        self.assertEqual(trackers.classify(sep2), "findmy_separated")
        self.assertIsNone(trackers.classify(near))
        self.assertIsNone(trackers.classify(other))
        self.assertIsNone(trackers.classify({"company_ids": [6], "mfg_data": ["12190000"]}))

    def test_others(self):
        self.assertEqual(trackers.classify({"uuid16": [0xFEED]}), "tile")
        self.assertEqual(trackers.classify({"uuid16": [0xFEEC]}), "tile")
        self.assertEqual(trackers.classify({"uuid16": [0xFD5A]}), "smarttag")
        self.assertEqual(trackers.classify({"uuid16": [0xFE33]}), "chipolo")
        self.assertEqual(trackers.classify({"uuid16": [0xFE65]}), "chipolo")
        self.assertEqual(trackers.classify({"uuid16": [0xFEAA], "mfg_data": ["4100"]}), "google_dult")
        self.assertEqual(trackers.classify({"uuid16": [0xFEAA]}), "google_dult")
        self.assertIsNone(trackers.classify({"uuid16": [0xFEAA], "mfg_data": ["00ee"]}))
        self.assertIsNone(trackers.classify({"uuid16": [0x180F], "company_ids": [6]}))
        self.assertIsNone(trackers.classify({}))


class FollowTest(unittest.TestCase):
    def dev(self, obs_list, kind=None):
        return {"d1": {"kind": kind, "radio": "ble", "obs": obs_list}}

    def test_tracker_two_stops(self):
        r = followme.assess(STOPS, self.dev([obs(A, 100), obs(B, 1300)], "tile"))
        self.assertEqual(len(r), 1)
        a = r[0]
        self.assertEqual((a["kind"], a["severity"], a["tracker"], a["stops_matched"]),
                         ("follow", "high", "tile", 2))
        self.assertGreater(a["span_m"], 4000)
        self.assertEqual((a["first_ts"], a["last_ts"], a["present_at_start"]), (100, 1300, False))

    def test_unknown_medium_and_close_bump(self):
        far = followme.assess(STOPS, self.dev([obs(A, 100), obs(B, 1300)]))
        self.assertEqual(far[0]["severity"], "medium")
        near = followme.assess(STOPS, self.dev([obs(A, 100, -60), obs(B, 1300, -62)]))
        self.assertEqual(near[0]["severity"], "high")

    def test_driving_only(self):
        self.assertEqual(followme.assess(STOPS, self.dev([obs(A, 800), obs(B, 1000)])), [])

    def test_same_stop_only(self):
        self.assertEqual(followme.assess(STOPS, self.dev([obs(A, 100), obs(A, 500)])), [])

    def test_stops_too_close(self):
        st = [stop(A, 0, 600), stop(C, 1200, 1800)]
        self.assertEqual(followme.assess(st, self.dev([obs(A, 100), obs(C, 1300)])), [])

    def test_mine_and_present_at_start(self):
        d = self.dev([obs(A, 100), obs(B, 1300)])
        self.assertEqual(followme.assess(STOPS, d, mine={"d1"}), [])
        r = followme.assess(STOPS, d, present_at_start={"d1"})
        self.assertTrue(r and r[0]["present_at_start"])


if __name__ == "__main__":
    unittest.main()
