"""Drive Guard: tablet token scope, touch lock, sentry, TPMS, ALPR, phrases, watchdog limit."""
import json
import os
import tempfile
import unittest

from havokbox.config import BoxConfig
from havokbox.wardrive import alpr
from havokbox.wardrive.service import PHRASES, phrase_for
from tests.test_wd_service import FakeReader, FakeRunner, ServiceTest, APPLE_SEPARATED, TAG


def tpms_lines(model="Ford", sid="0x1a2b3c4d", n=2, rssi=-20.0):
    return "\n".join(json.dumps({"type": "TPMS", "model": model, "id": sid, "mic": "CRC",
                                 "pressure_kPa": 230, "rssi": rssi}) for _ in range(n))


class GuardRunner(FakeRunner):
    def __init__(self):
        super().__init__()
        self.tpms = ""

    def __call__(self, argv, timeout):
        if argv and argv[0] == "rtl_433":
            self.calls.append(argv)
            return self.tpms
        return super().__call__(argv, timeout)


class FakeNotifier:
    enabled = True

    def __init__(self):
        self.sent = []

    def send(self, key, kind, severity, text, ts, lat=None, lon=None):
        self.sent.append((kind, severity, text))
        return True


class GuardTest(ServiceTest):
    def setUp(self):
        super().setUp()
        self.run = GuardRunner()
        self.wd.runner = self.run
        self.notes = FakeNotifier()
        self.wd.notifier = self.notes
        self.h.cfg.guard_token = "tablet-tok"

    def drive(self, speed):
        for _ in range(12):
            self.mono[0] += 1
            self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.95, "lon": -82.46,
                                "mode": 3, "speed": speed})
            self.wd.tick_track()

    # ---- tokens / touch lock ---------------------------------------------
    def test_guard_token_only_reaches_guard_api(self):
        self.assertTrue(self.h.authorized("Bearer tablet-tok", "/api/guard/state"))
        self.assertFalse(self.h.authorized("Bearer tablet-tok", "/api/run"))
        self.assertFalse(self.h.authorized("Bearer tablet-tok", "/api/wardrive/export"))
        self.assertTrue(self.h.authorized("Bearer s3cret", "/api/guard/state"))

    def test_touch_locked_while_moving_server_side(self):
        self.wd.start()
        self.drive(12.0)                                   # ~27 mph
        st = self.h.guard_state(0)[1]
        self.assertFalse(st["can_touch"])
        self.assertEqual(st["offers"], [])
        for call in (lambda: self.h.guard_ack({"alert_id": 1}),
                     lambda: self.h.guard_sentry({"arm": True}),
                     lambda: self.h.guard_mine({"radio": "tpms", "dev_key": "h:x"})):
            code, r = call()
            self.assertEqual((code, r["reason"]), (409, "park first"))
        self.drive(0.0)
        self.assertTrue(self.h.guard_state(0)[1]["can_touch"])
        self.assertEqual(self.h.wardrive_ack({"alert_id": 1})[0], 200)   # phone/passenger unrestricted

    def test_garage_no_fix_allows_touch(self):
        self.wd.start()
        self.drive(0.0)
        self.wd.gps.mark_no_fix()
        self.mono[0] += 61
        self.wd.tick_track()
        self.assertTrue(self.wd.can_touch())

    # ---- sentry ---------------------------------------------------------------
    def test_arm_from_drive_switches_in_place_radios_stay_held(self):
        self.wd.start()
        self.drive(0.0)
        held_before = set(self.h.jobs.held)
        code, r = self.h.guard_sentry({"arm": True})
        self.assertEqual(code, 200)
        self.assertEqual(self.wd.mode, "sentry")
        self.assertEqual(set(self.h.jobs.held), held_before)
        self.assertTrue(self.h.api.orch.passive_only)
        modes = [(x["mode"], x["status"]) for x in self.db.query(
            "SELECT mode, status FROM wardrive_sessions ORDER BY started")]
        self.assertIn(("drive", "switched"), modes)
        self.assertIn(("sentry", "running"), modes)

    def test_car_moved_needs_consistent_fixes(self):
        self.wd.start(mode="sentry")
        for i in range(13):                                  # 2 min of anchor fixes
            self.mono[0] += 10
            self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.95, "lon": -82.46, "mode": 3,
                                "speed": 0, "eph": 8})
            self.wd.tick_sentry()
        self.assertIsNotNone(self.wd.anchor)
        # one GPS jump: no alert
        self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.9520, "lon": -82.46, "mode": 3, "eph": 8})
        self.wd.tick_sentry()
        self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.95, "lon": -82.46, "mode": 3, "eph": 8})
        self.wd.tick_sentry()
        self.assertEqual(self.db.query("SELECT * FROM alerts WHERE kind='car_moved'"), [])
        for _ in range(3):
            self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.9530, "lon": -82.46, "mode": 3, "eph": 8})
            self.wd.tick_sentry()
        a = self.db.query("SELECT * FROM alerts WHERE kind='car_moved'")
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "high")
        self.assertEqual(self.notes.sent[0][0], "car_moved")

    def test_own_tires_waking_means_car_moved(self):
        self.wd.start(mode="sentry")
        key = self.db.dev_key("tpms", "tpms", "Ford:0x1a2b3c4d")
        self.db.add_mine("tpms", key, "Mustang FL")
        self.run.tpms = tpms_lines()
        self.wd._stop.set()                                  # don't wait out the 270 s duty cycle
        self.wd.tick_sdr_sentry()
        self.assertEqual(len(self.db.query("SELECT * FROM alerts WHERE kind='car_moved'")), 1)

    def test_sentry_tracker_held_ten_minutes_and_quiet_zone(self):
        self.wd.start(mode="sentry")
        self.run.ble = [{"addr": TAG, "rssi": -60, "company_ids": [76], "uuid16": [],
                         "mfg_data": [APPLE_SEPARATED], "random": True}]
        self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.95, "lon": -82.46, "mode": 3})
        self.wd.quiet_zones = [{"lat": 27.95, "lon": -82.46, "radius_m": 200}]   # at home
        for t in (0, 300, 660):
            self.wall[0] += t and 330
            self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.95, "lon": -82.46, "mode": 3})
            self.wd.tick_ble(); self.wd.tick_sentry()
        self.assertEqual(self.db.query("SELECT * FROM alerts WHERE kind='sentry_tracker'"), [])
        self.wd.quiet_zones = []
        self.wd.tick_sentry()
        self.assertEqual(len(self.db.query("SELECT * FROM alerts WHERE kind='sentry_tracker'")), 1)

    # ---- TPMS -----------------------------------------------------------------
    def test_tpms_hashed_and_follow_is_medium(self):
        self.wd.start()
        self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.95, "lon": -82.46, "mode": 3})
        self.run.tpms = tpms_lines(sid="0xdeadbeef")
        self.wd._last_floor = self.mono[0]                   # skip the floor sweep this pass
        self.wd.tick_sdr()
        rows = self.db.query("SELECT * FROM device_cells WHERE radio='tpms'")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["dev_key"].startswith("h:"))
        self.assertNotIn("deadbeef", json.dumps(rows))
        # simulate the follow-me verdict for a TPMS device
        import havokbox.wardrive.followme as fm
        orig = fm.assess
        fm.assess = lambda stops, by_dev, **kw: [{"dev_key": rows[0]["dev_key"], "severity": "high",
                                                  "stops_matched": 3, "span_m": 4000, "tracker": None}]
        self.wd.db.query = (lambda q=self.wd.db.query: (lambda sql, args=(): (
            [{"ts": 0, "lat": 27.95, "lon": -82.46}, {"ts": 400, "lat": 27.95, "lon": -82.46},
             {"ts": 900, "lat": 28.0, "lon": -82.46}, {"ts": 1300, "lat": 28.0, "lon": -82.46}]
            if "FROM track" in sql else q(sql, args))))()
        import havokbox.wardrive.geo as geo
        orig_stops = geo.find_stops
        geo.find_stops = lambda pts: [{"lat": 1, "lon": 1, "start": 0, "end": 1}] * 2
        try:
            self.wd.tick_follow()
        finally:
            fm.assess, geo.find_stops = orig, orig_stops
        a = self.db.query("SELECT * FROM alerts WHERE kind='follow_tpms'")
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "medium")

    def test_own_tires_offered_after_two_sessions_never_auto(self):
        for _ in range(2):
            self.wd.start()
            self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.95, "lon": -82.46, "mode": 3})
            self.run.tpms = tpms_lines(sid="0x0000feed")
            for _ in range(6):
                self.wd._last_floor = self.mono[0]
                self.wd.tick_sdr()
            self.wd.track.distance_m = 6000
            self.wd.stop()
        self.drive(0.0)
        offers = self.db.offers()
        self.assertEqual(len(offers), 1)
        self.assertEqual(self.db.mine_keys(), set())         # offered, not allowlisted

    # ---- ALPR -----------------------------------------------------------------
    def test_alpr_warning_reaches_tablet_but_not_alerts(self):
        path = os.path.join(self.dir, "alpr.json")
        alpr.save_atomic(path, [{"id": "123", "lat": 27.9525, "lon": -82.4600, "dir": None}])
        self.wd.alpr_path = path
        self.wd.load_alpr()
        self.wd.start()
        for i in range(10):                                  # drive north toward the camera at 10 m/s
            self.mono[0] += 1; self.wall[0] += 1
            self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.9500 + i * 0.0001,
                                "lon": -82.46, "mode": 3, "speed": 10, "track": 0})
            self.wd.tick_track()
        st = self.h.guard_state(0)[1]
        self.assertEqual(st["alpr_near"]["id"], "123")
        self.assertEqual(self.db.query("SELECT * FROM alerts WHERE kind='alpr'"), [])

    # ---- misc -----------------------------------------------------------------
    def test_phrases_are_short(self):
        for k in list(PHRASES) + ["DEAUTHFLOOD"]:
            self.assertLessEqual(len(phrase_for(k).split()), 6, k)

    def test_watchdog_uses_sentry_limit(self):
        from havokbox.watchdog import Watchdog
        cfg = BoxConfig(db_path=self.path, session_limit_s=100, sentry_limit_s=5000)
        w = Watchdog(cfg, spawn=lambda c: None)
        self.assertEqual(w._limit(), 100)
        self.wd.start(mode="sentry")
        self.assertEqual(w._limit(), 5000)


if __name__ == "__main__":
    unittest.main()
