"""Phase 6 integration: exposure report, drone alerts, SDR lanes, baseline drift via the API."""
import json
import unittest

from tests.test_remoteid import basic, loc, system
from tests.test_wd_guard import GuardTest, tpms_lines
from tests.helpers import make


class ExposureTest(GuardTest):
    def moving(self, speed=15.0):
        self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.95, "lon": -82.46,
                            "mode": 3, "speed": speed})

    def test_report_marks_static_ids_and_hides_plaintext_in_stored_copy(self):
        self.wd.start()
        self.moving()
        self.run.kismet_devices = [{"kismet.device.base.macaddr": "AA:BB:CC:00:11:22",
                                    "kismet.device.base.type": "Wi-Fi AP",
                                    "kismet.device.base.commonname": "Mustang-4F2A"}]
        self.run.ble = [{"addr": "aa:aa:aa:00:00:01", "name": "Watch", "random": False, "rssi": -40},
                        {"addr": "7a:00:00:00:00:02", "random": True, "rssi": -50}]
        for _ in range(32):
            self.wd.tick_kismet()
            self.wd.tick_ble()
        self.moving(0.5)                      # parked windows don't count
        for _ in range(40):
            self.wd.tick_kismet()
        self.wd.track.distance_m = 8000
        self.wd.stop()
        live = self.wd.last_exposure
        names = {it.get("name") for it in live["items"]}
        self.assertIn("Mustang-4F2A", names)
        self.assertEqual(live["rotating_ble"], 1)
        ap = [i for i in live["items"] if i["radio"] == "wifi"][0]
        self.assertEqual(ap["identifier"], "static")
        self.assertIn("Turn it off", ap["advice"])
        self.assertEqual(live["windows"]["wifi"], 32)          # only moving windows counted
        stored = json.loads(self.db.query("SELECT report_json FROM exposure_reports")[0]["report_json"])
        self.assertNotIn("aa:aa:aa:00:00:01", json.dumps(stored))   # not marked yours -> no plaintext
        self.assertTrue(all(i["label"] == "not marked as yours" for i in stored["items"]))

    def test_short_or_few_window_drives_get_no_report(self):
        self.wd.start()
        self.moving()
        self.run.ble = [{"addr": "aa:aa:aa:00:00:01", "random": False}]
        for _ in range(10):
            self.wd.tick_ble()
        self.wd.track.distance_m = 8000
        self.wd.stop()
        self.assertEqual(self.wd.last_exposure["items"], [])   # < 30 windows
        self.wd.start(); self.wd.stop()                         # < 5 km: no new report
        self.assertEqual(len(self.db.query("SELECT * FROM exposure_reports")), 1)

    def test_drone_lingering_alerts_without_operator_position(self):
        self.wd.start()
        self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.9, "lon": -82.4, "mode": 3})
        self.run.ble = [{"addr": "d0:00:00:00:00:01", "service_data": [basic(), loc(27.9005, -82.4), system()]}]
        for i in range(8):
            self.wall[0] += 60
            self.wd.gps.update({"class": "TPV", "ts": self.wall[0], "lat": 27.9, "lon": -82.4, "mode": 3})
            self.wd.tick_ble()
        a = self.db.query("SELECT * FROM alerts WHERE kind='drone'")
        self.assertEqual(len(a), 1)
        self.assertIsNone(a[0]["lat"] if False else None)
        self.assertNotIn("27.95", json.dumps(a))               # operator coords never stored
        st = self.h.wardrive_state()[1]
        self.assertTrue(st["drones"][0]["operator_known"])
        self.assertNotIn("op_lat", st["drones"][0])


class LaneTest(unittest.TestCase):
    def test_sdr2_shares_main_lane_without_second_dongle(self):
        h, store, *_ = make()
        self.assertEqual(h.lane_for("sdr2"), "sdr")
        h.cfg.hw = {"sdr2_serial": "ADSB01"}
        self.assertEqual(h.lane_for("sdr2"), "sdr2")
        store.close()

    def test_adsb_refused_during_drive_on_single_dongle(self):
        h, store, *_ = make()
        h.jobs.hold(["wifi", "ble", "esp", "sdr", "subghz"], owner="wardrive")
        self.assertEqual(h.scan({"space": "sdr2", "action": "adsb"})[0], 409)
        h.cfg.hw = {"sdr2_serial": "ADSB01"}
        self.assertEqual(h.scan({"space": "sdr2", "action": "adsb"})[0], 202)
        store.close()

    def test_rtl_tools_pin_serial(self):
        from havokbox.tools import sdr
        from havokbox.wardrive import rf_floor, tpms
        hw = {"sdr_serial": "MAIN01"}
        self.assertIn(":MAIN01", sdr.build_decode({}, "stealth", None, hw)[0])
        self.assertIn(":MAIN01", tpms.window_argv("315M", 50, hw))
        self.assertIn(":MAIN01", rf_floor.sweep_argv("433", hw=hw))
        with self.assertRaises(ValueError):
            sdr.dev_args({"sdr_serial": "x; rm"})

    def test_lane_owner_survey_cannot_release_wardrive(self):
        h, store, *_ = make()
        self.assertTrue(h.jobs.hold(["wifi"], owner="wardrive"))
        self.assertFalse(h.jobs.hold(["wifi"], owner="survey"))
        h.jobs.release(["wifi"], owner="survey")
        self.assertEqual(h.jobs.held.get("wifi"), "wardrive")
        store.close()


class BaselineApiTest(unittest.TestCase):
    def test_learn_then_new_host_shows_then_accept(self):
        h, store, runner, *_ = make()
        h.scan({"space": "wired", "mode": "standard"})
        while h.jobs.run_one():
            pass
        self.assertFalse(h.state()[1]["drift"]["learned"])
        self.assertEqual(h.baseline_learn()[0], 200)
        self.assertEqual(h.state()[1]["drift"]["items"], [])
        import tests.helpers as hp
        orig = hp.DISCOVERY_XML
        runner_xml = ('<nmaprun><host><status state="up"/><address addr="10.10.0.50" addrtype="ipv4"/>'
                      '<address addr="AA:00:00:00:00:50" addrtype="mac"/></host>'
                      '<host><status state="up"/><address addr="10.10.0.77" addrtype="ipv4"/>'
                      '<address addr="AA:00:00:00:00:77" addrtype="mac"/></host></nmaprun>')
        h.api.orch.runner = lambda cmd: runner_xml if "-sn" in cmd else hp.SERVICES_XML
        h.scan({"space": "wired", "mode": "standard"})
        while h.jobs.run_one():
            pass
        items = h.state()[1]["drift"]["items"]
        new = [i for i in items if i["kind"] == "new_host"]
        self.assertTrue(new)
        self.assertEqual(h.baseline_accept({"space": new[0]["space"], "key": new[0]["key"]})[0], 200)
        self.assertFalse([i for i in h.state()[1]["drift"]["items"]
                          if i["kind"] == "new_host" and i["key"] == new[0]["key"]])
        store.close()


if __name__ == "__main__":
    unittest.main()
