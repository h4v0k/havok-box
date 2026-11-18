import csv
import io
import json
import os
import tempfile
import unittest

from havokbox.wardrive import export, kismet_poll as kp, rf_floor

HW = {"kismet_header": "/tmp/k.header"}
SECRET = "SECRETKEY123"

DEVICES = [
    {"kismet.device.base.macaddr": "AA:BB:CC:00:11:22", "kismet.device.base.type": "Wi-Fi AP",
     "kismet.device.base.commonname": "HomeNet", "kismet.device.base.channel": "6",
     "kismet.device.base.signal": {"kismet.common.signal.last_signal": -47},
     "kismet.device.base.location": {"kismet.common.location.avg_loc": {
         "kismet.common.location.geopoint": [-82.5, 28.0]}},
     "kismet.device.base.last_time": 1700000000},
    {"kismet.device.base.macaddr": "DE:AD:BE:EF:00:01", "kismet.device.base.type": "Wi-Fi Client",
     "kismet.device.base.name": "phone", "kismet.device.base.signal": {},
     "kismet.device.base.last_time": 1700000001},
    {"kismet.device.base.type": "Wi-Fi AP"},
    "junk",
]
ALERTS = {"kismet.alert.list": [
    {"kismet.alert.header": "DEAUTHFLOOD", "kismet.alert.transmitter_mac": "AA:BB:CC:00:11:22",
     "kismet.alert.text": "Deauth flood\n  detected " + "x" * 400, "kismet.alert.timestamp": 1700000100},
    {"kismet.alert.header": "NEWTHING", "kismet.alert.text": "benign"},
    {"kismet.alert.header": "BCASTDISCON", "kismet.alert.source_mac": "00:00:00:00:00:00"},
]}


class ArgvTests(unittest.TestCase):
    def test_devices_argv(self):
        a = kp.devices_argv(HW, 20)
        self.assertEqual(a[0], "curl")
        self.assertIn("@/tmp/k.header", a)
        self.assertIn("--fail", a)
        self.assertTrue(a[-1].endswith("/devices/last-time/-20/devices.json"))
        body = a[a.index("-d") + 1]
        self.assertTrue(body.startswith("json="))
        fields = json.loads(body[5:])["fields"]
        self.assertIn("kismet.device.base.macaddr", fields)

    def test_alerts_argv_and_no_key(self):
        a = kp.alerts_argv(HW)
        self.assertTrue(a[-1].endswith("/alerts/last-time/-15/alerts.json"))
        self.assertNotIn(SECRET, " ".join(a + kp.devices_argv(HW)))
        self.assertNotIn("Cookie", " ".join(a + kp.devices_argv(HW)))

    def test_default_header(self):
        self.assertIn(f"@{kp.DEFAULT_HEADER_FILE}", kp.devices_argv({}))


class ParseTests(unittest.TestCase):
    def test_devices(self):
        r = kp.parse_devices(json.dumps(DEVICES))
        self.assertEqual(len(r), 2)
        ap, cl = r
        self.assertEqual((ap["dev_id"], ap["kind"], ap["name"], ap["rssi"]),
                         ("aa:bb:cc:00:11:22", "ap", "HomeNet", -47))
        self.assertEqual((ap["lat"], ap["lon"]), (28.0, -82.5))
        self.assertEqual(ap["radio"], "wifi")
        self.assertEqual(cl["kind"], "client")
        self.assertIsNone(cl["lat"])
        self.assertIsNone(cl["rssi"])

    def test_devices_garbage(self):
        for g in ("", "nope", "{}", "null", None, "[1,2]"):
            self.assertEqual(kp.parse_devices(g), [])

    def test_alerts(self):
        r = kp.parse_alerts(json.dumps(ALERTS))
        self.assertEqual([a["kind"] for a in r], ["DEAUTHFLOOD", "BCASTDISCON"])
        self.assertEqual(r[0]["dev_id"], "aa:bb:cc:00:11:22")
        self.assertLessEqual(len(r[0]["detail"]), 200)
        self.assertNotIn("\n", r[0]["detail"])
        self.assertIsNone(r[1]["dev_id"])
        self.assertTrue(all(a["severity"] == "medium" for a in r))

    def test_alerts_list_and_garbage(self):
        self.assertEqual(len(kp.parse_alerts(json.dumps(ALERTS["kismet.alert.list"]))), 2)
        for g in ("", "x", "{}", None):
            self.assertEqual(kp.parse_alerts(g), [])

    def test_bucket(self):
        self.assertEqual(kp.alert_bucket(0), 0)
        self.assertEqual(kp.alert_bucket(599), 0)
        self.assertEqual(kp.alert_bucket(600), 1)
        self.assertEqual(kp.alert_bucket(None), 0)


class RfTests(unittest.TestCase):
    def test_sweep_argv(self):
        a = rf_floor.sweep_argv("433", gain_db=25, seconds=8)
        self.assertEqual(a[0], "rtl_power")
        self.assertEqual(a[a.index("-g") + 1], "25")
        self.assertEqual(a[a.index("-i") + 1], "2")
        self.assertEqual(a[a.index("-e") + 1], "8s")
        self.assertTrue(a[a.index("-f") + 1].startswith("432M:435M:"))
        self.assertEqual(a[-1], "/dev/stdout")
        for k in rf_floor.BANDS:
            self.assertIn("-g", rf_floor.sweep_argv(k))

    def test_medians(self):
        out = ("2026-01-01, 00:00:00, 432000000, 433000000, 5000, 10, -60.0, -50.0, -40.0\n"
               "2026-01-01, 00:00:02, 432000000, 433000000, 5000, 10, -70.0, nan, bad\n")
        r = rf_floor.parse_medians(out)
        self.assertEqual(r["bins"], 4)
        self.assertEqual(r["median_db"], -55.0)
        self.assertEqual(rf_floor.parse_medians("garbage\n"), {"median_db": None, "bins": 0})
        self.assertEqual(rf_floor.parse_medians(None), {"median_db": None, "bins": 0})


class ExportTests(unittest.TestCase):
    def test_argv(self):
        self.assertEqual(export.wigle_argv("a.kismet", "o.csv"),
                         ["kismetdb_to_wiglecsv", "--in", "a.kismet", "--out", "o.csv", "--force"])
        self.assertEqual(export.kml_argv("a.kismet", "o.kml")[0], "kismetdb_to_kml")

    def test_newest(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(export.newest_kismetdb(d))
            a, b, c = (os.path.join(d, n) for n in ("a.kismet", "b.kismet", "c.txt"))
            for p, t in ((a, 1000), (b, 2000), (c, 3000)):
                open(p, "w").close()
                os.utime(p, (t, t))
            self.assertEqual(export.newest_kismetdb(d), b)
            self.assertEqual(export.newest_kismetdb(d, since_ts=2500), None)
            self.assertEqual(export.newest_kismetdb(d, since_ts=1500), b)
            self.assertIsNone(export.newest_kismetdb(os.path.join(d, "missing")))

    def test_ble_csv_hostile(self):
        rows = [{"dev_id": "x1", "name": 'a,b "q"', "kind": "ble", "tracker": "airtag",
                 "first_seen": 1, "last_seen": 2, "best_rssi": -50, "lat": 28.0, "lon": -82.0},
                {"dev_id": "x2", "name": "=cmd|' /C calc'!A0", "kind": "+1", "tracker": "-2",
                 "first_seen": None, "last_seen": 2, "best_rssi": -60, "lat": None, "lon": None},
                {"dev_id": "x3", "name": "@SUM(1)"}]
        text = export.ble_csv(rows)
        parsed = list(csv.reader(io.StringIO(text)))
        self.assertEqual(parsed[0], export.BLE_COLUMNS)
        self.assertEqual(parsed[1][1], 'a,b "q"')
        self.assertEqual(parsed[2][1], "'=cmd|' /C calc'!A0")
        self.assertEqual(parsed[2][2], "'+1")
        self.assertEqual(parsed[2][3], "'-2")
        self.assertEqual(parsed[3][1], "'@SUM(1)")
        self.assertEqual(export.ble_csv([]).strip(), ",".join(export.BLE_COLUMNS))


if __name__ == "__main__":
    unittest.main()
