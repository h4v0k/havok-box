import json
import os
import tempfile
import unittest

from havokbox.helpers import ble_scan
from havokbox.scope import Scope
from havokbox.tools import DEFAULT_HW, ToolCtx, ble

TSHARK = ("aa:bb:cc:dd:ee:01\tTag One\t-60\n"
          "aa:bb:cc:dd:ee:01\t\t-45\n"
          "AA:BB:CC:DD:EE:02\t\t-80\n"
          "garbage line\n\n")
GATT = ("attr handle = 0x0001, end grp handle = 0x0007 uuid: 00001800-0000-1000-8000-00805f9b34fb\n"
        "attr handle = 0x0008, end grp handle = 0x000b uuid: 0000180f-0000-1000-8000-00805f9b34fb\n"
        "attr handle = 0x000c, end grp handle = 0xffff uuid: 6e400001-b5a3-f393-e0a9-e50e24dcca9e\n"
        "Connecting... \n")
SCOPE = Scope({"name": "t", "auto_allow": [], "approval_required": []})


class BleHelperTest(unittest.TestCase):
    def test_parse_dedupe_strongest(self):
        d = ble_scan.parse_tshark_fields(TSHARK)
        self.assertEqual(len(d), 2)
        self.assertEqual(d[0]["addr"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(d[0]["rssi"], -45)
        self.assertEqual(d[0]["name"], "Tag One")
        self.assertEqual(d[0]["seen"], 2)

    def test_service_data_field(self):
        long = "ab" * 100
        row = "aa:bb:cc:dd:ee:09\t\t-50\t\t\t\t\t\tfaff0d01,0102\n"
        row2 = "aa:bb:cc:dd:ee:09\t\t-55\t\t\t\t\t\t" + long + "\n"
        d = ble_scan.parse_tshark_fields(row + row2)[0]
        self.assertEqual(d["service_data"][:2], ["faff0d01", "0102"])
        self.assertEqual(len(d["service_data"][2]), 128)
        self.assertEqual(ble_scan.parse_tshark_fields(TSHARK)[0]["service_data"], [])

    def test_service_data_last_in_argv(self):
        calls = []

        def runner(argv, timeout):
            calls.append(argv)
            return ""
        with tempfile.TemporaryDirectory() as w:
            ble_scan.scan("/opt/sniffle", "/dev/ttyUSB0", 5, w, runner=runner)
        self.assertEqual(calls[1][-1], "btcommon.eir_ad.entry.service_data")
        self.assertEqual(calls[1][-3], "btle.advertising_header.randomized_tx")

    def test_cap_64(self):
        txt = "".join(f"aa:bb:cc:dd:{i // 256:02x}:{i % 256:02x}\tn\t-50\n" for i in range(100))
        self.assertEqual(len(ble_scan.parse_tshark_fields(txt)), 64)

    def test_scan_with_fake_runner(self):
        calls = []

        def runner(argv, timeout):
            calls.append(argv)
            return TSHARK if argv[0] == "tshark" else ""
        with tempfile.TemporaryDirectory() as w:
            res = ble_scan.scan("/opt/sniffle", "/dev/ttyUSB0", 10, w, runner=runner)
            self.assertIsNone(res["pcap"])
            self.assertEqual(os.listdir(w), [])
        self.assertEqual(len(res["devices"]), 2)
        self.assertIn("-a", calls[0])
        self.assertEqual(calls[1][0], "tshark")
        self.assertTrue(all(isinstance(c, list) for c in calls))

    def test_argv_sniffle_passive_only(self):
        calls = []

        def runner(argv, timeout):
            calls.append(argv)
            return ""
        with tempfile.TemporaryDirectory() as w:
            ble_scan.scan("/opt/sniffle", "/dev/ttyUSB0", 5, w, runner=runner)
        flat = " ".join(" ".join(c) for c in calls).lower()
        for bad in ("scanner.py", "initiator", "relay"):
            self.assertNotIn(bad, flat)
        self.assertIn("sniff_receiver.py", " ".join(calls[0]))
        self.assertIn("-a", calls[0])

    def test_pcap_deleted_after_parse(self):
        def runner(argv, timeout):
            if "-o" in argv:
                open(argv[argv.index("-o") + 1], "wb").write(b"x")
            return TSHARK if argv[0] == "tshark" else ""
        with tempfile.TemporaryDirectory() as w:
            res = ble_scan.scan("/opt/sniffle", "/dev/ttyUSB0", 5, w, runner=runner)
            self.assertIsNone(res["pcap"])
            self.assertEqual(os.listdir(w), [])

    def test_parse_extended_fields(self):
        row = "aa:bb:cc:dd:ee:09\t\t-50\t\t0x004c,0x0006\t0xfeaa,0xfeed\t4c001219,aabb\t1\n"
        d = ble_scan.parse_tshark_fields(row)[0]
        self.assertEqual(d["company_ids"], [0x4C, 6])
        self.assertEqual(d["uuid16"], [0xFEAA, 0xFEED])
        self.assertEqual(d["mfg_data"], ["4c001219", "aabb"])
        self.assertTrue(d["random"])
        d0 = ble_scan.parse_tshark_fields(TSHARK)[0]
        self.assertEqual((d0["company_ids"], d0["mfg_data"], d0["random"]), ([], [], False))

    def test_port_validation(self):
        for bad in ("/etc/passwd", "ttyUSB0", "/dev/../etc/x"):
            with self.assertRaises(ValueError):
                ble_scan.validate_port(bad)
        self.assertEqual(ble_scan.validate_port("/dev/ttyUSB0"), "/dev/ttyUSB0")

    def test_empty_output(self):
        self.assertEqual(ble_scan.parse_tshark_fields(""), [])


class BleToolTest(unittest.TestCase):
    def test_build_scan_defaults(self):
        argv = ble.build_scan({}, "standard", SCOPE, DEFAULT_HW)[0]
        self.assertEqual(argv[:3], ["python3", "-m", "havokbox.helpers.ble_scan"])
        self.assertEqual(argv[argv.index("--seconds") + 1], "30")
        self.assertEqual(argv[argv.index("--port") + 1], DEFAULT_HW["sniffle_port"])

    def test_scan_runs_build_argv(self):
        rec = []
        out = json.dumps({"devices": [{"addr": "aa:bb:cc:dd:ee:01", "name": "x", "rssi": -50, "seen": 1}]})
        ctx = ToolCtx(runner=lambda a: (rec.append(a), out)[1], mode="standard", scope=SCOPE)
        res = ble.scan({"target": {"seconds": 20}}, ctx)
        self.assertEqual(rec, ble.build_scan({"seconds": 20}, "standard", SCOPE, ctx.hw))
        self.assertEqual((res["space"], res["kind"]), ("ble", "ble_devices"))
        self.assertEqual(len(res["data"]["devices"]), 1)

    def test_scan_garbage(self):
        ctx = ToolCtx(runner=lambda a: "not json", mode="standard", scope=SCOPE)
        self.assertEqual(ble.scan({"target": {}}, ctx)["data"]["devices"], [])

    def test_parse_gatt(self):
        s = ble.parse_gatt(GATT)
        self.assertEqual(len(s), 3)
        self.assertEqual(s[0]["name"], "Generic Access")
        self.assertEqual(s[1]["name"], "Battery")
        self.assertEqual(s[2]["name"], "Unknown")
        self.assertEqual(s[0]["start"], "0x0001")
        self.assertEqual(ble.parse_gatt("garbage"), [])
        self.assertEqual(ble.parse_gatt(""), [])

    def test_build_gatt_and_run(self):
        t = {"addr": "aa:bb:cc:dd:ee:01"}
        exp = [["timeout", "30", "gatttool", "-i", "hci0", "-b", t["addr"], "-t", "public", "--primary"]]
        self.assertEqual(ble.build_gatt(t, "standard", SCOPE, DEFAULT_HW), exp)
        rec = []
        ctx = ToolCtx(runner=lambda a: (rec.append(a), GATT)[1], mode="standard", scope=SCOPE)
        res = ble.gatt({"target": t}, ctx)
        self.assertEqual(rec, exp)
        self.assertEqual(res["kind"], "ble_gatt")
        self.assertEqual(len(res["data"]["services"]), 3)

    def test_gatt_random_type(self):
        argv = ble.build_gatt({"addr": "aa:bb:cc:dd:ee:01", "addr_type": "random"}, "standard", SCOPE, DEFAULT_HW)[0]
        self.assertEqual(argv[argv.index("-t") + 1], "random")


if __name__ == "__main__":
    unittest.main()
