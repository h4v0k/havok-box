import json
import os
import tempfile
import unittest

from havokbox.helpers import adsb
from havokbox.scope import Scope
from havokbox.tools import DEFAULT_HW, ToolCtx, air

SCOPE = Scope({"name": "t", "auto_allow": [], "approval_required": []})
AC = {"aircraft": [
    {"hex": "A1B2C3", "flight": "DAL12  ", "alt_baro": 35000, "gs": 450, "track": 90, "lat": 27.9,
     "lon": -82.4, "squawk": "1200", "seen": 0.5},
    {"hex": "abcdef", "altitude": 1000, "squawk": "7700", "seen": 2},
    {"hex": "000001", "alt_baro": "ground", "squawk": "7600", "lat": 1, "lon": 2},
    {"nohex": 1}, "junk"]}


class FakeProc:
    def __init__(self, argv, out_dir_holder):
        self.argv, self.terminated = argv, False
        out_dir_holder.append(argv[argv.index("--write-json") + 1])

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0


class AdsbHelperTest(unittest.TestCase):
    def test_run(self):
        dirs, procs, slept = [], [], []

        def popen(argv):
            p = FakeProc(argv, dirs)
            with open(os.path.join(dirs[0], "aircraft.json"), "w") as f:
                json.dump(AC, f)
            procs.append(p)
            return p
        with tempfile.TemporaryDirectory() as w:
            res = adsb.run("ADSB1", 30, w, runner=popen, sleep=slept.append)
            self.assertEqual(os.listdir(w), [])
            self.assertFalse(os.path.exists(dirs[0]))
        self.assertEqual(slept, [30])
        self.assertTrue(procs[0].terminated)
        a = procs[0].argv
        self.assertEqual(a[:6], ["readsb", "--device-type", "rtlsdr", "--device", "ADSB1", "--write-json"])
        self.assertEqual(a[-1], "--quiet")
        self.assertNotIn("--net", a)
        ac = res["aircraft"]
        self.assertEqual(len(ac), 3)
        self.assertEqual((ac[0]["flight"], ac[0]["alt"], ac[0]["hex"]), ("DAL12", 35000, "a1b2c3"))
        self.assertEqual(ac[1]["alt"], 1000)

    def test_missing_json_and_cap(self):
        with tempfile.TemporaryDirectory() as w:
            res = adsb.run("", 1, w, runner=lambda a: FakeProc(a, []), sleep=lambda s: None)
            self.assertEqual(res, {"aircraft": []})
            self.assertEqual(os.listdir(w), [])
        big = {"aircraft": [{"hex": f"{i:06x}"} for i in range(300)]}
        self.assertEqual(len(adsb.parse_aircraft(big)), 200)

    def test_bad_serial(self):
        with tempfile.TemporaryDirectory() as w:
            with self.assertRaises(ValueError):
                adsb.run("a b;", 1, w, runner=lambda a: None, sleep=lambda s: None)




class AirToolTest(unittest.TestCase):
    def test_build_adsb_serial_preference(self):
        hw = {**DEFAULT_HW, "sdr_serial": "MAIN", "sdr2_serial": "AIR2"}
        a = air.build_adsb({"seconds": 90}, "standard", SCOPE, hw)[0]
        self.assertEqual(a[a.index("--device") + 1], "AIR2")
        self.assertEqual(a[a.index("--seconds") + 1], "90")
        hw["sdr2_serial"] = ""
        self.assertEqual(air.build_adsb({}, "s", SCOPE, hw)[0][a.index("--device") + 1], "MAIN")
        self.assertEqual(air.build_adsb({}, "s", SCOPE, DEFAULT_HW)[0][a.index("--device") + 1], "0")
        self.assertIn("60", air.build_adsb({}, "s", SCOPE, DEFAULT_HW)[0])
        self.assertIn("600", air.build_adsb({"seconds": 9999}, "s", SCOPE, DEFAULT_HW)[0])

    def test_adsb_fn_and_emergencies(self):
        out = json.dumps({"aircraft": adsb.parse_aircraft(AC)})
        rec = []
        ctx = ToolCtx(runner=lambda a: (rec.append(a), out)[1], mode="standard", scope=SCOPE)
        res = air.adsb({"target": {}}, ctx)
        self.assertEqual(rec, air.build_adsb({}, "standard", SCOPE, ctx.hw))
        self.assertEqual((res["space"], res["kind"]), ("sdr2", "aircraft"))
        self.assertEqual(res["summary"], "3 aircraft, 2 with position, 2 emergency")
        self.assertEqual([e["squawk"] for e in res["data"]["emergencies"]], ["7700", "7600"])

    def test_adsb_garbage(self):
        ctx = ToolCtx(runner=lambda a: "oops", mode="standard", scope=SCOPE)
        res = air.adsb({"target": {}}, ctx)
        self.assertEqual(res["data"], {"aircraft": [], "emergencies": []})


if __name__ == "__main__":
    unittest.main()
