import json
import unittest

from havokbox.scope import Scope
from havokbox.tools import DEFAULT_HW, ToolCtx, sdr

SCOPE = Scope({"name": "t", "auto_allow": [], "approval_required": []})
POWER = ("2026-11-17, 10:00:00, 24000000, 25000000, 1000000.00, 10, -40.1, -55.0\n"
         "2026-11-17, 10:00:10, 24000000, 25000000, 1000000.00, 10, -42.0, -30.5\n"
         "junk\n"
         "2026-11-17, 10:00:10, abc, def, ghi, 1, x\n")
R433 = "\n".join([
    "rtl_433 version 23.11",
    json.dumps({"time": "2026-11-17 10:00:01", "model": "Acurite-Tower", "id": 1234, "channel": "A",
                "temperature_C": 20.1, "rssi": -12.3, "raw": "x" * 500}),
    json.dumps({"time": "2026-11-17 10:00:05", "model": "Acurite-Tower", "id": 1234, "channel": "A", "rssi": -11.0}),
    json.dumps({"time": "2026-11-17 10:00:06", "model": "Other", "id": 7}),
    "{bad json",
    "",
])


class SdrTest(unittest.TestCase):
    def test_parse_survey(self):
        d = sdr.parse_survey(POWER, 24, 25)
        self.assertEqual(d["range"], [24, 25])
        self.assertEqual(d["top"][0], {"mhz": 25.0, "db": -30.5})
        self.assertEqual(d["top"][1]["mhz"], 24.0)
        self.assertEqual(d["top"][1]["db"], -40.1)
        self.assertEqual(d["noise_floor_db"], -35.3)

    def test_parse_survey_garbage(self):
        d = sdr.parse_survey("nope\n,,,\n")
        self.assertEqual(d["top"], [])
        self.assertIsNone(d["noise_floor_db"])
        self.assertEqual(sdr.parse_survey("")["top"], [])

    def test_build_survey_defaults(self):
        self.assertEqual(sdr.build_survey({}, "standard", SCOPE, DEFAULT_HW),
                         [["rtl_power", "-f", "24M:1700M:1M", "-i", "10", "-e", "60s", "/dev/stdout"]])

    def test_build_survey_custom(self):
        argv = sdr.build_survey({"start_mhz": 88.5, "end_mhz": 108, "seconds": 30}, "standard", SCOPE, DEFAULT_HW)[0]
        self.assertIn("88.5M:108M:1M", argv)
        self.assertIn("30s", argv)

    def test_survey_start_ge_end_refused(self):
        for t in ({"start_mhz": 500, "end_mhz": 500}, {"start_mhz": 900, "end_mhz": 100}):
            with self.assertRaises(ValueError):
                sdr.build_survey(t, "standard", SCOPE, DEFAULT_HW)

    def test_survey_runs_build_argv(self):
        rec = []
        ctx = ToolCtx(runner=lambda a: (rec.append(a), POWER)[1], mode="standard", scope=SCOPE)
        t = {"start_mhz": 24, "end_mhz": 25, "seconds": 10}
        res = sdr.survey({"target": t}, ctx)
        self.assertEqual(rec, sdr.build_survey(t, "standard", SCOPE, ctx.hw))
        self.assertEqual((res["space"], res["kind"]), ("sdr", "spectrum"))

    def test_survey_garbage_output(self):
        ctx = ToolCtx(runner=lambda a: "", mode="standard", scope=SCOPE)
        self.assertEqual(sdr.survey({"target": {}}, ctx)["data"]["top"], [])

    def test_parse_decode(self):
        devs = sdr.parse_decode(R433)
        self.assertEqual(len(devs), 2)
        a = devs[0]
        self.assertEqual((a["model"], a["id"], a["channel"], a["count"]), ("Acurite-Tower", 1234, "A", 2))
        self.assertEqual(a["last"], "2026-11-17 10:00:05")
        self.assertEqual(a["rssi"], -11.0)
        self.assertNotIn("raw", a)
        self.assertEqual(sdr.parse_decode("garbage"), [])
        self.assertEqual(sdr.parse_decode(""), [])

    def test_build_decode_defaults_and_run(self):
        exp = [["rtl_433", "-F", "json", "-M", "level", "-T", "60", "-f", "433.92M"]]
        self.assertEqual(sdr.build_decode({}, "standard", SCOPE, DEFAULT_HW), exp)
        rec = []
        ctx = ToolCtx(runner=lambda a: (rec.append(a), R433)[1], mode="standard", scope=SCOPE)
        res = sdr.decode({"target": {}}, ctx)
        self.assertEqual(rec, exp)
        self.assertEqual((res["space"], res["kind"]), ("sdr", "iot_devices"))
        self.assertEqual(len(res["data"]["devices"]), 2)

    def test_decode_freq_seconds(self):
        argv = sdr.build_decode({"freq": "915M", "seconds": 20}, "standard", SCOPE, DEFAULT_HW)[0]
        self.assertEqual(argv[-1], "915M")
        self.assertEqual(argv[argv.index("-T") + 1], "20")


if __name__ == "__main__":
    unittest.main()
