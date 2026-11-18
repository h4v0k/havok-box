import unittest

from havokbox.scope import Scope
from havokbox.tools import ToolCtx, kismet

DEVICES = [
    {"type": "AP", "ssid": "LAB-NET", "bssid": "AA:BB:CC:DD:EE:FF", "channel": 6},
    {"type": "AP", "ssid": "LAB-NET", "bssid": "11:22:33:44:55:66", "channel": 6},
    {"type": "AP", "ssid": "Neighbor", "bssid": "99:99:99:99:99:99", "channel": 1},
    {"type": "Wi-Fi Client", "bssid": "de:ad:be:ef:00:01"},
]

SCOPE = Scope({
    "name": "lab", "networks": {"include": ["10.10.0.0/24"]},
    "wifi": {"ssids": ["LAB-NET"], "bssids": ["aa:bb:cc:dd:ee:ff"]},
    "auto_allow": ["recon.passive"], "approval_required": [],
})


class KismetTest(unittest.TestCase):
    def test_parse_splits_aps_and_clients(self):
        aps, clients = kismet.parse_devices(DEVICES)
        self.assertEqual(len(aps), 3)
        self.assertEqual(len(clients), 1)

    def test_evil_twin_detected(self):
        aps, _ = kismet.parse_devices(DEVICES)
        twins = kismet.detect_evil_twins(aps, {"LAB-NET"}, {"aa:bb:cc:dd:ee:ff"})
        self.assertEqual(len(twins), 1)
        self.assertEqual(twins[0]["bssid"], "11:22:33:44:55:66")

    def test_scan_summary_flags_twin(self):
        import json
        ctx = ToolCtx(runner=lambda cmd: json.dumps(DEVICES), mode="stealth", scope=SCOPE)
        res = kismet.scan({"target": {}}, ctx)
        self.assertEqual(res["space"], "wifi")
        self.assertIn("evil twin", res["summary"])
        self.assertEqual(len(res["data"]["evil_twins"]), 1)


if __name__ == "__main__":
    unittest.main()


class KismetAuthTest(unittest.TestCase):
    def test_key_read_from_file_never_in_argv(self):
        from havokbox.tools import kismet
        argv = kismet.build_cmd({"kismet_header": "/data/x/kismet.header"})
        self.assertIn("@/data/x/kismet.header", argv)
        self.assertIn("--fail", argv)
        self.assertFalse(any("KISMET=" in a for a in argv))

    def test_no_output_says_key_not_set(self):
        from havokbox.tools import ToolCtx, kismet
        ctx = ToolCtx(runner=lambda cmd: "", mode="stealth", scope=Scope({}))
        r = kismet.scan({"target": {}}, ctx)
        self.assertIn("API key", r["summary"])
        self.assertEqual(r["data"]["error"], "kismet_unavailable")
        ctx.runner = lambda cmd: "<html>401</html>"
        self.assertEqual(kismet.scan({"target": {}}, ctx)["data"]["error"], "kismet_unavailable")
