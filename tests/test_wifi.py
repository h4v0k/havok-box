import json
import unittest

from havokbox.helpers import wifi_capture as wc
from havokbox.scope import Scope
from havokbox.tools import ToolCtx, wifi

SCOPE = Scope({
    "name": "lab", "networks": {"include": ["10.10.0.0/24"]},
    "wifi": {"ssids": ["LAB-NET"], "bssids": ["aa:bb:cc:dd:ee:ff"]},
    "auto_allow": ["recon.passive"], "approval_required": ["wifi.capture", "wifi.deauth"],
})

HW = {"wifi_mon_iface": "wlan1mon", "work_dir": "/data/havokbox/work"}

AIRODUMP_CSV = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, "
    "Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
    "AA:BB:CC:DD:EE:FF, 2026-01-01 00:00:00, 2026-01-01 00:01:00, 6, 54, WPA2, CCMP, PSK, "
    "-40, 100, 0, 0.0.0.0, 7, LAB-NET, \r\n"
    "\r\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n"
    "11:22:33:44:55:66, 2026-01-01 00:00:00, 2026-01-01 00:01:00, -55, 42, AA:BB:CC:DD:EE:FF, \r\n"
)

AIRCRACK_HIT = "   #  BSSID              ESSID                     Encryption\n\n   1  AA:BB:CC:DD:EE:FF  LAB-NET                   WPA (1 handshake)\n"
AIRCRACK_MISS = "   #  BSSID              ESSID                     Encryption\n\n   1  AA:BB:CC:DD:EE:FF  LAB-NET                   WPA (0 handshake)\n"

AIREPLAY_OUT = "22:10:05  Sending 64 directed DeAuth. STMAC: [FF:FF:FF:FF:FF:FF] [123|45 ACKs]\n64 packets sent.\n"


# ---------------------------------------------------------------- helper: parsing

class HelperParsingTest(unittest.TestCase):
    def test_parse_airodump_csv_ap_and_station(self):
        out = wc.parse_airodump_csv(AIRODUMP_CSV, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(out["ap"]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(out["ap"]["channel"], 6)
        self.assertEqual(out["ap"]["ssid"], "LAB-NET")
        self.assertEqual(len(out["clients"]), 1)
        self.assertEqual(out["clients"][0]["mac"], "11:22:33:44:55:66")
        self.assertEqual(out["clients"][0]["packets"], 42)

    def test_parse_airodump_csv_unknown_bssid(self):
        out = wc.parse_airodump_csv(AIRODUMP_CSV, "ff:ff:ff:ff:ff:ff")
        self.assertIsNone(out["ap"])
        self.assertEqual(out["clients"], [])

    def test_parse_handshake_count_hit(self):
        self.assertEqual(wc.parse_handshake_count(AIRCRACK_HIT), 1)

    def test_parse_handshake_count_miss(self):
        self.assertEqual(wc.parse_handshake_count(AIRCRACK_MISS), 0)

    def test_parse_handshake_count_garbage(self):
        self.assertEqual(wc.parse_handshake_count("not aircrack output at all"), 0)

    def test_parse_deauth_sent(self):
        self.assertEqual(wifi.parse_deauth_sent(AIREPLAY_OUT), 64)

    def test_parse_deauth_sent_garbage(self):
        self.assertEqual(wifi.parse_deauth_sent(""), 0)


# ---------------------------------------------------------------- helper: validation

class HelperValidationTest(unittest.TestCase):
    def test_validate_bssid_rejects_bad(self):
        with self.assertRaises(wc.HelperError):
            wc.validate_bssid("not-a-mac")

    def test_validate_channel_bounds(self):
        with self.assertRaises(wc.HelperError):
            wc.validate_channel(0)
        with self.assertRaises(wc.HelperError):
            wc.validate_channel(197)
        self.assertEqual(wc.validate_channel(6), 6)

    def test_validate_seconds_bounds(self):
        with self.assertRaises(wc.HelperError):
            wc.validate_seconds(5, 10, 600)
        self.assertEqual(wc.validate_seconds(60, 10, 600), 60)


# ---------------------------------------------------------------- helper: argv builders

class HelperArgvTest(unittest.TestCase):
    def test_airodump_watch_argv(self):
        argv = wc.airodump_watch_argv("wlan1mon", "aa:bb:cc:dd:ee:ff", 6, "/tmp/x/cap")
        self.assertEqual(argv, ["airodump-ng", "--bssid", "aa:bb:cc:dd:ee:ff", "-c", "6",
                                 "--output-format", "csv", "-w", "/tmp/x/cap", "wlan1mon"])

    def test_airodump_pcap_argv(self):
        argv = wc.airodump_pcap_argv("wlan1mon", "aa:bb:cc:dd:ee:ff", 6, "/tmp/x/cap")
        self.assertIn("pcap", argv)

    def test_aireplay_deauth_argv_broadcast(self):
        argv = wc.aireplay_deauth_argv("wlan1mon", "aa:bb:cc:dd:ee:ff", 3, None)
        self.assertEqual(argv, ["aireplay-ng", "-0", "3", "-a", "aa:bb:cc:dd:ee:ff", "wlan1mon"])

    def test_aireplay_deauth_argv_targeted(self):
        argv = wc.aireplay_deauth_argv("wlan1mon", "aa:bb:cc:dd:ee:ff", 3, "11:22:33:44:55:66")
        self.assertIn("-c", argv)
        self.assertIn("11:22:33:44:55:66", argv)


# ---------------------------------------------------------------- helper: do_* with fake runner/popen

class FakeProc:
    def __init__(self):
        self.terminated = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0


class HelperDoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = __import__("tempfile").mkdtemp()

    def _write_csv(self, session_dir):
        import os
        os.makedirs(session_dir, exist_ok=True)
        path = __import__("os").path.join(session_dir, "cap-01.csv")
        with open(path, "w", newline="") as f:
            f.write(AIRODUMP_CSV)
        return path

    def test_do_watch_happy_path(self):
        calls = []

        def runner(argv, timeout):
            calls.append((argv, timeout))
            session_dir = __import__("os").path.dirname(argv[argv.index("-w") + 1])
            self._write_csv(session_dir)
            return ""

        result = wc.do_watch("wlan1mon", "AA:BB:CC:DD:EE:FF", 6, 60, self.tmp, runner=runner,
                              clock=lambda: 0)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["kind"], "ap_watch")
        self.assertEqual(result["ap"]["ssid"], "LAB-NET")
        self.assertEqual(len(result["clients"]), 1)
        self.assertEqual(calls[0][1], 60)

    def test_do_watch_no_output_is_error(self):
        result = wc.do_watch("wlan1mon", "aa:bb:cc:dd:ee:ff", 6, 10, self.tmp,
                              runner=lambda argv, timeout: "", clock=lambda: 0)
        self.assertEqual(result["status"], "error")

    def test_do_capture_handshake(self):
        import os

        def runner(argv, timeout):
            if argv[0] == "airodump-ng":
                session_dir = os.path.dirname(argv[argv.index("-w") + 1])
                os.makedirs(session_dir, exist_ok=True)
                with open(os.path.join(session_dir, "cap-01.cap"), "wb") as f:
                    f.write(b"\x00\x01")
                return ""
            if argv[0] == "aircrack-ng":
                return AIRCRACK_HIT
            raise AssertionError(argv)

        result = wc.do_capture("wlan1mon", "aa:bb:cc:dd:ee:ff", 6, 30, self.tmp, runner=runner,
                                clock=lambda: 0)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["handshake"])
        self.assertTrue(result["sha256"])

    def test_do_capture_deauth_sends_deauth_between_watch_window(self):
        import os

        popen_calls = []
        runner_calls = []
        sleep_calls = []

        def popen(argv):
            popen_calls.append(argv)
            session_dir = os.path.dirname(argv[argv.index("-w") + 1])
            os.makedirs(session_dir, exist_ok=True)
            with open(os.path.join(session_dir, "cap-01.cap"), "wb") as f:
                f.write(b"\x00\x01")
            return FakeProc()

        def runner(argv, timeout):
            runner_calls.append(argv)
            return AIRCRACK_HIT if argv[0] == "aircrack-ng" else AIREPLAY_OUT

        result = wc.do_capture_deauth("wlan1mon", "aa:bb:cc:dd:ee:ff", 6, 90, self.tmp, count=3,
                                       client="11:22:33:44:55:66", popen=popen, runner=runner,
                                       sleep=sleep_calls.append, clock=lambda: 0)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["deauth_sent"], 3)
        self.assertTrue(result["handshake"])
        self.assertEqual(popen_calls[0][0], "airodump-ng")
        self.assertEqual(runner_calls[0][0], "aireplay-ng")
        self.assertEqual(sleep_calls, [5, 85])


# ---------------------------------------------------------------- tool fns: build is what fn runs

class Recorder:
    def __init__(self, response="{}"):
        self.cmds = []
        self.response = response

    def __call__(self, cmd):
        self.cmds.append(cmd)
        return self.response


class WifiWatchTest(unittest.TestCase):
    def test_build_watch_defaults_and_hw(self):
        argv, = wifi.build_watch({"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}, "standard", SCOPE, HW)
        self.assertEqual(argv[:3], ["python3", "-m", "havokbox.helpers.wifi_capture"])
        self.assertIn("watch", argv)
        self.assertIn("wlan1mon", argv)
        self.assertIn("60", argv)  # default seconds
        self.assertIn("/data/havokbox/work", argv)

    def test_build_watch_explicit_seconds(self):
        argv, = wifi.build_watch({"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "seconds": 120},
                                  "standard", SCOPE, HW)
        self.assertIn("120", argv)

    def test_watch_fn_runs_exactly_build_argv(self):
        payload = json.dumps({"ap": {"bssid": "aa:bb:cc:dd:ee:ff"}, "clients": [{"mac": "x"}]})
        runner = Recorder(payload)
        ctx = ToolCtx(runner=runner, mode="standard", scope=SCOPE, hw=HW)
        target = {"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}
        res = wifi.watch({"target": target}, ctx)
        expected, = wifi.build_watch(target, ctx.mode, ctx.scope, ctx.hw)
        self.assertEqual(runner.cmds, [expected])
        self.assertEqual(res["space"], "wifi")
        self.assertEqual(res["kind"], "ap_watch")
        self.assertEqual(len(res["data"]["clients"]), 1)

    def test_watch_fn_tolerates_garbage_output(self):
        runner = Recorder("not json")
        ctx = ToolCtx(runner=runner, mode="standard", scope=SCOPE, hw=HW)
        res = wifi.watch({"target": {"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}}, ctx)
        self.assertEqual(res["data"]["clients"], [])


class WifiCaptureTest(unittest.TestCase):
    def test_build_capture_default_seconds(self):
        argv, = wifi.build_capture({"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}, "standard", SCOPE, HW)
        self.assertIn("capture", argv)
        self.assertIn("120", argv)

    def test_capture_fn_runs_exactly_build_argv(self):
        payload = json.dumps({"file": "/data/havokbox/work/x.cap", "handshake": True, "sha256": "abc"})
        runner = Recorder(payload)
        ctx = ToolCtx(runner=runner, mode="standard", scope=SCOPE, hw=HW)
        target = {"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "seconds": 90}
        res = wifi.capture({"target": target}, ctx)
        expected, = wifi.build_capture(target, ctx.mode, ctx.scope, ctx.hw)
        self.assertEqual(runner.cmds, [expected])
        self.assertTrue(res["data"]["handshake"])
        self.assertIn("handshake captured", res["summary"])


class WifiCaptureDeauthTest(unittest.TestCase):
    def test_build_capture_deauth_client_optional(self):
        argv, = wifi.build_capture_deauth({"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}, "standard",
                                           SCOPE, HW)
        self.assertNotIn("--client", argv)
        self.assertIn("3", argv)  # default count

    def test_build_capture_deauth_with_client(self):
        argv, = wifi.build_capture_deauth(
            {"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "client": "11:22:33:44:55:66", "count": 5},
            "standard", SCOPE, HW)
        self.assertIn("--client", argv)
        self.assertIn("11:22:33:44:55:66", argv)
        self.assertIn("5", argv)

    def test_capture_deauth_fn_runs_exactly_build_argv(self):
        payload = json.dumps({"file": "/x.cap", "handshake": False, "sha256": "abc", "deauth_sent": 3})
        runner = Recorder(payload)
        ctx = ToolCtx(runner=runner, mode="standard", scope=SCOPE, hw=HW)
        target = {"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}
        res = wifi.capture_deauth({"target": target}, ctx)
        expected, = wifi.build_capture_deauth(target, ctx.mode, ctx.scope, ctx.hw)
        self.assertEqual(runner.cmds, [expected])
        self.assertEqual(res["data"]["deauth_sent"], 3)
        self.assertFalse(res["data"]["handshake"])


class WifiDeauthTest(unittest.TestCase):
    def test_build_deauth_broadcast(self):
        steps = wifi.build_deauth({"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}, "standard", SCOPE, HW)
        self.assertEqual(steps[0], ["iw", "dev", "wlan1mon", "set", "channel", "6"])
        self.assertEqual(steps[1], ["aireplay-ng", "-0", "5", "-a", "aa:bb:cc:dd:ee:ff", "wlan1mon"])

    def test_build_deauth_targeted(self):
        steps = wifi.build_deauth(
            {"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "client": "11:22:33:44:55:66", "count": 2},
            "standard", SCOPE, HW)
        self.assertIn("-c", steps[1])
        self.assertIn("11:22:33:44:55:66", steps[1])
        self.assertIn("2", steps[1])

    def test_deauth_fn_runs_exactly_build_argv_in_order(self):
        runner = Recorder(AIREPLAY_OUT)
        ctx = ToolCtx(runner=runner, mode="standard", scope=SCOPE, hw=HW)
        target = {"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6}
        res = wifi.deauth({"target": target}, ctx)
        expected = wifi.build_deauth(target, ctx.mode, ctx.scope, ctx.hw)
        self.assertEqual(runner.cmds, expected)
        self.assertEqual(res["data"]["sent"], 64)
        self.assertIn("broadcast", res["summary"])

    def test_deauth_fn_targeted_summary(self):
        runner = Recorder(AIREPLAY_OUT)
        ctx = ToolCtx(runner=runner, mode="standard", scope=SCOPE, hw=HW)
        target = {"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "client": "11:22:33:44:55:66"}
        res = wifi.deauth({"target": target}, ctx)
        self.assertIn("targeted", res["summary"])


if __name__ == "__main__":
    unittest.main()
