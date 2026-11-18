import json
import unittest

from havokbox.helpers import marauder as mh
from havokbox.tools import marauder as mtool


class FakeSession:
    def __init__(self, script: dict, default: str = ""):
        self.script = script
        self.default = default
        self.sent = []

    def send(self, line):
        self.sent.append(line)

    def read_for(self, seconds):
        last = self.sent[-1] if self.sent else ""
        for key, reply in self.script.items():
            if key in last:
                return reply
        return self.default

    def read_until(self, prompt=None, timeout=10.0):
        return self.read_for(0)

    def send_ctrl_c(self):
        self.sent.append("^C")

    def close(self):
        pass


class RecordingRunner:
    def __init__(self, stdout="{}"):
        self.calls = []
        self.stdout = stdout

    def __call__(self, argv):
        self.calls.append(argv)
        return self.stdout


AP_LIST = (
    "[0][CH:6] MyNet -48\n"
    "[1][CH:11] OtherNet -70 aa:bb:cc:dd:ee:ff\n"
    "garbage line that is not an ap\n"
)


class ParseApListTest(unittest.TestCase):
    def test_parses_channel_ssid_rssi_and_optional_bssid(self):
        aps = mh.parse_ap_list(AP_LIST)
        self.assertEqual(len(aps), 2)
        self.assertEqual(aps[0], {"index": 0, "channel": 6, "ssid": "MyNet", "rssi": -48})
        self.assertEqual(aps[1]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(aps[1]["channel"], 11)


class ScanHelperTest(unittest.TestCase):
    def test_scan_runs_expected_sequence(self):
        session = FakeSession({"list -a": AP_LIST})
        result = mh.scan(session, 5)
        self.assertEqual(session.sent, ["scanap", "stopscan", "list -a"])
        self.assertEqual(len(result["aps"]), 2)


class DeauthHelperTest(unittest.TestCase):
    def test_command_sequence(self):
        session = FakeSession({})
        result = mh.deauth(session, "aa:bb:cc:dd:ee:ff", 6, "ff:ff:ff:ff:ff:ff", 5)
        self.assertEqual(result["status"], "sent")
        self.assertEqual(session.sent, [
            "channel -s 6",
            "attack -t deauth -s aa:bb:cc:dd:ee:ff -d ff:ff:ff:ff:ff:ff",
            "stopscan",
        ])

    def test_bad_bssid_refused_without_touching_session(self):
        session = FakeSession({})
        result = mh.deauth(session, "not-a-mac", 6, "ff:ff:ff:ff:ff:ff", 5)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(session.sent, [])

    def test_bad_client_mac_refused(self):
        session = FakeSession({})
        result = mh.deauth(session, "aa:bb:cc:dd:ee:ff", 6, "not-a-mac", 5)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(session.sent, [])


class ToolFnRunsBuildArgvTest(unittest.TestCase):
    def test_scan_fn_runs_exactly_build_argv(self):
        runner = RecordingRunner(json.dumps({"aps": []}))

        class Ctx:
            mode = "standard"
            scope = None
            hw = {"marauder_port": "/dev/ttyUSB1"}
            def __init__(self, r):
                self.runner = r

        ctx = Ctx(runner)
        task = {"target": {"seconds": 15}}
        expected = mtool.build_scan(task["target"], ctx.mode, ctx.scope, ctx.hw)
        result = mtool.scan(task, ctx)
        self.assertEqual(runner.calls, expected)
        self.assertEqual(result["kind"], "esp_survey")

    def test_deauth_fn_runs_exactly_build_argv(self):
        runner = RecordingRunner(json.dumps({"status": "sent"}))

        class Ctx:
            mode = "standard"
            scope = None
            hw = {"marauder_port": "/dev/ttyUSB1"}
            def __init__(self, r):
                self.runner = r

        ctx = Ctx(runner)
        task = {"target": {"bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "seconds": 8}}
        expected = mtool.build_deauth(task["target"], ctx.mode, ctx.scope, ctx.hw)
        result = mtool.deauth(task, ctx)
        self.assertEqual(runner.calls, expected)
        self.assertEqual(result["kind"], "deauth")

    def test_garbage_helper_output_never_crashes(self):
        runner = RecordingRunner("not json")

        class Ctx:
            mode = "standard"
            scope = None
            hw = {"marauder_port": "/dev/ttyUSB1"}
            def __init__(self, r):
                self.runner = r

        ctx = Ctx(runner)
        result = mtool.scan({"target": {}}, ctx)
        self.assertEqual(result["data"]["aps"], [])


class StopTests(unittest.TestCase):
    def test_stop_sends_stopscan(self):
        s = FakeSession({})
        out = mh.stop(s)
        self.assertEqual(s.sent, ["stopscan"])
        self.assertEqual(out["status"], "stopped")


if __name__ == "__main__":
    unittest.main()
