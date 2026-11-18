import json
import unittest

from havokbox.helpers import flipper as fh
from havokbox.tools import flipper as ftool


class FakeSession:
    """Scripted fake serial session: queues of canned replies, keyed loosely by command."""

    def __init__(self, script: dict, default: str = ""):
        self.script = script
        self.default = default
        self.sent = []

    def send(self, line):
        self.sent.append(line)

    def read_for(self, seconds):
        return self._reply_for_last_send()

    def read_until(self, prompt=None, timeout=10.0):
        return self._reply_for_last_send()

    def send_ctrl_c(self):
        self.sent.append("^C")

    def close(self):
        pass

    def _reply_for_last_send(self):
        last = self.sent[-1] if self.sent else ""
        for key, reply in self.script.items():
            if key in last:
                return reply
        return self.default


class RecordingRunner:
    def __init__(self, stdout="{}"):
        self.calls = []
        self.stdout = stdout

    def __call__(self, argv):
        self.calls.append(argv)
        return self.stdout


RX_TEXT = "Princeton 24bit Key:0x00ABCDEF\nsome noise\n"
LISTING = "[F] frontdoor.sub\n[F] bad name here.sub\n[F] gate_open.sub\n"
SUB_BODY_433 = "Filetype: Flipper SubGhz Key File\nVersion: 1\nFrequency: 433920000\nPreset: FuriHalSubGhzPresetOok270Async\n"
SUB_BODY_315 = "Filetype: Flipper SubGhz Key File\nVersion: 1\nFrequency: 315000000\n"


class ParseReceivedTest(unittest.TestCase):
    def test_parses_protocol_bits_key(self):
        out = fh.parse_received(RX_TEXT)
        self.assertTrue(any(r.get("protocol") == "Princeton" and r.get("bits") == 24 for r in out))


class ParseListingTest(unittest.TestCase):
    def test_skips_bad_names(self):
        names = fh.parse_listing(LISTING)
        self.assertIn("frontdoor", names)
        self.assertIn("gate_open", names)
        self.assertNotIn("bad name here", names)


class ScanHelperTest(unittest.TestCase):
    def test_scan_collects_captures(self):
        script = {
            "subghz rx": RX_TEXT,
            "storage list /ext/subghz": LISTING,
            "storage read /ext/subghz/frontdoor.sub": SUB_BODY_433,
            "storage read /ext/subghz/gate_open.sub": SUB_BODY_315,
        }
        session = FakeSession(script)
        result = fh.scan(session, 433.92, 5)
        ids = {c["id"] for c in result["captures"]}
        self.assertEqual(ids, {"frontdoor", "gate_open"})
        freqs = {c["id"]: c["freq_mhz"] for c in result["captures"]}
        self.assertAlmostEqual(freqs["frontdoor"], 433.92, places=2)
        self.assertAlmostEqual(freqs["gate_open"], 315.0, places=2)
        self.assertTrue(result["received"])


class ReplayHelperTest(unittest.TestCase):
    def test_refused_on_frequency_mismatch(self):
        session = FakeSession({"storage read /ext/subghz/frontdoor.sub": SUB_BODY_315})
        result = fh.replay(session, "frontdoor", 433.92)
        self.assertEqual(result["status"], "refused")
        self.assertFalse(any("tx_from_file" in s for s in session.sent))

    def test_refused_on_missing_file(self):
        session = FakeSession({})  # no Frequency line anywhere -> default ""
        result = fh.replay(session, "frontdoor", 433.92)
        self.assertEqual(result["status"], "refused")
        self.assertFalse(any("tx_from_file" in s for s in session.sent))

    def test_replay_ok_path(self):
        script = {
            "storage read /ext/subghz/frontdoor.sub": SUB_BODY_433,
        }
        session = FakeSession(script, default="OK\n>: ")
        result = fh.replay(session, "frontdoor", 433.92)
        self.assertEqual(result["status"], "transmitted")
        self.assertTrue(any("tx_from_file /ext/subghz/frontdoor.sub" in s for s in session.sent))

    def test_refuses_bad_id_without_touching_session(self):
        session = FakeSession({})
        result = fh.replay(session, "../etc/passwd", 433.92)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(session.sent, [])


class ToolFnRunsBuildArgvTest(unittest.TestCase):
    def test_scan_fn_runs_exactly_build_argv(self):
        runner = RecordingRunner(json.dumps({"received": [], "captures": []}))

        class Ctx:
            mode = "standard"
            scope = None
            hw = {"flipper_port": "/dev/ttyACM0"}
            def __init__(self, r):
                self.runner = r

        ctx = Ctx(runner)
        task = {"target": {"freq_mhz": 433.92, "seconds": 10}}
        expected = ftool.build_scan(task["target"], ctx.mode, ctx.scope, ctx.hw)
        result = ftool.scan(task, ctx)
        self.assertEqual(runner.calls, expected)
        self.assertEqual(result["space"], "subghz")
        self.assertEqual(result["kind"], "subghz")

    def test_replay_fn_runs_exactly_build_argv(self):
        runner = RecordingRunner(json.dumps({"status": "transmitted", "id": "frontdoor"}))

        class Ctx:
            mode = "standard"
            scope = None
            hw = {"flipper_port": "/dev/ttyACM0"}
            def __init__(self, r):
                self.runner = r

        ctx = Ctx(runner)
        task = {"target": {"id": "frontdoor", "freq_mhz": 433.92}}
        expected = ftool.build_replay(task["target"], ctx.mode, ctx.scope, ctx.hw)
        result = ftool.replay(task, ctx)
        self.assertEqual(runner.calls, expected)
        self.assertEqual(result["kind"], "replay")

    def test_garbage_helper_output_never_crashes(self):
        runner = RecordingRunner("not json at all")

        class Ctx:
            mode = "standard"
            scope = None
            hw = {"flipper_port": "/dev/ttyACM0"}
            def __init__(self, r):
                self.runner = r

        ctx = Ctx(runner)
        result = ftool.scan({"target": {}}, ctx)
        self.assertEqual(result["data"]["received"], [])


if __name__ == "__main__":
    unittest.main()
