import os
import tempfile
import unittest

from havokbox.config import BoxConfig
from havokbox.store import Store
from havokbox.watchdog import SERVER_CMD, Watchdog, console_cmd


class FakeProc:
    def __init__(self, cmd):
        self.cmd, self.rc, self.terminated, self.killed = cmd, None, False, False

    def poll(self):
        return self.rc

    def terminate(self):
        self.terminated = True
        self.rc = -15

    def wait(self, timeout=None):
        return self.rc

    def kill(self):
        self.killed = True


class WatchdogTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "box.db")
        self.cfg = BoxConfig(db_path=self.db, token="t", session_limit_s=100)
        s = Store(self.db)
        s.grant_approval("pending-task", "recon.active", {"ip": "10.10.0.5"})
        s.grant_approval("used-task", "recon.active", {"ip": "10.10.0.6"})
        s.consume_approval("used-task")
        s.close()
        self.now = [0.0]
        self.procs = []
        self.powered_off = False

    def wd(self, **kw):
        def spawn(cmd):
            p = FakeProc(cmd); self.procs.append(p); return p
        return Watchdog(self.cfg, spawn=spawn, clock=lambda: self.now[0], sleep=lambda s: None,
                        poweroff=lambda: setattr(self, "powered_off", True), **kw)

    def approvals(self):
        s = Store(self.db)
        try:
            return {r["task_id"]: r["consumed"] for r in s.cx.execute("SELECT * FROM approvals")}
        finally:
            s.close()

    def evidence(self):
        s = Store(self.db)
        try:
            return s.evidence()
        finally:
            s.close()

    def test_boot_voids_unconsumed_and_starts_server(self):
        w = self.wd(); w.boot()
        self.assertEqual(set(self.approvals()), {"used-task"})
        self.assertEqual(self.procs[0].cmd, SERVER_CMD)
        self.assertEqual(len(self.procs), 1)   # console off by default

    def test_restart_on_crash_voids_again(self):
        w = self.wd(); w.boot()
        s = Store(self.db); s.grant_approval("t2", "recon.active", {}); s.close()
        self.procs[0].rc = 1
        self.assertTrue(w.tick())
        self.assertEqual(len(self.procs), 2)
        self.assertNotIn("t2", self.approvals())
        self.assertTrue(any("restarting" in e["detail"] for e in self.evidence()))

    def test_crash_loop_shuts_down(self):
        w = self.wd(max_restarts=2); w.boot()
        for _ in range(3):
            self.procs[-1].rc = 1
            alive = w.tick()
        self.assertFalse(alive)
        self.assertIn("crash loop", w.stop_reason)

    def test_session_limit_clean_shutdown(self):
        w = self.wd(); w.boot()
        self.now[0] = 99
        self.assertTrue(w.tick())
        self.now[0] = 100
        self.assertFalse(w.tick())
        self.assertTrue(self.procs[0].terminated)
        self.assertTrue(self.powered_off)
        self.assertTrue(any("clean shutdown" in e["detail"] for e in self.evidence()))
        self.assertFalse(w.tick())

    def test_console_only_when_enabled_with_token(self):
        self.assertIsNone(console_cmd(BoxConfig(token="t")))
        self.assertIsNone(console_cmd(BoxConfig(console_enabled=True, token="")))
        cmd = console_cmd(BoxConfig(console_enabled=True, token="t", console_iface="wlan0"))
        self.assertEqual(cmd[:5], ["ttyd", "-W", "-i", "wlan0", "-p"])
        self.assertIn("havok:t", cmd)
        self.cfg.console_enabled = True
        w = self.wd(); w.boot()
        self.assertEqual(self.procs[1].cmd[0], "ttyd")
        self.procs[1].rc = 0
        w.tick()
        self.assertEqual(self.procs[2].cmd[0], "ttyd")
        w.shutdown("test")
        self.assertTrue(self.procs[2].terminated)


class ConsoleSessionTest(unittest.TestCase):
    def test_session_logged_with_transcript_hash(self):
        from havokbox import console_session
        d = tempfile.mkdtemp()
        cfg = BoxConfig(db_path=os.path.join(d, "b.db"), evidence_dir=os.path.join(d, "ev"))
        ran = []

        def run(cmd):
            ran.append(cmd)
            with open(cmd[-1], "w") as fh:
                fh.write("whoami\n")
            return 0
        self.assertEqual(console_session.session(cfg, run=run, now=lambda: 0), 0)
        self.assertEqual(ran[0][:2], ["script", "-q"])
        s = Store(cfg.db_path)
        ev = [e["detail"] for e in s.evidence()]
        s.close()
        self.assertTrue(ev[0].startswith("session start"))
        self.assertIn("sha256=", ev[1])
        self.assertNotIn("(missing)", ev[1])


class ConfigTest(unittest.TestCase):
    def test_defaults_safe_and_env_override(self):
        c = BoxConfig.load(path="/nonexistent", env={"HAVOKBOX_TOKEN": "x"})
        self.assertEqual(c.token, "x")
        self.assertFalse(c.console_enabled)
        self.assertEqual(c.commander_max_calls_per_day, 0)
        self.assertEqual(c.default_mode, "stealth")
        self.assertTrue(c.on_lan("192.168.4.7"))
        self.assertFalse(c.on_lan("8.8.8.8"))
        self.assertFalse(c.on_lan("not-an-ip"))

    def test_bad_mode_rejected(self):
        with self.assertRaises(ValueError):
            BoxConfig(default_mode="loud").validate()


if __name__ == "__main__":
    unittest.main()
