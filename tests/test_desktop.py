"""Remote desktop (noVNC): same guard posture as the Console — off by default, box-LAN, TLS, logged."""
import os
import tempfile
import unittest

from havokbox.config import BoxConfig
from havokbox.watchdog import desktop_cmd
from tests.helpers import make


class DesktopHandlerTest(unittest.TestCase):
    def test_off_by_default(self):
        h, store, *_ = make()
        self.assertEqual(h.desktop("192.168.4.20")[0], 404)
        self.assertFalse(h.state()[1]["desktop_enabled"])
        store.close()

    def test_lan_only_tls_required_and_logged(self):
        d = tempfile.mkdtemp()
        cert, key = os.path.join(d, "c"), os.path.join(d, "k")
        h, store, *_ = make(desktop_enabled=True, tls_cert=cert, tls_key=key)
        self.assertEqual(h.desktop("10.0.0.9")[0], 403)             # off-LAN
        self.assertEqual(h.desktop(None)[0], 403)
        self.assertEqual(h.desktop("192.168.4.20")[0], 503)        # no TLS cert yet
        open(cert, "w").close(); open(key, "w").close()
        code, r = h.desktop("192.168.4.20")
        self.assertEqual(code, 200)
        self.assertTrue(r["url"].startswith("https://192.168.4.1:6080/vnc.html"))
        kinds = [e["kind"] for e in store.evidence()]
        self.assertIn("refused", kinds)
        self.assertIn("desktop", kinds)
        store.close()

    def test_flag_reread_from_disk(self):
        import json
        d = tempfile.mkdtemp(); path = os.path.join(d, "box.json")
        h, store, *_ = make()
        h.cfg.source_path = path
        with open(path, "w") as fh:
            json.dump({"desktop_enabled": True}, fh)
        self.assertTrue(h.state()[1]["desktop_enabled"])
        with open(path, "w") as fh:
            json.dump({"desktop_enabled": False}, fh)
        self.assertFalse(h.state()[1]["desktop_enabled"])
        store.close()


class DesktopCmdTest(unittest.TestCase):
    def test_none_until_enabled_with_tls(self):
        d = tempfile.mkdtemp()
        cert, key = os.path.join(d, "c"), os.path.join(d, "k")
        self.assertIsNone(desktop_cmd(BoxConfig(tls_cert=cert, tls_key=key)))     # disabled
        self.assertIsNone(desktop_cmd(BoxConfig(desktop_enabled=True, tls_cert=cert, tls_key=key)))  # no cert
        open(cert, "w").close(); open(key, "w").close()
        cmd = desktop_cmd(BoxConfig(desktop_enabled=True, tls_cert=cert, tls_key=key,
                                    box_address="192.168.4.1", desktop_port=6080, desktop_vnc_port=5901))
        self.assertEqual(cmd[0], "websockify")
        self.assertIn("--cert", cmd)
        self.assertIn("192.168.4.1:6080", cmd)
        self.assertIn("localhost:5901", cmd)
        # no secret ever on the argv
        self.assertFalse(any("passw" in c.lower() for c in cmd))


class WatchdogDesktopTest(unittest.TestCase):
    class P:
        def __init__(self, cmd): self.cmd = cmd; self.rc = None; self.terminated = False
        def poll(self): return self.rc
        def terminate(self): self.terminated = True; self.rc = -15
        def wait(self, timeout=None): return self.rc
        def kill(self): pass

    def test_boot_launches_and_shutdown_stops_desktop(self):
        from havokbox.watchdog import Watchdog
        d = tempfile.mkdtemp()
        cert, key = os.path.join(d, "c"), os.path.join(d, "k")
        open(cert, "w").close(); open(key, "w").close()
        cfg = BoxConfig(db_path=os.path.join(d, "b.db"), token="t", session_limit_s=100,
                        desktop_enabled=True, tls_cert=cert, tls_key=key)
        procs = []
        w = Watchdog(cfg, spawn=lambda cmd: (procs.append(self.P(cmd)) or procs[-1]),
                     clock=lambda: 0.0, sleep=lambda s: None)
        w.boot()
        dprocs = [p for p in procs if p.cmd and p.cmd[0] == "websockify"]
        self.assertEqual(len(dprocs), 1)
        # restart on exit
        dprocs[0].rc = 0
        w.tick()
        self.assertEqual(len([p for p in procs if p.cmd[0] == "websockify"]), 2)
        w.shutdown("test")
        live = [p for p in procs if p.cmd[0] == "websockify"][-1]   # the restarted one, still running
        self.assertTrue(live.terminated)


if __name__ == "__main__":
    unittest.main()
