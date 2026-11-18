"""WardriveService end to end with fakes: radios held, passive only, privacy, follow-me, lifecycle."""
import json
import sys
import os
import sqlite3
import tempfile
import unittest

from havokbox.server import Handlers, Jobs, LaneHeld
from havokbox.store import Store
from havokbox.wardrive.db import WardriveDB
from havokbox.wardrive.service import WardriveError, WardriveService
from tests.helpers import make

AP = "aa:bb:cc:dd:ee:01"
CLIENT = "11:22:33:44:55:66"
TAG = "c0:ff:ee:12:34:56"
APPLE_SEPARATED = "4c0012190010aabbccddeeff00112233445566778899aabbccdd0000"


class FakeReader:
    def __init__(self, st): self.started = self.stopped = False
    def start(self): self.started = True
    def stop(self): self.stopped = True


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.kismet_devices = []
        self.kismet_alerts = []
        self.ble = []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        joined = " ".join(argv)
        if "devices/last-time" in joined:
            return json.dumps(self.kismet_devices)
        if "alerts/last-time" in joined:
            return json.dumps(self.kismet_alerts)
        if "ble_scan" in joined:
            return json.dumps({"devices": self.ble, "pcap": None})
        return ""


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "box.db")
        self.h, _, self.runner_tools, self.scope, _ = make()
        self.h.api.store.close()
        # real on-disk store so the read-only connection works
        self.store = Store(self.path)
        self.h.api.store = self.h.api.orch.store = self.store
        self.db = WardriveDB(self.store, self.path, b"k" * 32)
        self.run = FakeRunner()
        self.wall = [1_800_000_000.0]
        self.mono = [1000.0]
        self.wd = WardriveService(self.db, self.h.jobs, self.h.api.orch, self.store, {"marauder_port": "/dev/ttyUSB1"},
                                  scope=self.scope, runner=self.run, wall=lambda: self.wall[0],
                                  mono=lambda: self.mono[0], gps_reader_factory=FakeReader)
        self.h.wardrive = self.wd
        # don't spawn collector threads in unit tests: drive ticks by hand
        self.wd._loop = lambda fn, every: None

    def tearDown(self):
        if self.wd.running():
            self.wd.stop()
        self.store.close()

    def fix(self, lat, lon, ts=None):
        self.wd.gps.update({"class": "TPV", "ts": ts or self.wall[0], "lat": lat, "lon": lon, "mode": 3, "speed": 0})

    # ---- safety -------------------------------------------------------------
    def test_start_holds_radios_voids_approvals_and_silences_marauder(self):
        self.store.grant_approval("t1", "recon.active", {})
        code, r = self.h.wardrive_start({"note": "I-275"})
        self.assertEqual(code, 200)
        self.assertIsNone(self.store.open_approval("t1"))
        self.assertTrue(self.h.api.orch.passive_only)
        self.assertIn("stop", self.run.calls[0])                      # Marauder stopscan first
        self.assertEqual(self.h.scan({"space": "wifi"})[0], 409)       # radio held
        self.assertEqual(self.h.scan({"space": "ble"})[0], 409)
        with self.assertRaises(LaneHeld):
            self.h.jobs.submit("x", lambda: None, lane="esp")
        self.assertEqual(self.h.wardrive_start({})[0], 409)            # one session at a time

    def test_active_tools_refused_during_session_even_with_approval(self):
        self.h.scan({"space": "wired", "mode": "standard"})
        while self.h.jobs.run_one():
            pass
        p = self.h.state()[1]["proposals"][0]
        self.h.wardrive_start({})
        self.h.approve({"task_id": p["task_id"], "digest": p["digest"]})  # approved during the drive
        before = len(self.runner_tools.cmds)
        self.assertEqual(self.h.api.run(p["task_id"])["status"], "refused")
        self.assertEqual(len(self.runner_tools.cmds), before)

    def test_cannot_start_while_a_scan_is_queued(self):
        self.h.jobs.submit("busy", lambda: None, lane="wifi")
        code, r = self.h.wardrive_start({})
        self.assertEqual(code, 409)
        self.assertFalse(self.h.api.orch.passive_only)

    def test_stop_releases_everything(self):
        self.h.wardrive_start({})
        self.wd.stop()
        self.assertFalse(self.h.api.orch.passive_only)
        self.assertEqual(self.h.scan({"space": "wifi"})[0], 202)
        st = self.db.query("SELECT status FROM wardrive_sessions")
        self.assertEqual(st[0]["status"], "stopped")

    def test_boot_aborts_unfinished_session(self):
        self.db.start_session("left running", now=self.wall[0])
        self.wd.boot()
        self.assertEqual(self.db.query("SELECT status FROM wardrive_sessions")[0]["status"], "aborted")
        with self.assertRaises(sqlite3.IntegrityError):    # partial unique index
            self.db.start_session("a"); self.db.start_session("b")

    # ---- collection & privacy ----------------------------------------------
    def test_kismet_cells_hash_clients_keep_aps_and_dedupe_alerts(self):
        self.wd.start()
        self.fix(27.95, -82.46)
        self.run.kismet_devices = [
            {"kismet.device.base.macaddr": AP.upper(), "kismet.device.base.type": "Wi-Fi AP",
             "kismet.device.base.commonname": "LAB-NET", "kismet.device.base.channel": "6"},
            {"kismet.device.base.macaddr": CLIENT, "kismet.device.base.type": "Wi-Fi Client"}]
        self.run.kismet_alerts = [{"kismet.alert.header": "DEAUTHFLOOD", "kismet.alert.source_mac": AP,
                                   "kismet.alert.text": "deauth flood", "kismet.alert.timestamp": self.wall[0]}]
        self.wd.tick_kismet(); self.wd.tick_kismet()
        keys = {r["dev_key"] for r in self.db.query("SELECT dev_key FROM device_cells")}
        self.assertIn(AP, keys)
        self.assertNotIn(CLIENT, keys)                       # client stored only as HMAC
        self.assertTrue(any(k.startswith("h:") for k in keys))
        names = [r["name"] for r in self.db.query("SELECT name FROM device_cells WHERE name IS NOT NULL")]
        self.assertEqual(names, ["LAB-NET"])
        alerts = self.db.query("SELECT * FROM alerts WHERE kind='DEAUTHFLOOD'")
        self.assertEqual(len(alerts), 1)                     # deduped per 10-min bucket
        # wardrive never writes findings
        self.assertEqual(self.store.findings(), [])

    def test_ble_tracker_classified_and_never_named(self):
        self.wd.start()
        self.fix(27.95, -82.46)
        self.run.ble = [{"addr": TAG, "name": "Mike's AirTag", "rssi": -60, "company_ids": [0x004C],
                         "uuid16": [], "mfg_data": [APPLE_SEPARATED], "random": True}]
        self.wd.tick_ble()
        rows = self.db.query("SELECT * FROM device_cells WHERE radio='ble'")
        self.assertEqual(rows[0]["kind"], "findmy_separated")
        self.assertIsNone(rows[0]["name"])
        self.assertNotIn(TAG, json.dumps(rows))

    # ---- follow-me ----------------------------------------------------------
    def test_tracker_at_two_far_stops_raises_high_alert(self):
        self.wd.start()
        self.run.ble = [{"addr": TAG, "rssi": -55, "company_ids": [0x004C], "uuid16": [],
                         "mfg_data": [APPLE_SEPARATED], "random": True}]
        t0 = self.wall[0]
        # stop A: 8 minutes parked, tracker heard
        for i in range(0, 481, 30):
            self.wall[0] = t0 + i; self.mono[0] += 30
            self.fix(27.9500, -82.4600, self.wall[0]); self.wd.tick_track()
            if i in (60, 300):
                self.wd.tick_ble()
        # drive ~5 km north
        for i in range(1, 11):
            self.wall[0] += 30; self.fix(27.9500 + i * 0.0045, -82.4600, self.wall[0]); self.wd.tick_track()
        # stop B: 8 minutes parked, tracker heard again
        t1 = self.wall[0]
        for i in range(0, 481, 30):
            self.wall[0] = t1 + i; self.mono[0] += 30
            self.fix(27.9950, -82.4600, self.wall[0]); self.wd.tick_track()
            if i in (60, 300):
                self.wd.tick_ble()
        self.wd.tick_follow()
        a = self.db.query("SELECT * FROM alerts WHERE kind='follow'")
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "high")
        self.assertEqual(a[0]["dev_plain"], TAG)             # plaintext kept only for the alerted device
        self.assertIn("AirTag", a[0]["detail"])

    # ---- dashboard ----------------------------------------------------------
    def test_state_ack_delete(self):
        self.wd.start()
        self.fix(27.95, -82.46)
        self.run.kismet_alerts = [{"kismet.alert.header": "DEAUTHFLOOD", "kismet.alert.source_mac": AP,
                                   "kismet.alert.text": "x", "kismet.alert.timestamp": self.wall[0]}]
        self.wd.tick_kismet()
        code, st = self.h.wardrive_state()
        self.assertTrue(st["running"])
        aid = st["alerts"][0]["id"]
        self.assertEqual(self.h.wardrive_ack({"alert_id": aid})[0], 200)
        self.assertIsNotNone(self.h.wardrive_state()[1]["alerts"][0]["acked"])
        sid = st["session"]
        self.assertEqual(self.h.wardrive_delete({"session": sid})[0], 409)   # running
        self.wd.stop()
        self.assertEqual(self.h.wardrive_delete({"session": sid})[0], 200)
        self.assertEqual(self.db.query("SELECT COUNT(*) AS n FROM alerts")[0]["n"], 0)

    def test_purge_needs_a_set_clock(self):
        sid = self.db.start_session("old", now=1_000.0)
        self.db.end_session(sid, "stopped", 0, now=1_000.0)
        self.assertEqual(self.db.purge(7, 1_000.0 + 30 * 86400, clock_ok=False), 0)
        self.assertEqual(self.db.purge(7, 1_000.0 + 30 * 86400, clock_ok=True), 1)


if __name__ == "__main__":
    unittest.main()


class ReviewFixTest(ServiceTest):
    def test_drive_never_writes_evidence(self):
        before = len(self.store.evidence())
        self.wd.start("x"); self.wd.stop()
        new = self.store.evidence()[before:]
        self.assertFalse(any("session" in e["detail"] or "km" in e["detail"] for e in new), new)
        self.assertTrue(self.wd.notes)                     # kept locally instead

    def test_wifi_position_is_ours_not_kismet_average(self):
        self.wd.start()
        self.fix(27.95, -82.46)
        self.run.kismet_devices = [{"kismet.device.base.macaddr": CLIENT, "kismet.device.base.type": "Wi-Fi Client",
                                    "kismet.device.base.location": {"kismet.common.location.avg_loc": {
                                        "kismet.common.location.geopoint": [-80.0, 25.0]}},
                                    "kismet.device.base.last_time": 1}]
        self.wd.tick_kismet()
        r = self.db.query("SELECT lat, lon, first_ts FROM device_cells")[0]
        self.assertAlmostEqual(r["lat"], 27.95)
        self.assertGreater(r["first_ts"], 1_000_000_000)   # our time base, not Kismet's clock

    def test_non_tracker_ble_phone_can_trip_follow_me(self):
        self.wd.start()
        self.run.ble = [{"addr": "aa:aa:aa:aa:aa:01", "rssi": -60, "company_ids": [], "uuid16": [],
                         "mfg_data": [], "random": False}]
        for lat in (27.9500, 27.9950):
            t = self.wall[0]
            for i in range(0, 481, 30):
                self.wall[0] = t + i; self.mono[0] += 30
                self.fix(lat, -82.46, self.wall[0]); self.wd.tick_track()
                if i in (60, 300):
                    self.wd.tick_ble()
            for k in range(1, 11):
                self.wall[0] += 30; self.fix(lat + k * 0.0045, -82.46, self.wall[0]); self.wd.tick_track()
        self.wd.tick_follow()
        a = self.db.query("SELECT severity FROM alerts WHERE kind='follow'")
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "high")      # rssi -60 > -70: likely in the car

    def test_late_cap_stop_cannot_end_a_newer_session(self):
        s1 = self.wd.start(); self.wd.stop()
        self.wd.start()
        self.wd.stop(status="capped", sid=s1)
        self.assertTrue(self.wd.running())

    def test_gps_failure_rolls_back(self):
        class Boom(FakeReader):
            def start(self): raise OSError("gpspipe not found")
        self.wd._reader_factory = Boom
        self.assertEqual(self.h.wardrive_start({})[0], 409)
        self.assertFalse(self.wd.running())
        self.assertFalse(self.h.api.orch.passive_only)
        self.assertEqual(self.h.scan({"space": "wifi"})[0], 202)
        self.assertEqual(self.db.query("SELECT status FROM wardrive_sessions")[0]["status"], "failed")

    def test_kismet_logs_follow_session_window_delete_and_retention(self):
        logdir = os.path.join(self.dir, "kismet"); os.makedirs(logdir)
        self.wd.hw["kismet_log_dir"] = logdir
        sid = self.db.start_session("old", now=self.wall[0] - 3 * 86400)
        self.db.end_session(sid, "stopped", 0, now=self.wall[0] - 3 * 86400 + 600)
        old = os.path.join(logdir, "a.kismet"); new = os.path.join(logdir, "b.kismet")
        for f, t in ((old, self.wall[0] - 3 * 86400 + 500), (new, self.wall[0])):
            open(f, "w").close(); os.utime(f, (t, t))
        s = self.db.query("SELECT * FROM wardrive_sessions WHERE id=?", (sid,))[0]
        self.assertEqual(self.wd.kismet_logs_for(s), [old])          # not today's log
        self.assertTrue(self.wd.delete_session(sid))
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(new))
        os.utime(new, (self.wall[0] - 30 * 86400,) * 2)
        self.wd.purge()
        self.assertFalse(os.path.exists(new))                        # past retention


class ThreadedStopTest(unittest.TestCase):
    """Real collector threads + a real process group: Stop must kill grandchildren and release."""
    def test_stop_kills_process_group_and_releases(self):
        import time
        from havokbox.wardrive.service import GroupRunner
        d = tempfile.mkdtemp(); path = os.path.join(d, "b.db")
        h, s0, *_ = make(); s0.close()
        store = Store(path); h.api.store = h.api.orch.store = store
        db = WardriveDB(store, path, b"k" * 32)
        pidfile = os.path.join(d, "child.pid")
        script = ("import subprocess,time;p=subprocess.Popen(['sleep','60']);"
                  f"open({pidfile!r},'w').write(str(p.pid));time.sleep(60)")
        gr = GroupRunner()

        def runner(argv, timeout):
            if "ble_scan" in " ".join(argv):
                return gr([sys.executable, "-c", script], 120)   # a slow BLE window
            return ""
        import sys
        wd = WardriveService(db, h.jobs, h.api.orch, store, {"work_dir": d}, runner=runner,
                             gps_reader_factory=FakeReader)
        wd.runner.kill_all = gr.kill_all
        wd.start()
        for _ in range(50):
            if os.path.exists(pidfile) and open(pidfile).read():
                break
            time.sleep(0.1)
        child = int(open(pidfile).read())
        t0 = time.monotonic()
        wd.stop()
        self.assertLess(time.monotonic() - t0, 15)
        time.sleep(0.3)
        try:
            alive = open(f"/proc/{child}/stat").read().split()[2] != "Z"
        except FileNotFoundError:
            alive = False
        self.assertFalse(alive, "sleep grandchild survived Stop")
        self.assertFalse(h.api.orch.passive_only)
        self.assertEqual(h.scan({"space": "wifi"})[0], 202)
        store.close()
