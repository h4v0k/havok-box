import json

from havokbox.helpers import yardstick as ys
from havokbox.inventory import Inventory
from havokbox.tools import registry, yardstick

MODS = {"ASK_OOK": 48, "2FSK": 0, "GFSK": 16}


class FakeRadio:
    def __init__(self, frames=()):
        self.frames = list(frames)
        self.calls = []

    def __getattr__(self, name):
        def rec(*a, **k):
            self.calls.append((name, a, k))
        return rec

    def RFrecv(self, timeout=1000):
        self.calls.append(("RFrecv", (), {}))
        if not self.frames:
            raise TimeoutError
        return self.frames.pop(0), 0


def clock_seq(n):
    t = iter(range(n))
    return lambda: next(t, 10**9)


def test_scan_skips_noise_saves_signals_and_idles(tmp_path):
    r = FakeRadio([b"\x00" * 16, b"\xff" * 16, b"\x8e\x8e\x88\xe8" * 4, b"\x00\xff" * 8])
    out = ys.scan(r, MODS, 433.92, 30, str(tmp_path), clock=clock_seq(40))
    assert len(out["received"]) == 1 and out["received"][0]["hex"].startswith("8e8e88e8")
    cid = out["received"][0]["id"]
    assert [c["id"] for c in out["captures"]] == [cid] and out["captures"][0]["freq_mhz"] == 433.92
    saved = json.loads((tmp_path / "subghz" / f"{cid}.json").read_text())
    assert saved["freq_hz"] == 433_920_000 and saved["modulation"] == "ASK_OOK"
    names = [c[0] for c in r.calls]
    assert names[:4] == ["setFreq", "setMdmModulation", "setMdmDRate", "lowball"]
    assert names[-1] == "setModeIDLE"


def test_replay_checks_id_frequency_and_transmits(tmp_path):
    ys.scan(FakeRadio([b"\x12\x34\x56\x78" * 4]), MODS, 315.0, 5, str(tmp_path), clock=clock_seq(10))
    cid = ys.list_captures(str(tmp_path))[0]["id"]
    assert ys.replay(FakeRadio(), MODS, "../etc/passwd", 315.0, str(tmp_path))["status"] == "refused"
    assert ys.replay(FakeRadio(), MODS, "nope", 315.0, str(tmp_path))["status"] == "refused"
    bad = ys.replay(FakeRadio(), MODS, cid, 433.92, str(tmp_path))
    assert bad["status"] == "refused" and "differs" in bad["reason"]
    r = FakeRadio()
    ok = ys.replay(r, MODS, cid, 315.0, str(tmp_path))
    assert ok["status"] == "transmitted" and ok["freq_mhz"] == 315.0
    xmit = [c for c in r.calls if c[0] == "RFxmit"][0]
    assert xmit[1][0] == bytes.fromhex("12345678" * 4) and xmit[2] == {"repeat": ys.REPEAT}
    assert r.calls[-1][0] == "setModeIDLE"


def test_main_reports_missing_rfcat(capsys, tmp_path, monkeypatch):
    import builtins
    real = builtins.__import__
    monkeypatch.setattr(builtins, "__import__",
                        lambda n, *a, **k: (_ for _ in ()).throw(ImportError()) if n == "rflib" else real(n, *a, **k))
    ys.main(["scan", "--freq-mhz", "433.92", "--seconds", "5", "--work-dir", str(tmp_path)])
    assert "rfcat" in json.loads(capsys.readouterr().out)["error"]


def test_registry_points_subghz_at_yardstick_with_flipper_backup():
    reg = registry.default_registry()
    assert reg["subghz.scan"].fn is yardstick.scan and reg["subghz.replay"].category == "rf.replay"
    assert "flipper.scan" in reg and "flipper.replay" in reg
    inv = Inventory({"subghz.scan": reg["subghz.scan"]}, which=lambda b: None)
    assert inv.missing == ["subghz.scan"]  # hidden until rfcat is installed


class Ctx:
    mode, scope = "standard", None
    hw = {"work_dir": "/w"}

    def __init__(self, out):
        self.out, self.argv = out, None

    def runner(self, argv):
        self.argv = argv
        return self.out


def test_tool_wrappers():
    c = Ctx(json.dumps({"received": [{"hex": "aa"}], "captures": [{"id": "ys_1", "freq_mhz": 433.92}]}))
    r = yardstick.scan({"target": {"freq_mhz": 433.92, "seconds": 10}}, c)
    assert c.argv[-6:] == ["--freq-mhz", "433.92", "--seconds", "10", "--work-dir", "/w"]
    assert r["summary"].startswith("1 signal(s)") and r["data"]["captures"][0]["id"] == "ys_1"
    c = Ctx(json.dumps({"status": "refused", "reason": "x"}))
    assert yardstick.replay({"target": {"id": "ys_1", "freq_mhz": 433.92}}, c)["summary"] == "replay refused: x"
    assert yardstick.scan({"target": {}}, Ctx("garbage"))["summary"].startswith("Yard Stick error")


class RssiRadio(FakeRadio):
    def __init__(self, by_freq):
        super().__init__()
        self.by_freq, self.hz = by_freq, None

    def setFreq(self, hz):
        self.hz = hz
        self.calls.append(("setFreq", (hz,), {}))

    def getRSSI(self):
        return bytes([self.by_freq.get(self.hz, 0)])


def test_rssi_ranks_busy_frequencies_and_skips_out_of_band():
    # raw 0x50 = 80 -> 80/2-74 = -34 dBm (busy); 0xC0 = -64 -> -106 dBm (quiet)
    r = RssiRadio({433_920_000: 0x50, 315_000_000: 0xC0})
    t = [0.0]
    def clock():
        t[0] += 0.1
        return t[0]
    out = ys.rssi(r, MODS, [315.0, 433.92, 600.0], 1, clock=clock, sleep=lambda s: None)
    rows = out["busiest_first"]
    assert out["skipped_out_of_band"] == [600.0]
    assert [x["freq_mhz"] for x in rows] == [433.92, 315.0]
    assert rows[0]["peak_dbm"] == -34.0 and rows[1]["avg_dbm"] == -106.0 and rows[0]["samples"] > 1
    assert not any(c[0] in ("RFxmit", "setModeTX") for c in r.calls)
    assert r.calls[-1][0] == "setModeIDLE"


def test_rssi_conversion():
    assert ys._rssi_dbm(b"\x00") == -74.0 and ys._rssi_dbm(0x50) == -34.0 and ys._rssi_dbm(0xC0) == -106.0


def test_scan_with_fsk_and_baud_is_recorded(tmp_path):
    r = FakeRadio([b"\x12\x34\x56\x78" * 4])
    out = ys.scan(r, MODS, 915.0, 5, str(tmp_path), clock=clock_seq(10), mod="2FSK", drate=38400)
    cid = out["received"][0]["id"]
    saved = json.loads((tmp_path / "subghz" / f"{cid}.json").read_text())
    assert saved["modulation"] == "2FSK" and saved["drate"] == 38400
    assert ("setMdmModulation", (MODS["2FSK"],), {}) in r.calls


def test_all_captures_walks_kit_folders(tmp_path):
    for run in ("a", "b"):
        ys.scan(FakeRadio([b"\x12\x34\x56\x78" * 4]), MODS, 433.92, 5, str(tmp_path / run), clock=clock_seq(10))
    (tmp_path / "a" / "subghz" / "junk.json").write_text("nope")
    caps = ys.all_captures(str(tmp_path))
    assert len(caps) == 2 and all(c["bytes"] == 16 and c["freq_mhz"] == 433.92 for c in caps)


def test_main_refuses_bad_band_and_baud(capsys, tmp_path):
    ys.main(["scan", "--freq-mhz", "600", "--seconds", "5", "--work-dir", str(tmp_path)])
    assert "outside" in json.loads(capsys.readouterr().out)["reason"]
    ys.main(["scan", "--freq-mhz", "433.92", "--seconds", "5", "--work-dir", str(tmp_path), "--baud", "5"])
    assert "baud" in json.loads(capsys.readouterr().out)["reason"]
    ys.main(["rssi", "--freqs", "433.92,abc"])
    assert "comma" in json.loads(capsys.readouterr().out)["reason"]
    ys.main(["captures", "--dir", str(tmp_path)])
    assert json.loads(capsys.readouterr().out)["captures"] == []
