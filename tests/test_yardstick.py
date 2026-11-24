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
