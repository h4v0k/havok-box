import json

import pytest

from havokbox.helpers import radio as hr
from havokbox.tools import radio, registry

# rtl_power CSV: date, time, hz_low, hz_high, hz_step, samples, dB...
def power_line(lo_hz, step_hz, dbs):
    return ", ".join(["2026-11-24", "01:00:00", str(lo_hz), str(lo_hz + step_hz * len(dbs)), str(step_hz), "100"]
                     + [str(x) for x in dbs])


def test_labels():
    assert hr.label_for(462.5625) == "FRS/GMRS 1"
    assert hr.label_for(462.7250) == "FRS/GMRS 22"
    assert hr.label_for(467.6375) == "FRS/GMRS 11"
    assert hr.label_for(151.940) == "MURS 3"
    assert hr.label_for(162.550) == "NOAA weather WX7"
    assert hr.label_for(144.391) == "APRS"
    assert hr.label_for(146.940) == "2m repeater output range"
    assert hr.label_for(147.9) == "2m band"


def test_parse_power_finds_active_channels_and_merges_bins():
    step = 6250
    dbs = [-40.0] * 40
    dbs[2] = dbs[3] = -15.0          # 462.5625 / 462.56875 -> one signal (GMRS 1)
    dbs[14] = -22.0                  # 462.6375 -> GMRS 4
    txt = power_line(462_550_000, step, dbs) + "\nbogus line\n"
    r = hr.parse_power(txt, "gmrs")
    assert r["noise_floor_db"] == -40.0
    labels = [a["label"] for a in r["active"]]
    assert labels == ["FRS/GMRS 1", "FRS/GMRS 4"] and r["active"][0]["above_floor_db"] == 25.0
    assert hr.parse_power("", "gmrs")["active"] == []


def test_build_power_and_unknown_band():
    cmd = hr.build_power("2m", 30, "SDR01")
    assert cmd[:3] == ["rtl_power", "-d", "SDR01"] and "144M:148M:12.5k" in cmd
    assert hr.main(["bands", "--bands", "2m,marine"]) == 0


def test_parse_aprs():
    out = "\n".join([
        "Dire Wolf version 1.7",
        "[0.4] KJ4ABC-9>APDR16,WIDE1-1,WIDE2-1:=2757.00N/08227.50W>mobile",
        "[0.4] KJ4ABC-9>APDR16,WIDE1-1:=2757.10N/08227.40W>mobile",
        "[0.5] W4XYZ>APRS,TCPIP*:>Tampa digi",
        "garbage",
    ])
    st = hr.parse_aprs(out)
    assert [s["call"] for s in st] == ["KJ4ABC-9", "W4XYZ"]
    assert st[0]["packets"] == 2 and st[0]["lat"] == pytest.approx(27.9517, abs=1e-3)
    assert st[0]["lon"] == pytest.approx(-82.4567, abs=1e-3) and st[1]["lat"] is None


def test_main_rejects_bad_serial(capsys):
    hr.main(["aprs", "--device", "x;rm"])
    assert "bad SDR serial" in capsys.readouterr().out


class Ctx:
    mode, scope = "standard", None

    def __init__(self, out, hw=None):
        self.out, self.hw, self.argv = out, hw or {}, None

    def runner(self, argv):
        self.argv = argv
        return self.out


def test_tools_and_registry():
    out = {"bands": [{"band": "gmrs", "active": [{"mhz": 462.5625, "db": -15, "above_floor_db": 25,
                                                   "label": "FRS/GMRS 1"}]}]}
    c = Ctx(json.dumps(out), {"sdr_serial": "SDR01"})
    r = radio.bands({"target": {"band": "gmrs", "seconds": 30}}, c)
    assert c.argv[-4:] == ["--seconds", "30", "--device", "SDR01"] and "--bands" in c.argv
    assert r["summary"] == "1 active channel(s): FRS/GMRS 1"
    with pytest.raises(ValueError):
        radio.build_bands({"band": "marine"}, "s", None, {})
    c = Ctx(json.dumps({"stations": [{"call": "W4XYZ", "lat": 27.9, "lon": -82.4}]}))
    assert radio.aprs({"target": {}}, c)["summary"] == "1 APRS station(s), 1 with position"
    reg = registry.default_registry()
    assert reg["radio.bands"].category == reg["radio.aprs"].category == "recon.passive"
    assert "air.ais" not in reg and "air.adsb" in reg
