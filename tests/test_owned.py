"""'Mine': items marked as yours on the dashboard feed the scope and gate."""
import pytest

from havokbox import owned as O
from havokbox.scope import Gate, Scope

FILE = {"networks": {"include": ["10.20.0.0/24"], "exclude": ["192.168.1.0/24"]},
        "wifi": {"ssids": ["LAB-NET"]}, "rf": {"tx_bands": [{"min_mhz": 314.9, "max_mhz": 315.1}]}}


def scope(tmp_path):
    return Scope(FILE, owned_path=str(tmp_path / "owned.json"))


def test_validation():
    assert O.normalize("bssid", "AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert O.normalize("tx_band", {"mhz": 390})["min_mhz"] == 389.9
    for kind, bad in (("bssid", "nope"), ("ssid", ""), ("subghz", "../x"), ("never", "home"),
                      ("tx_band", {"mhz": 1200}), ("tx_band", {"min_mhz": 300, "max_mhz": 320}), ("x", 1)):
        with pytest.raises(O.OwnedError):
            O.normalize(kind, bad)


def test_marked_items_reach_the_gate(tmp_path):
    s = scope(tmp_path)
    g = Gate(s)
    task = {"category": "rf.replay", "target": {"id": "garage-left", "freq_mhz": 390.0}}
    assert not g.evaluate(task).allowed
    O.add(s.owned_path, "subghz", "garage-left")
    assert not g.evaluate(task).allowed            # 390 MHz not a transmit band yet
    O.add(s.owned_path, "tx_band", {"mhz": 390, "label": "garage"})
    d = g.evaluate(task)
    assert d.allowed and d.needs_approval          # still needs the per-action approval
    O.add(s.owned_path, "bssid", "aa:bb:cc:dd:ee:ff")
    O.add(s.owned_path, "ssid", "HOME-LAB")
    assert "aa:bb:cc:dd:ee:ff" in s.bssids and {"LAB-NET", "HOME-LAB"} <= s.ssids
    O.remove(s.owned_path, "subghz", "garage-left")
    assert not g.evaluate(task).allowed


def test_never_list_editing(tmp_path):
    s = scope(tmp_path)
    assert [str(n) for n in s.exclude] == ["192.168.1.0/24"]
    O.add(s.owned_path, "never", "10.20.0.1/32", file_never=s.file_exclude)
    assert [str(n) for n in s.exclude] == ["192.168.1.0/24", "10.20.0.1/32"]
    assert not s.ip_in_scope("10.20.0.1") and s.ip_in_scope("10.20.0.2")
    O.remove(s.owned_path, "never", "192.168.1.0/24", file_never=s.file_exclude)
    assert [str(n) for n in s.exclude] == ["10.20.0.1/32"]


def test_bad_file_entries_are_ignored(tmp_path):
    s = scope(tmp_path)
    (tmp_path / "owned.json").write_text('{"tx_bands": [{"min_mhz": 1, "max_mhz": 6000}], "bssids": [5, "x"]}')
    assert s.tx_bands == [(314.9, 315.1)]
    assert s.bssids == {"x"}   # strings only; the gate still needs an exact match


def test_dashboard_mine_endpoints(tmp_path):
    from tests.helpers import make
    h = make()[0]
    h.api.scope.owned_path = str(tmp_path / "owned.json")
    code, st = h.owned_add({"kind": "subghz", "value": "garage-left"})
    assert code == 200 and "garage-left" in st["subghz"] and "garage-left" in st["removable"]["subghz"]
    assert h.owned_add({"kind": "tx_band", "value": {"mhz": 5000}})[0] == 400
    assert h.owned_add({"kind": "weird", "value": 1})[0] == 400
    code, st = h.owned_remove({"kind": "subghz", "value": "garage-left"})
    assert code == 200 and "garage-left" not in st["subghz"]
