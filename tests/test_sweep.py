import json
import zlib

from havokbox.helpers import sweep


def _csv(tmp_path, name="s.csv"):
    lines = []
    for t in range(6):
        for lo in (433_000_000, 434_000_000):
            vals = [-60.0] * 10
            if lo == 433_000_000:
                vals[9] = -20.0           # strong signal at 433.9 MHz
            lines.append(f"2026-11-25, 10:00:0{t}, {lo}, {lo + 1_000_000}, 100000, 10, " + ", ".join(map(str, vals)))
    p = tmp_path / "run" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n")
    return p


def test_parse_merges_hops_into_one_row_per_time(tmp_path):
    p = _csv(tmp_path)
    rows, lo, hi, step = sweep.parse(p.read_text().splitlines())
    assert len(rows) == 6 and lo == 433e6 and hi == 435e6 and step == 1e5
    assert len(rows[0][1]) == 20


def test_picture_is_valid_png_and_finds_the_peak(tmp_path):
    rows, lo, hi, step = sweep.parse(_csv(tmp_path).read_text().splitlines())
    data, w, h, peaks = sweep.picture(rows, lo, hi, step)
    assert data.startswith(b"\x89PNG") and (w, h) == (20, 6)
    idat = data[data.index(b"IDAT") + 4:data.index(b"IEND") - 8]
    assert len(zlib.decompress(idat)) == h * (1 + w * 3)
    assert peaks[0]["freq_mhz"] == 433.9 and peaks[0]["above_floor_db"] == 40.0


def test_main_uses_newest_rtl_power_csv(tmp_path, capsys):
    (tmp_path / "other.csv").write_text("name,age\nbob,3\n")
    _csv(tmp_path)
    out = tmp_path / "w.png"
    sweep.main(["picture", "--dir", str(tmp_path), "--out", str(out)])
    r = json.loads(capsys.readouterr().out)
    assert r["status"] == "ok" and r["csv"].endswith("s.csv") and out.read_bytes().startswith(b"\x89PNG")
    sweep.main(["picture", "--dir", str(tmp_path / "nothing"), "--out", str(out)])
    assert json.loads(capsys.readouterr().out)["status"] == "error"
