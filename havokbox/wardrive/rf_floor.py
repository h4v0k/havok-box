"""RF noise-floor recording (design #13): fixed gain, per-band medians, record only. No alerting."""
from __future__ import annotations

import statistics

BANDS = {"315": (314, 316), "433": (432, 435), "915": (902, 928), "gps_l1": (1574, 1577)}
_STEP_HZ = {"315": 5000, "433": 5000, "915": 50000, "gps_l1": 10000}


def sweep_argv(band_key: str, gain_db: int = 30, seconds: int = 10, hw=None) -> list[str]:
    from ..tools.sdr import dev_args
    lo, hi = BANDS[band_key]
    return ["rtl_power"] + dev_args(hw) + ["-f", f"{lo}M:{hi}M:{_STEP_HZ[band_key]}", "-g", str(int(gain_db)),
            "-i", "2", "-e", f"{int(seconds)}s", "/dev/stdout"]


def parse_medians(stdout) -> dict:
    """rtl_power CSV: date, time, hz_low, hz_high, hz_step, samples, db, db, ..."""
    vals = []
    for line in (stdout or "").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 7:
            continue
        for p in parts[6:]:
            try:
                v = float(p)
            except ValueError:
                continue
            if v == v and abs(v) != float("inf"):
                vals.append(v)
    if not vals:
        return {"median_db": None, "bins": 0}
    return {"median_db": round(statistics.median(vals), 2), "bins": len(vals)}
