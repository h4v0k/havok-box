"""Hardware check: is each board plugged in, and does the software that drives it answer?

Plain yes/no per board with the fix when it's a no. Used by `hb hw`, the hb menus/GUI, and the
dashboard's Report tab. Read-only: it lists USB devices, reads an SDR's EEPROM, asks gpsd for a
few messages and imports rflib. It never transmits and never changes a radio's mode.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

SNIFFLE_DIR = "/opt/sniffle"
SNIFFLE_FLASHED = "/var/lib/havokbox/sniffle-flashed"

OK, WARN, MISSING = "ok", "check", "missing"


def _run(argv: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def usb_ids(lsusb_text: str) -> set[str]:
    return {m.lower() for m in re.findall(r"\bID ([0-9a-fA-F]{4}:[0-9a-fA-F]{4})\b", lsusb_text)}


def has_vendor(ids: set[str], vendor: str) -> bool:
    return any(i.startswith(vendor + ":") for i in ids)


def gps_fix(gpspipe_text: str) -> str | None:
    """'3D', '2D', or None from gpspipe -w JSON lines."""
    modes = [int(m) for m in re.findall(r'"class":"TPV".*?"mode":(\d)', gpspipe_text)]
    best = max(modes, default=0)
    return {3: "3D", 2: "2D"}.get(best)


def wifi_monitor_iface(sys_net: str = "/sys/class/net", builtin: str = "wlan0") -> str | None:
    """A USB Wi-Fi interface other than the built-in one (the Alfa)."""
    try:
        names = sorted(os.listdir(sys_net))
    except OSError:
        return None
    for n in names:
        if n == builtin or not os.path.isdir(os.path.join(sys_net, n, "wireless")):
            continue
        return n
    return None


def check(run=_run, which=shutil.which, exists=os.path.exists, wifi_iface=wifi_monitor_iface,
          missing_tools: list[str] | None = None) -> list[dict]:
    rc, ls = run(["lsusb"])
    ids = usb_ids(ls) if rc == 0 else set()
    rows: list[dict] = []

    def row(board, status, detail, fix=""):
        rows.append({"board": board, "status": status, "detail": detail, "fix": fix})

    if rc != 0:
        row("USB", WARN, "couldn't list USB devices", "sudo apt install usbutils")

    # Alfa AWUS036ACM (MediaTek MT7612U)
    if "0e8d:7612" in ids:
        iface = wifi_iface()
        row("Alfa Wi-Fi (AWUS036ACM)", OK if iface else WARN,
            f"plugged in, interface {iface}" if iface else "plugged in, but no interface came up",
            "" if iface else "replug it; check 'dmesg | tail' for mt76x2u errors")
    else:
        row("Alfa Wi-Fi (AWUS036ACM)", MISSING, "not detected", "plug it into the hub")

    # RTL-SDR Blog V4
    if "0bda:2838" in ids:
        if not which("rtl_eeprom"):
            row("RTL-SDR V4", WARN, "plugged in, rtl-sdr tools not installed", "re-run kali-setup.sh")
        else:
            rc2, out = run(["rtl_eeprom"], 15)
            serial = re.search(r"Serial number:\s*(\S+)", out)
            if rc2 == 0 or serial:
                row("RTL-SDR V4", OK, f"answers (serial {serial.group(1) if serial else '?'})")
            else:
                busy = "usb_claim_interface" in out or "busy" in out.lower()
                row("RTL-SDR V4", WARN, "plugged in but won't open" + (" (in use)" if busy else ""),
                    "another program has it; stop it" if busy
                    else "reboot so the TV-tuner driver blacklist takes effect")
    else:
        row("RTL-SDR V4", MISSING, "not detected", "plug it into the hub")

    # SONOFF Dongle Plus-P (CP210x bridge) running Sniffle
    if "10c4:ea60" in ids:
        if not exists(os.path.join(SNIFFLE_DIR, "python_cli", "sniff_receiver.py")):
            row("ZigBee dongle (Sniffle BLE)", WARN, "plugged in, Sniffle software missing", "re-run kali-setup.sh")
        elif not exists(SNIFFLE_FLASHED):
            row("ZigBee dongle (Sniffle BLE)", WARN, "plugged in, Sniffle firmware not flashed yet",
                "sudo scripts/flash-sniffle.sh (once)")
        else:
            row("ZigBee dongle (Sniffle BLE)", OK, "plugged in, Sniffle firmware flashed")
    else:
        row("ZigBee dongle (Sniffle BLE)", MISSING, "not detected", "plug it into the hub")

    # Yard Stick One (rfcat)
    if "1d50:605b" in ids:
        rc3, _ = run(["python3", "-c", "import rflib"])
        row("Yard Stick One (sub-GHz)", OK if rc3 == 0 else WARN,
            "plugged in, rfcat ready" if rc3 == 0 else "plugged in, rfcat not installed",
            "" if rc3 == 0 else "sudo apt install rfcat")
    else:
        row("Yard Stick One (sub-GHz)", MISSING, "not detected", "plug it into the hub")

    # GPS (u-blox)
    if has_vendor(ids, "1546"):
        if not which("gpspipe"):
            row("GPS", WARN, "plugged in, gpsd tools not installed", "re-run kali-setup.sh")
        else:
            _, out = run(["timeout", "8", "gpspipe", "-w", "-n", "15"], 12)
            fix = gps_fix(out)
            if fix:
                row("GPS", OK, f"{fix} fix")
            elif '"class":"TPV"' in out or '"class":"SKY"' in out:
                row("GPS", WARN, "talking to gpsd, no fix yet", "give it a view of the sky for a few minutes")
            else:
                row("GPS", WARN, "plugged in, gpsd isn't reading it", "sudo systemctl restart gpsd")
    else:
        row("GPS", MISSING, "not detected", "plug it into the hub")

    # Backups and spares
    if "0483:5740" in ids:
        row("Flipper Zero (backup sub-GHz)", OK, "plugged in")
    if exists("/dev/spidev0.0"):
        row("CC1101 on SPI (spare)", OK, "SPI is on; the CC1101 isn't used by any button")

    if missing_tools:
        row("Software", WARN, f"{len(missing_tools)} button(s) hidden, tools not installed: "
            + ", ".join(missing_tools[:12]) + ("..." if len(missing_tools) > 12 else ""),
            "re-run kali-setup.sh while online")
    elif missing_tools is not None:
        row("Software", OK, "every button's tool is installed")
    return rows


def render(rows: list[dict]) -> str:
    mark = {OK: "[ OK ]", WARN: "[ !! ]", MISSING: "[ -- ]"}
    lines = []
    for r in rows:
        lines.append(f"{mark[r['status']]} {r['board']:<30} {r['detail']}")
        if r["fix"]:
            lines.append(f"{'':7}{'':30} fix: {r['fix']}")
    return "\n".join(lines)


def missing_from_registry() -> list[str]:
    from .inventory import Inventory
    from .tools.registry import default_registry
    return Inventory(default_registry()).missing
