#!/usr/bin/env bash
# Give the two RTL-SDR dongles different serial numbers so havok-box can tell them apart, and
# record them in config/box.json:
#   hw.sdr_serial  = HBSDR1  main dongle: spectrum, 433 decode, ham/VHF/UHF, wardrive
#   hw.sdr2_serial = HBSDR2  second dongle: aircraft (ADS-B) on 1090 MHz, runs alongside the main one
#
#   sudo ./scripts/sdr-serials.sh
#
# Both dongles leave the factory with the same serial (usually 00000001), so this goes one at a time.
# Put a label on each dongle as you go. Writing a serial only changes the dongle's EEPROM name.
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${HAVOKBOX_CONFIG:-$APP_DIR/config/box.json}"
command -v rtl_eeprom >/dev/null || { echo "rtl_eeprom missing: run kali-setup.sh first" >&2; exit 1; }
[ -f "$CONFIG" ] || { echo "no $CONFIG yet: run kali-setup.sh first" >&2; exit 1; }

count() { lsusb -d 0bda:2838 2>/dev/null | wc -l; }
serial_of() { rtl_eeprom -d "$1" 2>&1 | sed -n 's/^Serial number:[[:space:]]*//p' | head -1; }
write_serial() { printf 'y\n' | rtl_eeprom -d "$1" -s "$2" >/dev/null 2>&1; }

echo "Step 1: plug in ONLY the dongle you want as the MAIN one (wideband antenna). Label it 'SDR1'."
read -rp "Press Enter when only that one is plugged in... " _
[ "$(count)" -eq 1 ] || { echo "Found $(count) RTL-SDR dongles; unplug all but one and run again." >&2; exit 1; }
write_serial 0 HBSDR1 || { echo "couldn't write the serial (is another program using it?)" >&2; exit 1; }
echo "    main dongle -> HBSDR1"

echo
echo "Step 2: unplug it and plug it back in, then plug in the SECOND dongle (1090 MHz antenna). Label it 'SDR2'."
read -rp "Press Enter when both are plugged in... " _
[ "$(count)" -eq 2 ] || { echo "Expected 2 dongles, found $(count)." >&2; exit 1; }
other=""
for i in 0 1; do [ "$(serial_of "$i")" != "HBSDR1" ] && other="$i"; done
[ -n "$other" ] || { echo "Both read HBSDR1. Replug the first dongle and run again." >&2; exit 1; }
write_serial "$other" HBSDR2 || { echo "couldn't write the second serial" >&2; exit 1; }
echo "    second dongle -> HBSDR2"

python3 - "$CONFIG" <<'PY'
import json, sys
p = sys.argv[1]
cfg = json.load(open(p))
cfg.setdefault("hw", {}).update({"sdr_serial": "HBSDR1", "sdr2_serial": "HBSDR2"})
json.dump(cfg, open(p, "w"), indent=2)
open(p, "a").write("\n")
PY
echo
echo "Saved to $CONFIG. Unplug and replug both dongles, then restart the dashboard:"
echo "    sudo systemctl restart havokbox-dashboard havokbox-watchdog"
echo "Check with: hb hw"
