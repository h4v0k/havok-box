#!/usr/bin/env bash
# Flash Sniffle (NCC Group's BLE sniffer firmware) onto the SONOFF Zigbee 3.0 USB Dongle Plus-P
# (TI CC2652P). Run ONCE, with only that dongle plugged into USB serial.
#
#   sudo ./scripts/flash-sniffle.sh                 # standard build (CP2102N bridge, 2 Mbaud)
#   sudo ./scripts/flash-sniffle.sh --old-cp2102    # 921600-baud build for older CP2102 (non-N) dongles
#   sudo ./scripts/flash-sniffle.sh --port /dev/ttyUSB1
#
# Sniffle's README warns that flashing the wrong build can brick the dongle and lock out the
# bootloader. The Dongle Plus-P is a CC2652P with a CP2102N bridge, so the standard build is right
# for it. Only use --old-cp2102 if `lsusb -v` shows a plain "CP2102" (no N).
# After flashing, the dongle is a BLE sniffer, not a Zigbee coordinator. Re-flash Zigbee firmware
# to undo.
set -euo pipefail

PORT=/dev/ttyUSB0
VARIANT="sniffle_cc1352p1_cc2652p1.hex"
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --old-cp2102) VARIANT="sniffle_cc1352p1_cc2652p1_1M.hex"; shift;;
    -h|--help) sed -n '2,15p' "$0"; exit 0;;
    *) echo "unknown option $1" >&2; exit 2;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
command -v lsusb >/dev/null || { echo "install usbutils first" >&2; exit 1; }
if ! lsusb -d 10c4:ea60 >/dev/null 2>&1; then
  echo "No Silicon Labs CP210x dongle found (10c4:ea60). Is the SONOFF dongle plugged in?" >&2; exit 1
fi
if [ "$(lsusb -d 10c4:ea60 | wc -l)" -gt 1 ]; then
  echo "More than one CP210x USB-serial device is plugged in (some LoRa/ESP32 boards use the same chip)." >&2
  echo "Unplug everything except the SONOFF dongle so the wrong board can't be flashed, then run again." >&2
  exit 1
fi
[ -e "$PORT" ] || { echo "$PORT not found. Pass --port (ls /dev/ttyUSB*)" >&2; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
echo "==> Downloading the latest Sniffle release firmware ($VARIANT)"
# Asset names can carry a version; match the board's build, with or without the 921600 (_1M) suffix
ASSETS="$(curl -fsSL https://api.github.com/repos/nccgroup/Sniffle/releases/latest \
          | grep -oE '"browser_download_url": *"[^"]+"' | sed -E 's/.*"(https[^"]+)"/\1/' \
          | grep -E '/sniffle_cc1352p1_cc2652p1[^/]*\.hex$')"
if [ "$VARIANT" = "sniffle_cc1352p1_cc2652p1_1M.hex" ]; then URL="$(echo "$ASSETS" | grep -E '_1M[^/]*\.hex$' | head -1)"
else URL="$(echo "$ASSETS" | grep -vE '_1M[^/]*\.hex$' | head -1)"; fi
[ -n "$URL" ] || { echo "Couldn't find $VARIANT in the latest Sniffle release." >&2; exit 1; }
curl -fsSL -o "$WORK/$VARIANT" "$URL"

echo "==> Getting cc2538-bsl (the fork Sniffle recommends: it resets the chip after flashing)"
git clone -q --depth 1 https://github.com/sultanqasim/cc2538-bsl "$WORK/bsl"

echo
echo "About to flash $VARIANT to the dongle on $PORT."
echo "This replaces the Zigbee firmware. Don't unplug it until this finishes."
read -rp "Type FLASH to continue: " ans
[ "$ans" = "FLASH" ] || { echo "Cancelled."; exit 0; }

python3 -c 'import intelhex' 2>/dev/null || { echo "Installing python3-intelhex (needed to read .hex files)"; apt-get install -y -qq python3-intelhex; }
# Newer libmagic reports Intel HEX as "text/x-hex", which cc2538-bsl doesn't recognise. Hide the
# magic module so it falls back to the .hex file extension (and reads the file with intelhex).
python3 -c 'import runpy, sys
sys.modules["magic"] = None
sys.argv = ["cc2538-bsl.py"] + sys.argv[1:]
runpy.run_path("'"$WORK"'/bsl/cc2538-bsl.py", run_name="__main__")' \
  -p "$PORT" --bootloader-sonoff-usb -ewv "$WORK/$VARIANT"
install -d /var/lib/havokbox && date -Is > /var/lib/havokbox/sniffle-flashed   # read by 'hb hw'
echo
echo "Done. Unplug and replug the dongle, then test: python3 /opt/sniffle/python_cli/sniff_receiver.py -s $PORT -a"
[ "$VARIANT" != "sniffle_cc1352p1_cc2652p1.hex" ] && \
  echo "You flashed the 921600 build: Sniffle tools need '-b 921600' (tell Claude so the helper passes it)."
exit 0
