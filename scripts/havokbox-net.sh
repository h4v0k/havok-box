#!/usr/bin/env bash
# havok-box network fallback (installed by kali-setup.sh as /usr/local/sbin/havokbox-net).
#
# The Pi's built-in Wi-Fi joins a known network (home Wi-Fi, car hotspot) when one is in range.
# If none connects within GRACE seconds, it turns on the box's own WPA2 network (havokbox-ap,
# 192.168.4.1). While that network is up and NOBODY is connected to it, it periodically tries the
# known networks again and switches back if one is in range. It never drops a connected client.
#
#   havokbox-net            run the watcher (systemd: havokbox-net.service)
#   havokbox-net status     show which mode the box is in
#   havokbox-net ap         force the box's own network now
#   havokbox-net client     leave the box network and try the known networks now
#
# Only the interface in IFACE is touched; the Alfa and other radios are left to the recon tools.
set -uo pipefail

IFACE="${HAVOKBOX_NET_IFACE:-wlan0}"
AP_CON="havokbox-ap"
CLIENT_PREFIX="havokbox-wifi-"
GRACE="${HAVOKBOX_NET_GRACE:-60}"          # seconds to find a known network before the AP comes up
RETRY="${HAVOKBOX_NET_RETRY:-180}"         # seconds between retries while the AP is idle

log() { echo "havokbox-net: $*"; }

active_con() { nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="$IFACE" '$2==d{print $1; exit}'; }
known_cons() {   # client profiles, highest autoconnect priority first
  nmcli -t -f NAME con show | grep "^${CLIENT_PREFIX}" | while read -r c; do
    printf '%s %s\n' "$(nmcli -g connection.autoconnect-priority con show "$c")" "$c"
  done | sort -rn | awk '{ $1=""; sub(/^ /,""); print }'
}
ap_clients() { iw dev "$IFACE" station dump 2>/dev/null | grep -c '^Station' || true; }

try_clients() {
  local c
  while read -r c; do
    [ -n "$c" ] || continue
    if nmcli --wait 25 con up "$c" ifname "$IFACE" >/dev/null 2>&1; then
      log "joined $c"
      return 0
    fi
  done < <(known_cons)
  return 1
}

start_ap() {
  if nmcli --wait 20 con up "$AP_CON" ifname "$IFACE" >/dev/null 2>&1; then
    log "no known network: box network is up (192.168.4.1)"
  else
    log "could not start the box network"
  fi
}

case "${1:-watch}" in
  status)
    a="$(active_con)"
    if [ "$a" = "$AP_CON" ]; then echo "box network ($(nmcli -g 802-11-wireless.ssid con show "$AP_CON")), clients: $(ap_clients)"
    elif [ -n "$a" ]; then echo "joined ${a#"$CLIENT_PREFIX"}"
    else echo "not connected"; fi
    exit 0;;
  ap)     nmcli con down "$(active_con)" >/dev/null 2>&1; start_ap; exit 0;;
  client) [ "$(active_con)" = "$AP_CON" ] && nmcli con down "$AP_CON" >/dev/null 2>&1
          try_clients || { log "no known network in range"; start_ap; }; exit 0;;
  watch)  ;;
  *) sed -n '2,15p' "$0"; exit 2;;
esac

# ---- watcher ----
log "watching $IFACE (grace ${GRACE}s, retry ${RETRY}s)"
waited=0
while [ "$waited" -lt "$GRACE" ]; do        # let NetworkManager autoconnect first
  a="$(active_con)"
  [ -n "$a" ] && [ "$a" != "$AP_CON" ] && break
  sleep 5; waited=$((waited + 5))
done

idle_since=$(date +%s)
empty=0
while true; do
  a="$(active_con)"
  if [ -z "$a" ]; then                      # off any network: give NM ~30s to reconnect first
    empty=$((empty + 1))
    if [ "$empty" -ge 2 ] || [ "$waited" -ge "$GRACE" ]; then
      try_clients || start_ap
      idle_since=$(date +%s); empty=0; waited=0
    fi
  elif [ "$a" = "$AP_CON" ]; then
    empty=0
    if [ "$(ap_clients)" -gt 0 ]; then
      idle_since=$(date +%s)                # someone is on the box network: never yank it
    elif [ $(( $(date +%s) - idle_since )) -ge "$RETRY" ] && [ -n "$(known_cons)" ]; then
      nmcli con down "$AP_CON" >/dev/null 2>&1
      try_clients || start_ap
      idle_since=$(date +%s)
    fi
  else
    empty=0
  fi
  sleep 15
done
