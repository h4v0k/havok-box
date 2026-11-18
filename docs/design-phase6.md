# Phase 6 — remaining capability items (design)

Everything unbuilt from the two capability lists. All receive-only / read-only: nothing here
transmits on any radio or writes to any other device.

## 1. How-trackable-am-I report (your own vehicles)

- Built at the end of a drive ≥ 5 km. "Riding with you" = heard in ≥ 80 % of that radio's windows
  across the drive (same rule as the TPMS own-tire offer, per band / per radio).
- Per broadcaster: radio, whether the identifier is static (TPMS id, BLE public address, fixed AP
  BSSID) or rotating (BLE random), the advertised name/SSID if any, and a plain fix
  ("your hotspot broadcasts a fixed BSSID everywhere — turn it off when not needed";
  "TPMS ids can't be turned off — normal"). Passengers' devices are labelled as possibly theirs.
- Stored per drive in `exposure_reports(session_id, created, vehicle, report_json)`; plaintext only
  for devices that rode with you. Drive tab "Exposure" card; optional vehicle label at drive start.

## 2. Rayhunter (fake cell tower detection)

- EFF Rayhunter on an Orbic hotspot exposes an HTTP API (`/api/analysis`, per-recording reports;
  not guaranteed stable across versions). If the box's internet hotspot is the Orbic, a read-only
  poller (60 s) reads it and raises `cell_suspicious` alerts (high), deduped per warning/10 min.
  Never writes to the device; URL from config; off when unset. Tablet + Drive tab; drive and sentry.

## 3. Drone Remote ID

- ASTM F3411 broadcasts over BLE (service UUID 0xFFFA, 25-byte messages: Basic ID 0, Location 1,
  System 4 with operator location, Operator ID 5, pack 0xF), parsed from the BLE windows already
  running; Wi-Fi Remote ID via Kismet if it decodes it.
- Drones seen per drive (UA id, position, altitude, speed, operator position if broadcast) on the
  map; `drone` alert low, medium if within 300 m for ≥ 5 min.

## 4. Baseline drift (lab, requirement #2)

- "Learn baseline" (Recon) snapshots the in-lab inventory from findings: hosts (ip, mac), APs
  (bssid, ssid, channel), BLE, sub-GHz / rtl_433 ids → `baseline(space, key, label, learned_at)`,
  dashboard-only writer. Drift computed at read time in `Api.state()`: "New since baseline" tags,
  a Drift list (new hosts/MACs, new APs, AP channel change, new BLE/IoT ids, known IP with a new
  MAC = ARP-spoof indicator, high). "Accept" adds an item to the baseline.

## 5. ADS-B / AIS receiver (aircraft + ships)

- Two passive recon tools on the RTL-SDR lane: `sdr.adsb` (readsb/dump1090 for N seconds, JSON
  aircraft list: hex, callsign, altitude, speed, track, position, squawk) and `sdr.ais`
  (AIS-catcher JSON for N seconds: MMSI, name, type, position, speed, course).
- One SDR: these run as scans when not driving (the lane hold refuses them during a drive or
  sentry). A second RTL-SDR (configurable `sdr2` device index) lets ADS-B run alongside a drive.
- Emergency squawks (7500/7600/7700) highlighted. Findings only; nothing is forwarded anywhere.

## 6. Wi-Fi site-survey heatmaps

- Survey session (`mode='survey'`): pick your AP(s) from the scope file's BSSIDs; the box samples
  their RSSI from Kismet every 2 s.
- Positioning: outdoors, GPS; indoors, the operator taps where they're standing on a grid in the
  dashboard (no GPS indoors). Each sample is binned to the current grid cell / GPS cell.
- Output: heatmap per AP (grid or map), weak-spot list, and per-survey export (CSV). Only your
  in-scope BSSIDs are sampled.

## Design-check resolutions (override everything above where they differ)

1. Exposure windows count only when they complete without error while moving > 5 m/s. Each radio needs ≥ 30 windows; ≥ 80 % in ≥ 2 drives before a device is called "yours". Random BLE addresses are reported only as a rotating count. Per-radio window counters.
2. The exposure report is built in `stop()`/`switch_mode()` from a capped RAM accumulator (dev_key, plain id, BLE name, random flag). An aborted session gets no report. `self.plain` is limited to alerted devices plus the accumulator.
3. Plaintext appears on the live card from RAM, for the latest drive only. Stored `report_json` keeps plaintext only for ids marked mine; others are stored as {radio, static/rotating, class, dev_key}. `exposure_reports` joins `CHILD_TABLES`.
4. Rayhunter: GET only, two allowlisted paths — `/api/qmdl-manifest` (current entry) and `/api/analysis-report/<entry>` (NDJSON). Pinned release; an unknown version shows "unknown", never "clear".
5. Rayhunter reached by USB tether / dedicated interface at an RFC1918 IP over http. No redirects, 5 s timeout, 1 MB cap, only new rows parsed. Severity mapped from a fixed set: Rayhunter "high" → high, everything else medium. Dedupe on (entry, row ts, analyzer).
6. Rayhunter unreachable / not recording / rebooted shows as its own status, never all-clear. Alerts go only through `WardriveService._alert` during a session; status otherwise lives in RAM.
7. Remote ID v1 decodes BT4 legacy advertising only (`-a`). It covers add-on modules; most DJI drones use Wi-Fi beacon/NAN and are missed.
8. Remote ID data comes from the `btcommon.eir_ad.entry.service_data` field, parsed in Python.
9. RID layout: AD 0x16, UUID FA FF, app code 0x0D, counter, then a 25-byte message. Header = type (high nibble) / version. Location: lat/lon int32 LE ×1e-7, alt uint16 ×0.5−1000, speed ×0.25 (or ×0.75+63.75 with the multiplier bit), vspeed int8 ×0.5, direction + E/W bit. System: operator lat/lon ×1e-7. 0/0 and −1000 are invalid. Message packs and Wi-Fi RID are cut.
10. Operator location in RAM only (10-minute TTL); never stored. UA ids are HMAC'd; plaintext only for alerted drones.
11. Drift is computed over the latest finding per space/kind and memoised on (max finding created, max baseline rowid). The dashboard is the only writer.
12. Baseline keys: hosts by MAC (IP is an attribute, so a change is info). APs by BSSID, with a new BSSID on a baseline SSID as the evil-twin indicator; channel change is info. BLE public addresses only (random addresses as a count). Sub-GHz by model:id:channel.
13. ARP-spoof high only if the gateway's or a pinned static IP's MAC changes within the same capture, or one MAC answers for ≥ 2 baseline IPs including the gateway. Otherwise "IP reassigned" (info).
14. ADS-B: `readsb --device-type rtlsdr --device <serial> --write-json <tmpfs> --quiet`, no `--net`; parse aircraft.json, accepting `alt_baro` or `altitude`. AIS: `AIS-catcher -d <serial>` with JSON output, no UDP or web server. Short windows mostly give MMSI and position.
15. Dongles are selected by serial (`rtl_eeprom`). Every rtl_* argv takes `-d <serial>`. `sdr2` is its own lane.
16. Site survey is indoor grid-tap: 15 s dwell per cell, the median of ≥ 3 fresh samples per in-scope BSSID. Separate `surveys` / `survey_cells` tables written only by SurveyService. Holds the wifi lane only; refused during wardrive/sentry. `Jobs.held` becomes lane→owner: hold fails if any lane is held, release frees only its own lanes.
17. Cut: GPS survey mode, Wi-Fi NAN RID, RID message packs, AP channel-change as an alert, AIS during drives, the per-drive vehicle label.
