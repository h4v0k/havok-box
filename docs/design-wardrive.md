# Wardrive mode, follow-me detection, jamming detection — design

Receive-only additions. Nothing here transmits, connects, or runs a Test-phase tool.

## Wardrive mode

A **session** the operator starts and stops from a new **Drive** tab. While a session runs, a
`WardriveService` thread in the server process runs passive collectors in a loop and records
location-tagged **sightings**:

| Collector | Source | Cadence |
|---|---|---|
| GPS | `gpspipe -w` (gpsd JSON: TPV fix, SKY satellites/SNR) | continuous reader thread |
| Wi-Fi | Kismet REST, devices changed since last poll (`/devices/last-time/<ts>/devices.json`), same `-H @file` key | every 10 s |
| Kismet alerts | `/alerts/last-time/<ts>/alerts.json` (DEAUTHFLOOD, BCASTDISCON, etc.) | every 10 s |
| BLE | existing `ble_scan` helper in 20 s windows, extended to return company id + 16-bit service UUIDs | back-to-back |
| ESP | existing Marauder `scanap` in 15 s windows | back-to-back |
| RF floor | `rtl_power` short sweeps of watched bands (315/433/915 ISM, GPS L1 1575.42 MHz) | every 60 s |

- Every sighting is tagged with the **current GPS fix** (lat, lon, fix quality, time). No fix:
  still recorded with null position.
- **Radios are exclusive.** A running session holds the wifi, ble, esp and sdr lanes; scans on
  those lanes are refused with 409 "wardrive running". The **Test tab is off** for the session
  (Handlers.run refuses any non-`recon.passive` task while a session runs).
- The gate is unchanged: wardrive only ever runs `recon.passive` collectors.
- Stopping a session (or the watchdog session limit / clean shutdown) stops every collector.

## Storage (new tables — needs design check)

```
wardrive_sessions(id TEXT PK, started REAL, ended REAL, status TEXT, distance_m REAL, note TEXT)
devices_seen(session_id, dev_id, radio, kind, name, first_ts, last_ts, best_rssi, best_lat,
             best_lon, sightings INTEGER, PRIMARY KEY(session_id, dev_id, radio))
sightings(id INTEGER PK, session_id, ts, radio, dev_id, kind, rssi, lat, lon)   -- sparse
alerts(id INTEGER PK, ts, session_id, kind, severity, dev_id, detail, lat, lon, acked REAL)
```

- `devices_seen` is upserted on every observation (one row per device per session).
- `sightings` is **sparse**: a row is written only when a device is first seen, has moved
  > 50 m from its last stored sighting, or 5 min have passed. This bounds growth on long drives
  and is exactly what follow-me needs.
- Writer: the WardriveService is the only writer of these four tables (one writer per table,
  same store lock). Findings/approvals tables are untouched.
- Retention: sessions older than `wardrive_retention_days` (default 30) are purged on boot.
- Not published: the Cloudflare snapshot carries alerts only, never sightings (other people's
  devices and locations stay on the box).

## Follow-me detection

Runs every 60 s over the current session (and the previous sessions in the last 24 h):

- A device is **following** if it has sightings in **≥ 3 distinct places** (clusters ≥ 500 m
  apart) spanning **≥ 10 min**, and is not on the owner allowlist (`wardrive.mine`: your phone,
  watch, vehicle hotspots; plus every BSSID/BLE address in the scope file).
- **Tracker classification** (BLE advertisement data): Apple Find My (company 0x004C, type
  0x12 — AirTag / separated Find My), Tile (UUID 0xFEED), Samsung SmartTag (UUID 0xFD5A),
  Chipolo (0xFE33 / 0xFE65). Trackers following you raise a **high** alert; other devices **medium**.
- Known limit: BLE privacy addresses rotate (Find My devices away from their owner rotate roughly
  daily; phones every ~15 min), so phones rarely trip it; trackers — the real concern — do.
- **Flock / surveillance cameras**: configurable SSID/name/OUI patterns (from Guard Dog) mark
  sightings as `kind=camera`; logged and mapped, alert on proximity (low).

## Jamming / attack detection

- **Deauth / disassoc floods**: Kismet alerts → `alerts` (high), with location.
- **GPS interference** (heuristic, medium): with a prior 3D fix, satellites-used drops to ≤ 2 and
  mean SNR falls ≥ 10 dB within 30 s while the RF floor at L1 rises — or fix lost while Kismet
  still sees the same APs (not a tunnel). Reported as "possible", never certain.
- **RF noise-floor rise** (medium): a watched band's median power ≥ 15 dB above its rolling
  baseline across most of the band (not a single carrier) for 2 consecutive sweeps.

## Dashboard

- **Drive** tab: Start/Stop session, live line (fix status, distance, devices logged — plain text,
  no badges), alerts list (newest first, ack button), and an offline SVG track map (no tile
  server: CSP stays `'self'`) plotting the drive path, APs, and following devices.
- Export per session: WiGLE CSV (WigleWifi-1.4 header) and KML, via `GET /api/wardrive/export`.
- Alerts also show in Recon findings with an Alert tag.

## API

`POST /api/wardrive/start` `{note?}` · `POST /api/wardrive/stop` · `GET /api/wardrive/state`
(session, fix, track points (downsampled), devices (capped), alerts) ·
`POST /api/wardrive/ack {alert_id}` · `GET /api/wardrive/export?session=&fmt=wigle|kml`.

## Design-check resolutions (override everything above where they differ)

1. Lanes are held in `Jobs.hold()` (409 if a wifi/ble/esp/sdr/subghz job is running or queued; `run_one` re-checks). Session start voids unconsumed approvals. The orchestrator refuses any non-`recon.passive` dispatch while a session runs.
2. Collectors use pinned argv and are tested. Sniffle uses `sniff_receiver.py -a` only (a test fails if `scanner.py`, initiator or relay scripts appear). gpsd runs `-b` (read-only). Kismet uses a read-only API key and polls with relative time (`last-time/-15`) plus a `fields` filter.
3. No Marauder collector. The esp lane is held, and `stopscan` is sent at session start and at server boot.
4. Boot marks any `running` session `aborted` (never resumes). A partial unique index on running sessions prevents two Starts. Stop kills each collector's process group, joins, then writes `stopped`.
5. Data model: `device_cells` (250 m grid) replaces `sightings`; add a `track` table (25 m / 10 s); indexes `device_cells(radio, dev_id, last_ts)` and `alerts(session_id, ts)`; a per-session cap of 300k cell rows stops collection with an alert.
6. Alerts are `UNIQUE(session_id, kind, dev_id, bucket)` with a 10-minute bucket. Acks go in `alert_acks`, written only by the dashboard.
7. Collectors run outside the store lock and write batched transactions of ≤500 rows. Reads go through a separate read-only connection.
8. Durations use monotonic time; stored timestamps prefer GPS time. Purge only runs past `CLOCK_FLOOR`, in batches, child tables first, never on a running session.
9. Privacy: retention 7 days, plus per-session delete. Client and BLE ids are stored as a keyed HMAC; plaintext only for APs and alerted devices. Sniffle pcaps are deleted after parsing. Wardrive never writes `evidence` or `findings`. Published alerts carry no lat/lon or device ids.
10. Follow-me anchors on your stops: a device seen at ≥2 of your stops (≥5 min dwell, ≥2 km apart, driving between), across the current or previous 24 h of sessions. Close RSSI (> -70) raises severity. Devices present at the start are never auto-allowlisted; they are offered for confirmation.
11. Tracker fields: `btcommon.eir_ad.entry.company_id`, `.uuid_16`, `.data` and `btle.advertising_header.randomized_tx`, parsed in Python. Find My means 0x004C type 0x12 len 0x19 (separated). Also Google/DULT 0xFEAA frames 0x40/0x41, Tile 0xFEED/0xFEEC, SmartTag 0xFD5A (rotates often; documented as likely missed).
12. GPS jamming: no alert in v1. "GNSS degraded" is a track note; alert only on a receiver-reported jamming state.
13. RF floor: record only, at fixed gain with per-band medians. Any future alert is stationary-only.
14. Kismet runs with `gps=gpsd` and tags Wi-Fi itself. Exports use `kismetdb_to_wiglecsv` / `kismetdb_to_kml`. Box tables hold BLE cells, the track and alerts. Kismet deauth/disassoc alerts are medium severity, deduped per BSSID.
