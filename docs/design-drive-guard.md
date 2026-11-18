# Phase 5 — Drive Guard (design)

Protection while driving and parked. Receive-only, like wardrive: nothing here transmits on any
radio. It builds on the wardrive service (sessions, GPS, collectors, alerts table, follow-me).

## 1. Mounted tablet display (`/guard`)

- A separate, minimal page served by the box (`static/guard.html`), opened on a tablet mounted
  in the car and joined to the box's Wi-Fi. Same bearer token; same CSP (`'self'`).
- **Glanceable**: one huge status word (ALL CLEAR / ALERT / SENTRY / NO LINK), GPS fix, speed,
  session state, and the last 3 alerts in very large type. Dark, high contrast, rem-sized.
- **Heard, not read**: high alerts flash the whole screen and are spoken with the browser's
  offline `speechSynthesis` plus a WebAudio chime; medium alerts are queued silently and spoken
  as a summary once the car stops; camera warnings speak a short "Plate reader ahead".
- **Touch locked while moving**: the page ignores taps when speed > 2 m/s; the server also refuses
  `POST /api/guard/ack` unless the box's own GPS speed < 1 m/s (not trusting the client).
- **Link watchdog**: if the page gets no successful poll for 10 s it alarms "Lost link to box"
  (box unplugged / powered off / out of range). Screen Wake Lock keeps the display on.
- Polls `GET /api/guard/state?since=<alert id>` every 2 s.

## 2. Sentry mode (parked)

- Arm from the tablet or phone: a wardrive session with `mode='sentry'`. Same collectors
  (Kismet, Sniffle BLE, rtl_433), same held radios and passive-only lock.
- Detections:
  - **Car moved**: GPS position > 50 m from the armed position (high).
  - **Lingering device**: a device not present in the first 3 minutes after arming that is then
    seen in ≥ 3 BLE/Kismet windows spanning ≥ 10 min with RSSI > -75 (medium; high if it is a
    tracker class).
  - **Tracker appears** near the car (high).
- **Phone alerts**: a Discord webhook (URL from config/env, never logged or shown). Rate-limited
  (≤ 1 message per alert key per 10 min, ≤ 20/hour), deduped, queued while offline and sent when
  the car hotspot is up. Message: alert kind, severity, short text, time, and a map link to the
  car's position (it's your own channel; configurable off).

## 3. TPMS follow detection

- During drives the RTL-SDR runs `rtl_433` on 315 MHz (US TPMS) in 50 s windows, with one
  noise-floor sweep every 10 min (the single dongle is shared; TPMS wins).
- TPMS decodes (rtl_433 `"type":"TPMS"`, `model`, `id`) become `device_cells` rows with
  `radio='tpms'`, id stored as the keyed HMAC like BLE/clients.
- Follow-me (stops-based, design-wardrive #10) treats `tpms` like other radios: a sensor ID seen
  at ≥ 2 of your stops ≥ 2 km apart → "A car's tire sensors were at N of your stops" (medium; high
  at ≥ 3 stops).
- **Your own car**: your four sensors are heard constantly. A sensor heard in ≥ 80 % of windows
  across ≥ 5 km is *offered* as "looks like your car's tires — mark as mine" (never auto-allowlisted).
  Marked IDs go to `wardrive_mine_tpms` and are skipped.

## 4. Plate-reader (ALPR) camera warnings

- Camera locations from OpenStreetMap (`surveillance:type=ALPR`, the data DeFlock contributes),
  fetched via the Overpass API for a configured bounding box (default Tampa Bay) when the box is
  online, cached on the box (`/data/havokbox/alpr.json`), refreshed weekly. ODbL attribution shown.
- Fetched data is validated (numbers in range, capped count) and treated as untrusted input.
- While driving: a camera within 300 m and within ±45° of the heading → "Plate reader ahead"
  (info), once per camera per 10 min; logged as an alert row of kind `alpr`.
- Over-the-air confirmation: configurable SSID/BLE-name/OUI patterns (copy from Guard Dog) mark
  matching Kismet/BLE devices as `kind='camera'`; a match near a mapped camera marks it confirmed.

## API

`GET /api/guard/state?since=` · `POST /api/guard/ack {alert_id}` (stationary only) ·
`POST /api/guard/sentry {arm: bool}` · `POST /api/guard/mine {dev_key}` (mark TPMS/BLE as yours) ·
`POST /api/guard/alpr/refresh`.

## Design-check resolutions (override everything above where they differ)

1. Tablet alerts: no full-screen flashing. A high alert turns the background a steady colour, plays one WebAudio chime and speaks one phrase of 6 words or fewer, at most one utterance per 20 s. Medium alerts are spoken as one summary after 60 s stationary. Plate-reader passes chime only and are never spoken.
2. The page opens on a "Start guard" screen (needed to unlock audio and speech) that works only while stationary. "Lost link" is spoken once per outage, after 3 missed polls (6 s), and is visual only after that.
3. `/api/guard/ack`, `/sentry` and `/mine` are accepted only when the box's GPS speed has been < 1.5 m/s for 5 s, or there has been no fix for > 60 s (garage). The phone's `/api/wardrive/ack` stays unrestricted (passenger).
4. Generate a box CA, install it on the tablet, and sign the leaf with it. Wake Lock is best-effort; use Android "stay awake while charging" or a kiosk browser. The tablet gets a guard-scoped token that only reaches `/api/guard/*`.
5. `wardrive_sessions.mode` ('drive'|'sentry') with a real migration. Switching from drive to sentry happens in place under the service lock without releasing lanes. Sentry is exempt from the watchdog's `session_limit_s`, with its own `sentry_limit_s` (default 14 h).
6. Car moved: the anchor is the median of the first 2 min of fixes. Alert after 3 consecutive mode≥2 fixes farther than max(75 m, 3×eph), or speed > 2 m/s for 10 s, or your own TPMS sensors being heard while armed. Parse `eph` and `track` from TPV.
7. No generic lingering-device rule. Sentry alerts only on tracker classes held ≥ 10 min with RSSI > -75, plus Kismet deauth. Quiet geofences (home, work) suppress everything except car-moved.
8. Discord: the `HAVOKBOX_DISCORD_WEBHOOK` env var only, must start with `https://discord.com/api/webhooks/`. No redirects, `allowed_mentions: {parse: []}`, honour 429 `retry_after`, 1 per key per 10 min, 20/hour. RAM queue of ≤ 50 entries, dropped after 2 h. Payload: kind, severity, text, time; the map link is opt-in, off by default.
9. Power: sentry runs BLE + GPS only (Kismet and rtl_433 off). Battery runtime shown as an estimate only.
10. TPMS: count an id only if it decodes ≥ 2× in a window from a checksummed model. Alternate 315 MHz and 433.92 MHz. Keep only model, id and RSSI. Ids are HMAC'd. TPMS follow alerts are medium at most.
11. One SDR owner thread schedules TPMS windows plus a floor sweep every 10 min; never two processes on the dongle.
12. A `wardrive_mine(radio, dev_key, label, added)` table, written only by the dashboard, merged with config. An id is offered as "your tires" only after the 80 % rule holds in ≥ 2 sessions.
13. ALPR: Overpass `node["surveillance:type"="ALPR"](bbox)`. Keep only id, lat/lon inside the bbox and direction 0–360; cap 20k; atomic write keeping the last good copy; ODbL attribution; never published. Heading from TPV `track` above 4 m/s, else the bearing over the last 50 m. Warn within 300 m, inside ±45°, distance closing, and facing you if the camera's direction is tagged. Index by grid cell.
14. ALPR passes are kept in RAM only (no alerts rows). The over-the-air "confirmed" link is cut from v1. `/api/guard/state` returns RAM state plus alerts with id > since, never track or devices.
