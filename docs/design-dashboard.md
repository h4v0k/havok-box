# Dashboard design (Phase 1)

> **Read this first.** This doc was written before the dashboard on `main` was built
> (commits `3c3986c` and `6d1e863`), from a design check that ran on the original plan. Its file and
> function names may not match the code that was built. Use the **Design-check resolutions** below as
> a checklist: verify each safety property against the implementation on `main`, and fix any that
> aren't met. Don't rebuild to match this doc's module layout.

Addendum to `docs/architecture.md`. Covers what the dashboard build adds: the HTTP server,
background jobs, auth, the drain loop + Claude commander, the watchdog, and the console.

## Verification status (checked against `main`, Nov 2026)

| # | Status | Where / note |
|---|--------|--------------|
| 1 | Met | `tasks.task_digest`; `Api.approve(task_id, digest)` refuses a stale digest; `Api.run` re-checks the approval's digest before executing and voids it on mismatch. Approval's digest is stored in the approvals row's target JSON (no schema change). |
| 2 | Met (variant) | Approvals stay keyed by `task_id`; re-approving after a consumed/failed run replaces the old row and logs it to evidence, so a fresh approval is always created. |
| 3 | Met | `Handlers.run` returns `409 approve first` with nothing queued; scan tasks (incl. mode) built in `Handlers.scan` via `Api.prepare_scan`. Consumption stays atomic in the orchestrator. |
| 4 | Met | `textContent` only, no inline script/style, CSP + nosniff + no-referrer + `X-Frame-Options: DENY`; labels from `tasks.LABELS`; LLM text never displayed or stored as a label. |
| 5 | Met | `server.tls_args` exits without cert/key unless `allow_insecure_http`; `havokbox.provision` prints the SHA-256 fingerprint. |
| 6 | Met | `tasks.make_task` used by planner (`Api._plan_from`) and commander (`Drainer.sanitise`); unknown target keys rejected. |
| 7 | Met | `tasks.step_kind` = tool + canonical target (lowercase BSSID, canonical IP/CIDR), shared by both paths. |
| 8 | Met | Zero valid proposals marks done; errors back off 30s·2ⁿ, marked failed after 5 (`drain.MAX_ATTEMPTS`). |
| 9 | Met | Watchdog spawns children with `start_new_session` and kills the process group on shutdown and after a crash; voided approvals written to evidence first. |
| 10 | Met | Console: own password, TLS required (`-S -C -K`), off by default; documented as out-of-gate in `docs/console.md`. |
| 11 | Met | `needs_approval` from `gate.evaluate`; console flag re-read from the config file each request (config is `config/box.json`, not `box.yaml`). |

Also matched: Starlette (not FastAPI), one job lane per space, `GET /api/jobs/{id}`, `drain_many`,
locked reads, Haiku default commander model, phase tabs (Recon / Enumerate / Test / Report), and no
dead Phase-3 cards. A planner step whose tool isn't registered (e.g. `wifi.capture`) is skipped and
logged instead of shown.

## Design-check resolutions (these override the sections below where they differ)

1. **Approvals are bound to the exact command.** Every task carries its mode, stamped in code
   when the proposal is created. A proposal's **digest** = SHA-256 over {tool, category, target,
   mode, preview argv}. The confirm sheet shows the command and sends the digest it displayed;
   `approve` refuses if the proposal's current digest differs. At execution the orchestrator
   rebuilds the argv, recomputes the digest, and runs only if it matches the approval's digest.
2. **Approvals have their own id** (`approval_id`), not the task id, so re-approving after a failed
   run creates a fresh approval instead of silently doing nothing.
3. **Reserve at request time.** `POST /api/run` atomically *claims* a matching un-consumed approval
   in the request handler. No approval → `409 approve first`, and nothing is queued. The job carries
   the claimed `approval_id`; the orchestrator marks it executed exactly once (so a claim can't be
   replayed). Scan tasks, including their mode, are built in the handler, not the job thread.
4. **XSS hardening.** The UI builds DOM with `textContent` only (never `innerHTML` with data),
   ships no inline script/style, and the server sends a strict CSP plus nosniff/no-referrer/
   frame-deny headers. All proposal labels are generated in code; LLM text is never displayed.
5. **TLS fails closed.** The server refuses to start without the cert/key unless
   `allow_insecure_http: true` is set explicitly. Provisioning prints the cert's SHA-256 fingerprint.
6. **Whitelisted tasks.** Planner and commander proposals are rebuilt by one `make_task()` from
   registry data: id from `new_id()`, category from the registry, mode from the finding, target
   normalised and restricted to the tool's declared params (unknown keys are rejected).
7. **One dedupe key.** `step_kind()` = tool + canonical target (lowercase BSSIDs, canonical IPs),
   shared by both proposal paths.
8. **Drain retry is bounded.** A reply with zero valid proposals still marks the entry done; errors
   back off and the entry is marked failed after 5 attempts.
9. **No orphaned tools.** The watchdog starts the server in its own process group and kills the
   whole group on shutdown or after a crash, so an `nmap` child can't outlive its server. Voided
   approvals are written to evidence before they're removed.
10. **Console is separate.** Its own password (not the dashboard token), TLS required (refuses to
    start without the cert), off by default, and documented as out-of-gate.
11. `needs_approval` in the UI comes from `gate.evaluate`, not a hard-coded list; the console flag
    is read from `box.yaml` each time, never cached.

## Server

- **Starlette + uvicorn** (Starlette is FastAPI's foundation; both are on the box, FastAPI isn't
  needed). Run as **one process, one worker** so the store stays the single writer.
- Routes: `GET /api/state`, `POST /api/scan` {space, mode}, `POST /api/mode` {mode},
  `POST /api/approve` {task_id}, `POST /api/run` {task_id}, `GET /api/jobs/{id}`, static UI at `/`.
- All route logic lives in `havokbox/web.py` (`Handlers`), pure Python, unit-tested; `server.py`
  only maps HTTP to `Handlers`.

## Auth

- One shared **access token** (32 random bytes, urlsafe), generated on first boot into
  `config/box.yaml` (gitignored). Every `/api/*` request needs `Authorization: Bearer <token>`;
  compared with `hmac.compare_digest`. Bearer header (not a cookie) so there's no CSRF surface.
- The phone enters the token once; the UI keeps it in `localStorage`. A 401 clears it.
- **TLS**: a self-signed cert is generated at provisioning and uvicorn serves HTTPS when it
  exists, so the token isn't readable by other clients on a shared car hotspot.

## Background jobs (new runtime state)

- Tool runs can take many minutes (stealth `-T1` scans), so `scan` and `run` never execute inside
  the HTTP request. They go to an in-memory `JobRunner` with **one worker thread per lane**, where
  lane = the tool's `space` (wired, wifi). Same lane = serial (one radio/NIC job at a time);
  different lanes run concurrently.
- `POST /api/scan` and `POST /api/run` return `202 {job_id}` immediately; `state()` lists jobs so
  cards can show "scanning…". Jobs are **ephemeral** (not persisted): durable results still land
  in the store through the orchestrator exactly as today.

## Store changes

- Reads now take the same lock as writes (one shared connection, many threads).
- `drain_many(queue_id, result_id, items)`: insert N proposals **and** mark the queue entry done
  in one transaction.

## Proposals: two writer paths, one key

1. **Planner** (offline, immediate): after every new finding, `Api` runs `planner.plan`.
2. **Claude commander** (online, via the drain loop): see below.

Both write with `INSERT OR IGNORE` keyed on `(result_id, step_kind)`. `step_kind` is always
**derived in code** from tool + target (`"nmap.services:10.10.0.50"`), never taken from the LLM,
so both paths dedupe onto the same row. Only `Api.run` changes a proposal's status.

## Mode stamping (approve exactly what runs)

- A proposal **inherits the mode of the finding that spawned it**. The confirm sheet previews the
  command for that mode, and the run uses that same mode. Flipping the header toggle affects new
  scans only — never an already-previewed proposal.
- `ToolSpec.preview(task, ctx) -> argv` is built from the same command builders the tool runs.

## Drain loop + Claude commander

- On each new finding, `Api` enqueues an `analysis` entry holding a **compact digest** of the
  parsed finding (IPs, open ports + service names, SSID/BSSID/channel, evil twins), capped in
  size. Raw tool output never leaves the box.
- A `Drainer` thread polls the queue. If online and an API key is configured, it sends the digest
  plus the tool menu (name, category, params from the registry) to Claude and asks for JSON
  proposals. Every returned proposal is **validated in code**: tool must exist in the registry;
  `category` is taken from the registry (never from the LLM); params must pass `validate_params`;
  the gate must allow it. Invalid ones are dropped and logged. Survivors are written with
  `drain_many` (atomic). On any API/parse error the entry stays pending and is retried later.
- Default model: `claude-haiku-5-5` (configurable). API key from `ANTHROPIC_API_KEY`, never sent to
  the UI or logged. The commander only *proposes*; the gate + a consumed approval still stand
  between any proposal and an active run.

## Watchdog

- Parent process. On **every** (re)start of the server it first voids unconsumed approvals (store
  opened, voided, closed before the child starts — no concurrent access), then spawns the server.
- Restarts a crashed server with backoff, up to N restarts per window, then stops and logs.
- Enforces a session time limit, then runs the clean shutdown: SIGTERM the child, wait, optional
  poweroff.

## Console

- Off by default (`console.enabled: false`). When enabled: `ttyd` bound to the box LAN interface,
  credential = the dashboard token, the shell wrapped in `script` so every session is recorded to
  the evidence directory, and a `console` evidence entry is logged. The UI shows the Console tab
  only when enabled.

## Phase-1 scope of the UI

- Signal cards appear only for spaces that have a registered scan tool (Wi-Fi, Wired today). BLE,
  sub-GHz, spectrum and ESP cards arrive with their workers in Phase 3 — no dead buttons.
- Phase tabs: Recon (cards + findings), Enumerate (`recon.*` proposals), Test (active-category
  proposals), Report (findings + evidence timeline). No counts on tabs.
