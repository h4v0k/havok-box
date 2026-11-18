# Architecture

## Components

- **Commander** (planner). Opus/Mythos. Reads findings + attack-path state, proposes the next step.
  Never runs a tool and never writes the database; it only emits a proposed task (tool + args + target).
- **Scope gate.** Pure, non-AI (`havokbox/scope.py`). Checks every proposed task against
  `config/scope.yaml`. Out-of-scope → hard refuse + log. Active actions → "needs approval". Fail-closed.
- **Orchestrator.** The **single on-box writer** of findings and attack-path state. Applies commander
  proposals, dispatches gated tasks to workers, writes their results. Nothing else writes those tables.
- **Workers.** Haiku, one per tool. Run a standard tool, parse output on-box, return a short summary to
  the orchestrator (which writes it). Never see the whole conversation.
- **Watchdog.** Non-AI. Restarts a crashed commander/orchestrator, enforces time limits, runs clean
  shutdown. On restart it **voids any approval not yet consumed** (fail-closed).
- **Dashboard (control).** Served from the box. The attack-path view and the **only** writer of the
  approvals table. Approvals are bound to one task instance and consumed once.
- **Publisher.** One-way push of a versioned, read-only snapshot to Cloudflare for review.

## Network paths

- **Car hotspot present (normal):** Pi joins the hotspot on its **built-in** Wi-Fi; the phone is on the
  same hotspot and browses to the Pi's IP. Internet (API + Cloudflare) rides the hotspot. One radio.
- **No hotspot (offline):** the built-in Wi-Fi hosts its own AP for the dashboard; agent runs playbooks
  and queues results.
- The **Alfa stays dedicated to recon** with both antennas — never split or used to host the dashboard.

## Data — single source of truth

| Data | One home | Single writer |
|------|----------|---------------|
| Scope | `config/scope.yaml` | human only (no code writer) |
| Findings / device inventory | local SQLite (encrypted) | orchestrator |
| Attack-path state + phase | local SQLite | orchestrator |
| Approvals | local SQLite | control dashboard only (bound to task id, one-shot) |
| Offline queue | local queue table | orchestrator enqueues; drain dequeues (idempotent) |
| Evidence / session log | local, append-only | any component appends (append-only, safe) |
| Cloudflare snapshot | Cloudflare | publisher (one-way, read-only, never read back in) |

## Concurrency & integrity (design-check resolutions)

1. **One on-box writer per table.** The orchestrator is the only process that writes findings and
   attack-path; the dashboard writes only approvals; evidence is append-only. SQLite in WAL mode. The
   real dual-writer risk was intra-box, not box-vs-Cloudflare — this closes it.
2. **Findings don't depend on the API.** Workers produce findings online or offline; the orchestrator
   writes them immediately. The offline queue carries commander-analysis and publish tasks, not finding
   creation — so losing connectivity never loses a finding.
3. **Offline-queue idempotency.** Every result gets a UUID `result_id` at creation. Drain: call the API,
   then in ONE SQLite transaction `INSERT OR IGNORE` the resulting attack-path proposal keyed on
   `(result_id, step_kind)` and mark the queue entry done. Crash before commit → re-drain re-sends and
   the INSERT-OR-IGNORE makes the duplicate a no-op. No double-apply, no loss on retry.
4. **Approval binding.** An approval row is `{approval_id, task_id, category, target, granted_at,
   consumed_at}`. The gate/orchestrator requires a matching approval whose `task_id` equals the exact
   proposed task instance and `consumed_at IS NULL`, and sets `consumed_at` in the same transaction that
   dispatches. One-shot: a second queued action can't reuse it; a watchdog restart voids unconsumed
   approvals, so an approved-but-unexecuted action must be re-approved.
5. **Publisher consistency.** Snapshots carry a monotonic version and are a full consistent read. A crash
   mid-publish leaves an older or partial snapshot the next publish overwrites — read-only review only,
   no box-side correctness impact.

## Scope-gate rules (fail-closed; enforced in `havokbox/scope.py`)

- `recon.passive` — allowed only if in `auto_allow`; listening only, no target needed.
- `recon.active` / `auth.attempt` / `exploit.tool` — target IP must be in `networks.include` and not in
  `networks.exclude`. Needs approval.
- `wifi.deauth` / `wifi.inject` — target BSSID must be in `wifi.bssids` (compared lowercase). Needs approval.
- `rf.replay` / `rf.transmit` — target id in `rf.subghz_ids` or `rf.ble_addresses` **and** frequency within
  an `rf.tx_bands` entry. Needs approval.
- Any category whose required target list is missing or empty → **hard refuse**. Unknown category → refuse.
- Every refusal is logged to evidence.
