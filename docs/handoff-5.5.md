# Handoff — build the Phase-1 dashboard

Lab-only recon/testing platform for a Pi 5: an AI planner proposes steps, cheap workers run one
standard tool each, a scope gate + human approval stand in front of anything active, and a
phone dashboard drives it. Read `docs/requirements.md`, `docs/architecture.md`, and
`docs/workflows.md` first. **Everything in this file is lab-only; no autonomous exploitation.**

## Already built — do NOT rebuild (reuse as-is)

- `havokbox/scope.py` — fail-closed scope gate.
- `havokbox/store.py` — the single on-box writer (SQLite/WAL): idempotent findings + queue drain,
  one-shot approvals, `void_unconsumed_approvals()`, evidence log.
- `havokbox/orchestrator.py` — runs only registered tools; binds each task to the tool's true gate
  category; validates typed params; consumes an approval before any active run.
- `havokbox/tools/` — `registry.py` (the manifest), `nmap.py`, `kismet.py`.
- `havokbox/planner.py` — rule-based next-step proposals (the offline commander seam).
- `havokbox/api.py` — backend the dashboard calls: `state()`, `scan(space, mode)`, `set_mode(mode)`,
  `approve(task_id)`, `run(task_id)`.
- `tests/` — 42 tests. Run: `python3 -m unittest discover -s tests` (keep it green).

## Your job

1. **Dashboard server** (`havokbox/server.py`, FastAPI + uvicorn) over `Api`:
   `GET /api/state` → `state()`; `POST /api/scan` {space, mode} → `scan()`; `POST /api/mode` {mode};
   `POST /api/approve` {task_id}; `POST /api/run` {task_id}; serve the static UI at `/`.
2. **Phone UI** (`havokbox/static/`): the layout in `docs/workflows.md` and the approved mockup —
   phase bar (Recon→Enumerate→Test→Report), one-tap signal-space cards, Stealth/Standard toggle in
   the header (default Stealth), findings list with the suggested next step highlighted, and an
   approval confirm sheet showing the exact command + target before Run.
3. **Watchdog** (`havokbox/watchdog.py`): on boot call `store.void_unconsumed_approvals()`; supervise
   and restart the orchestrator; enforce a session time limit; run the clean-shutdown routine.
4. **Offline drain loop**: poll `store.pending_queue()`; when online send the finding summary to the
   API commander, then `store.drain(...)` (atomic); the API commander plugs in behind `planner.plan`.
5. **Console tab**: a web terminal to the Pi, **off by default** in config, behind the same auth,
   box-LAN only, every session logged to evidence.

## Hard constraints — do not weaken

- The box is the only writer; the dashboard is the ONLY writer of approvals. Cloudflare is a one-way,
  read-only snapshot — never written back.
- Nothing active runs without a consumed approval. Add no "run arbitrary command" path except the
  explicit, logged Console.
- Parse tool output on-box; send only summaries to the API (reliability + token cost).
- No notification count badges anywhere (standing preference). Big tap targets; enlarged-text safe.

## Process (team mode)

- Build to the numbered requirements in `docs/requirements.md`.
- You should NOT need to change the data model; if you do, run an Opus design check first.
- Factor server logic so it's testable without the HTTP layer (like `api.py`); FastAPI/uvicorn are
  not installed here and can't be (network off) — unit-test against `Api`, add watchdog + drain tests.
- When done, run the review council — Requirements, Quality, Risk — on **Opus**. Fable is OFF-LIMITS
  for this cybersecurity work; use Opus wherever a reviewer/design call is needed.
- Budget ledger (per job): 12 workers, 3 council rounds, 6 Opus/Fable calls. Spent so far: 1 Opus call.
- Keep the suite green; push to `h4v0k/havok-box`.
