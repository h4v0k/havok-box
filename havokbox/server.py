"""Dashboard server: a thin FastAPI shell over `Handlers`, which holds all the logic so it is
testable without the HTTP layer (FastAPI/uvicorn are runtime deps on the Pi only).

Endpoints (all behind the bearer token):
  GET  /api/state             -> dashboard state
  POST /api/scan    {space, mode?}
  POST /api/mode    {mode}
  POST /api/approve {task_id}
  POST /api/run     {task_id}
  GET  /api/console           -> console URL (only if enabled AND caller is on the box LAN)
  /                           -> static phone UI

Tool runs go through a single background job worker: one tool at a time (one set of radios),
and a long stealth scan never ties up the HTTP request or the dashboard.

The dashboard is the ONLY writer of approvals. There is no arbitrary-command endpoint; the
Console is the one explicit, logged escape hatch.
"""
from __future__ import annotations

import collections
import hmac
import queue
import subprocess
import threading
import time

from .config import MODES, BoxConfig
from .store import new_id

SPACES = ("wired", "wifi")


# ---------------------------------------------------------------------------
# Job worker
# ---------------------------------------------------------------------------
class Jobs:
    def __init__(self, store, history: int = 20, start: bool = True):
        self.store = store
        self.q: queue.Queue = queue.Queue()
        self.recent = collections.deque(maxlen=history)
        self.running = None
        self._lock = threading.Lock()
        if start:
            threading.Thread(target=self._loop, daemon=True, name="havokbox-jobs").start()

    def submit(self, label: str, fn) -> dict:
        job = {"id": new_id(), "label": label, "status": "queued", "submitted": time.time()}
        with self._lock:
            self.recent.appendleft(job)
        self.q.put((job, fn))
        return job

    def run_one(self, timeout: float | None = None) -> bool:
        """Run the next job (used by the loop, and directly by tests)."""
        try:
            job, fn = self.q.get(timeout=timeout)
        except queue.Empty:
            return False
        with self._lock:
            job["status"] = "running"
            self.running = job
        try:
            res = fn() or {}
            job["status"] = res.get("status", "ok")
            job["detail"] = res.get("summary") or res.get("reason") or ""
        except Exception as exc:  # a job crash must not kill the worker
            job["status"], job["detail"] = "error", str(exc)
            self.store.log("error", f"job {job['label']}: {exc}")
        finally:
            job["finished"] = time.time()
            with self._lock:
                self.running = None
        return True

    def _loop(self) -> None:
        while True:
            self.run_one()

    def snapshot(self) -> dict:
        with self._lock:
            return {"running": dict(self.running) if self.running else None,
                    "jobs": [dict(j) for j in self.recent]}


# ---------------------------------------------------------------------------
# Handlers — all the server logic, HTTP-free
# ---------------------------------------------------------------------------
class Handlers:
    def __init__(self, api, cfg: BoxConfig, jobs: Jobs):
        self.api = api
        self.cfg = cfg
        self.jobs = jobs

    # ---- auth -------------------------------------------------------------
    def authorized(self, auth_header: str | None) -> bool:
        if not self.cfg.token:          # no token configured -> fail closed
            return False
        if not auth_header or not auth_header.startswith("Bearer "):
            return False
        return hmac.compare_digest(auth_header[7:].encode(), self.cfg.token.encode())

    # ---- endpoints --------------------------------------------------------
    def state(self) -> tuple[int, dict]:
        st = self.api.state()
        st.update(self.jobs.snapshot())
        st["console_enabled"] = self.cfg.console_enabled
        return 200, st

    def scan(self, body: dict) -> tuple[int, dict]:
        space = (body or {}).get("space")
        mode = (body or {}).get("mode") or self.api.mode
        if space not in SPACES:
            return 400, {"status": "error", "reason": f"unknown space: {space!r}"}
        if mode not in MODES:
            return 400, {"status": "error", "reason": f"unknown mode: {mode!r}"}
        job = self.jobs.submit(f"Scan {space} [{mode}]", lambda: self.api.scan(space, mode))
        return 202, {"status": "queued", "job_id": job["id"]}

    def mode(self, body: dict) -> tuple[int, dict]:
        mode = (body or {}).get("mode")
        if mode not in MODES:
            return 400, {"status": "error", "reason": f"unknown mode: {mode!r}"}
        self.api.set_mode(mode)
        return 200, {"status": "ok", "mode": mode}

    def _task_id(self, body) -> str | None:
        tid = (body or {}).get("task_id")
        return tid if isinstance(tid, str) and 0 < len(tid) <= 64 else None

    def approve(self, body: dict) -> tuple[int, dict]:
        tid = self._task_id(body)
        if not tid:
            return 400, {"status": "error", "reason": "task_id required"}
        res = self.api.approve(tid)
        return (404 if res["status"] == "not_found" else 200), res

    def run(self, body: dict) -> tuple[int, dict]:
        tid = self._task_id(body)
        if not tid:
            return 400, {"status": "error", "reason": "task_id required"}
        if self.api._find_proposal(tid) is None:
            return 404, {"status": "not_found"}
        job = self.jobs.submit(f"Run {tid[:8]}", lambda: self.api.run(tid))
        return 202, {"status": "queued", "job_id": job["id"]}

    def console(self, client_ip: str | None, host: str | None) -> tuple[int, dict]:
        if not self.cfg.console_enabled:
            return 404, {"status": "disabled"}
        if not self.cfg.on_lan(client_ip):
            self.api.store.log("refused", f"console requested from off-LAN {client_ip}")
            return 403, {"status": "forbidden", "reason": "console is box-LAN only"}
        hostname = (host or "").split(":")[0] or "127.0.0.1"
        self.api.store.log("console", f"console link issued to {client_ip}")
        return 200, {"status": "ok", "url": f"http://{hostname}:{self.cfg.console_port}/"}


# ---------------------------------------------------------------------------
# Real runner + wiring (Pi only)
# ---------------------------------------------------------------------------
def make_runner(timeout_s: float):
    def runner(cmd: list[str]) -> str:
        # argv list, never a shell string; built only by registered tools.
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
        return out.stdout
    return runner


def build(cfg: BoxConfig | None = None):
    """Wire the real box: store, scope, orchestrator, api, jobs, drainer."""
    from .api import Api
    from .commander import ApiCommander
    from .drain import Drainer
    from .orchestrator import Orchestrator
    from .scope import load_scope
    from .store import Store
    from .tools.registry import default_registry

    cfg = cfg or BoxConfig.load()
    store = Store(cfg.db_path)
    scope = load_scope(cfg.scope_path)
    registry = default_registry()
    orch = Orchestrator(scope, store, registry, make_runner(cfg.session_limit_s))
    api = Api(scope, store, orch, mode=cfg.default_mode)
    jobs = Jobs(store)
    commander = ApiCommander(cfg.anthropic_api_key, cfg.commander_model,
                             cfg.commander_max_calls_per_day, registry)
    drainer = Drainer(store, commander, registry, scope)
    threading.Thread(target=drainer.run_forever, args=(cfg.drain_interval_s,),
                     daemon=True, name="havokbox-drain").start()
    return Handlers(api, cfg, jobs)


def create_app(handlers: Handlers | None = None):
    from pathlib import Path

    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from fastapi.staticfiles import StaticFiles

    h = handlers or build()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.url.path.startswith("/api/") and not h.authorized(
                request.headers.get("authorization")):
            return JSONResponse({"status": "unauthorized"}, status_code=401)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    async def body(request: Request) -> dict:
        try:
            data = await request.json()
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    def reply(result):
        code, payload = result
        return JSONResponse(payload, status_code=code)

    @app.get("/api/state")
    def get_state():
        return reply(h.state())

    @app.post("/api/scan")
    async def post_scan(request: Request):
        return reply(h.scan(await body(request)))

    @app.post("/api/mode")
    async def post_mode(request: Request):
        return reply(h.mode(await body(request)))

    @app.post("/api/approve")
    async def post_approve(request: Request):
        return reply(h.approve(await body(request)))

    @app.post("/api/run")
    async def post_run(request: Request):
        return reply(h.run(await body(request)))

    @app.get("/api/console")
    def get_console(request: Request):
        ip = request.client.host if request.client else None
        return reply(h.console(ip, request.headers.get("host")))

    static = Path(__file__).parent / "static"
    app.mount("/", StaticFiles(directory=static, html=True), name="ui")
    return app


def main() -> None:  # pragma: no cover - Pi entry point
    import uvicorn

    cfg = BoxConfig.load()
    uvicorn.run(create_app(build(cfg)), host="0.0.0.0", port=8080, log_level="warning")


if __name__ == "__main__":  # pragma: no cover
    main()
