"""Dashboard server: a thin Starlette shell over `Handlers`, which holds all the logic so it is
testable without the HTTP layer (Starlette/uvicorn are runtime deps on the Pi only).

Endpoints (all behind the bearer token):
  GET  /api/state
  POST /api/scan    {space, mode?}       -> 202 {job_id} | 200 needs_approval | 409 unavailable
  POST /api/mode    {mode}
  POST /api/approve {task_id, digest}    -> refused unless digest == the command shown
  POST /api/run     {task_id}            -> 409 "approve first" unless a matching approval exists
  GET  /api/jobs/{id}
  GET  /api/console                      -> console URL (enabled + box LAN + TLS only)
  /                                      -> static phone UI

Jobs run on one worker thread per lane (lane = signal space): one radio/NIC job at a time per
space, different spaces concurrently. One process, one worker, so the store stays the single
writer. The dashboard is the ONLY writer of approvals. There is no arbitrary-command endpoint;
the Console is the one explicit, logged escape hatch.
"""
from __future__ import annotations

import collections
import hmac
import os
import subprocess
import threading
import time

from .config import MODES, BoxConfig
from .store import new_id

SPACES = ("wired", "wifi", "ble", "subghz", "sdr", "esp")


# ---------------------------------------------------------------------------
# Job runner — one worker per lane
# ---------------------------------------------------------------------------
class Jobs:
    def __init__(self, store, history: int = 30, start: bool = True):
        self.store = store
        self.start = start
        self.lanes: dict[str, collections.deque] = {}
        self.recent = collections.deque(maxlen=history)
        self.running: dict[str, dict] = {}
        self._cv = threading.Condition()

    def submit(self, label: str, fn, lane: str = "default") -> dict:
        job = {"id": new_id(), "label": label, "lane": lane, "status": "queued",
               "submitted": time.time()}
        with self._cv:
            self.recent.appendleft(job)
            if lane not in self.lanes:
                self.lanes[lane] = collections.deque()
                if self.start:
                    threading.Thread(target=self._loop, args=(lane,), daemon=True,
                                     name=f"havokbox-jobs-{lane}").start()
            self.lanes[lane].append((job, fn))
            self._cv.notify_all()
        return job

    def pending(self) -> int:
        with self._cv:
            return sum(len(q) for q in self.lanes.values())

    def run_one(self, lane: str | None = None) -> bool:
        """Run the next job in `lane` (or any lane). Used by the lane loops and by tests."""
        with self._cv:
            for ln in ([lane] if lane else list(self.lanes)):
                q = self.lanes.get(ln)
                if q:
                    job, fn = q.popleft()
                    job["status"] = "running"
                    self.running[ln] = job
                    break
            else:
                return False
        try:
            res = fn() or {}
            job["status"] = res.get("status", "ok")
            job["detail"] = res.get("summary") or res.get("reason") or ""
        except Exception as exc:  # a job crash must not kill the worker
            job["status"], job["detail"] = "error", str(exc)
            self.store.log("error", f"job {job['label']}: {exc}")
        finally:
            job["finished"] = time.time()
            with self._cv:
                self.running.pop(job["lane"], None)
        return True

    def _loop(self, lane: str) -> None:
        while True:
            with self._cv:
                while not self.lanes[lane]:
                    self._cv.wait()
            self.run_one(lane)

    def get(self, job_id: str) -> dict | None:
        with self._cv:
            for j in self.recent:
                if j["id"] == job_id:
                    return dict(j)
        return None

    def snapshot(self) -> dict:
        with self._cv:
            return {"running": [dict(j) for j in self.running.values()],
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
        st["console_enabled"] = self.cfg.console_enabled_now()
        return 200, st

    def scan(self, body: dict) -> tuple[int, dict]:
        body = body or {}
        space = body.get("space")
        mode = body.get("mode") or self.api.mode
        if space not in SPACES:
            return 400, {"status": "error", "reason": f"unknown space: {space!r}"}
        if mode not in MODES:
            return 400, {"status": "error", "reason": f"unknown mode: {mode!r}"}
        action = body.get("action")
        if action is not None and not (isinstance(action, str) and action.isalpha() and len(action) <= 16):
            return 400, {"status": "error", "reason": "bad action"}
        try:
            prep = self.api.prepare_scan(space, mode, action)   # task + mode built HERE, not in the job
        except ValueError as exc:
            return 400, {"status": "error", "reason": str(exc)}
        if prep["status"] == "unavailable":
            return 409, prep
        if prep["status"] == "refused":
            return 403, prep
        if prep["status"] == "needs_approval":
            return 200, prep
        task = prep["task"]
        job = self.jobs.submit(f"{task['label']} [{mode}]", lambda: self.api.execute_scan(task),
                               lane=space)
        return 202, {"status": "queued", "job_id": job["id"]}

    def mode(self, body: dict) -> tuple[int, dict]:
        mode = (body or {}).get("mode")
        if mode not in MODES:
            return 400, {"status": "error", "reason": f"unknown mode: {mode!r}"}
        self.api.set_mode(mode)
        return 200, {"status": "ok", "mode": mode}

    @staticmethod
    def _str(body, key, maxlen=64) -> str | None:
        v = (body or {}).get(key)
        return v if isinstance(v, str) and 0 < len(v) <= maxlen else None

    def approve(self, body: dict) -> tuple[int, dict]:
        tid = self._str(body, "task_id")
        dg = self._str(body, "digest")
        if not tid or not dg:
            return 400, {"status": "error", "reason": "task_id and digest required"}
        res = self.api.approve(tid, dg)
        return {"not_found": 404, "stale": 409}.get(res["status"], 200), res

    def run(self, body: dict) -> tuple[int, dict]:
        tid = self._str(body, "task_id")
        if not tid:
            return 400, {"status": "error", "reason": "task_id required"}
        t = self.api._find_proposal(tid)
        if t is None:
            return 404, {"status": "not_found"}
        if self.api.needs_approval(t) and not self.api.approval_ok(tid):
            return 409, {"status": "error", "reason": "approve first"}   # nothing queued
        spec = self.api.registry.get(t.get("tool"))
        lane = getattr(spec, "space", "") or "default"
        job = self.jobs.submit(t.get("label") or tid[:8], lambda: self.api.run(tid), lane=lane)
        return 202, {"status": "queued", "job_id": job["id"]}

    def job(self, job_id: str) -> tuple[int, dict]:
        j = self.jobs.get(job_id)
        return (200, j) if j else (404, {"status": "not_found"})

    def console(self, client_ip: str | None) -> tuple[int, dict]:
        if not self.cfg.console_enabled_now():
            return 404, {"status": "disabled"}
        if not self.cfg.on_lan(client_ip):
            self.api.store.log("refused", f"console requested from off-LAN {client_ip}")
            return 403, {"status": "forbidden", "reason": "console is box-LAN only"}
        if not self.cfg.console_password or not self.cfg.tls_ready():
            return 503, {"status": "error", "reason": "console needs console_password and TLS cert"}
        self.api.store.log("console", f"console link issued to {client_ip}")
        return 200, {"status": "ok", "url": f"https://{self.cfg.box_address}:{self.cfg.console_port}/"}


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
    # Fail-closed even when started without the watchdog (manual run, bare systemd unit).
    n = store.void_unconsumed_approvals()
    store.log("server", f"start: voided {n} unconsumed approval(s)")
    scope = load_scope(cfg.scope_path)
    registry = default_registry()
    orch = Orchestrator(scope, store, registry, make_runner(cfg.tool_timeout_s), hw=cfg.hardware())
    api = Api(scope, store, orch, mode=cfg.default_mode)
    jobs = Jobs(store)
    commander = ApiCommander(cfg.anthropic_api_key, cfg.commander_model,
                             cfg.commander_max_calls_per_day, registry,
                             counter_path=os.path.join(os.path.dirname(cfg.db_path), "commander-cap.json"))
    drainer = Drainer(store, commander, registry, scope)
    threading.Thread(target=drainer.run_forever, args=(cfg.drain_interval_s,),
                     daemon=True, name="havokbox-drain").start()
    return Handlers(api, cfg, jobs)


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
                               "base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app(handlers: Handlers | None = None):
    from pathlib import Path

    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from starlette.staticfiles import StaticFiles

    h = handlers or build()

    class Guard(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.url.path.startswith("/api/") and not h.authorized(
                    request.headers.get("authorization")):
                resp = JSONResponse({"status": "unauthorized"}, status_code=401)
            else:
                resp = await call_next(request)
            resp.headers.update(SECURITY_HEADERS)
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

    async def get_state(request):
        return reply(h.state())

    async def post_scan(request):
        return reply(h.scan(await body(request)))

    async def post_mode(request):
        return reply(h.mode(await body(request)))

    async def post_approve(request):
        return reply(h.approve(await body(request)))

    async def post_run(request):
        return reply(h.run(await body(request)))

    async def get_job(request):
        return reply(h.job(request.path_params["job_id"]))

    async def get_console(request):
        return reply(h.console(request.client.host if request.client else None))

    static = Path(__file__).parent / "static"
    routes = [
        Route("/api/state", get_state),
        Route("/api/scan", post_scan, methods=["POST"]),
        Route("/api/mode", post_mode, methods=["POST"]),
        Route("/api/approve", post_approve, methods=["POST"]),
        Route("/api/run", post_run, methods=["POST"]),
        Route("/api/jobs/{job_id}", get_job),
        Route("/api/console", get_console),
        Mount("/", StaticFiles(directory=static, html=True)),
    ]
    return Starlette(routes=routes, middleware=[Middleware(Guard)])


def tls_args(cfg: BoxConfig) -> dict:
    """TLS fails closed (design-check #5)."""
    if cfg.tls_ready():
        return {"ssl_certfile": cfg.tls_cert, "ssl_keyfile": cfg.tls_key}
    if cfg.allow_insecure_http:
        return {}
    raise SystemExit(f"refusing to start: no TLS cert/key at {cfg.tls_cert} / {cfg.tls_key} "
                     "(run `python3 -m havokbox.provision`, or set allow_insecure_http: true)")


def main() -> None:  # pragma: no cover - Pi entry point
    import uvicorn

    cfg = BoxConfig.load()
    ssl = tls_args(cfg)
    uvicorn.run(create_app(build(cfg)), host="0.0.0.0", port=8443 if ssl else 8080,
                workers=1, log_level="warning", **ssl)


if __name__ == "__main__":  # pragma: no cover
    main()
