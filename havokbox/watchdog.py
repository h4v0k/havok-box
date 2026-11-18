"""Watchdog — non-AI supervisor (req 4).

- On boot: void every approval not yet consumed (fail-closed; architecture §4).
- Supervise the dashboard/orchestrator process; restart it if it dies. Every restart voids
  unconsumed approvals again, so an approved-but-unrun action must be re-approved.
- Crash-loop guard: too many restarts in a window -> clean shutdown instead of thrashing.
- Enforce the session time limit -> clean shutdown.
- Clean shutdown: stop the console + server (TERM, then KILL), log, checkpoint the WAL, sync.
- If the Console is enabled in config, also run ttyd (box-LAN interface, same token).

Everything external (process spawn, clock, sleep, power-off) is injected so it is unit-testable.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

from .config import BoxConfig
from .store import Store

SERVER_CMD = [sys.executable, "-m", "havokbox.server"]


def console_cmd(cfg: BoxConfig) -> list[str] | None:
    """ttyd bound to the box-LAN interface, basic-auth with the dashboard token. None = don't run."""
    if not cfg.console_enabled or not cfg.token:
        return None
    return ["ttyd", "-W", "-i", cfg.console_iface, "-p", str(cfg.console_port),
            "-c", f"havok:{cfg.token}", sys.executable, "-m", "havokbox.console_session"]


class Watchdog:
    def __init__(self, cfg: BoxConfig, store_factory=None, spawn=None, clock=time.monotonic,
                 sleep=time.sleep, poweroff=None, max_restarts: int = 5, window_s: float = 300,
                 backoff_s: float = 2.0):
        self.cfg = cfg
        self.store_factory = store_factory or (lambda: Store(cfg.db_path))
        self.spawn = spawn or (lambda cmd: subprocess.Popen(cmd))
        self.clock = clock
        self.sleep = sleep
        self.poweroff = poweroff
        self.max_restarts = max_restarts
        self.window_s = window_s
        self.backoff_s = backoff_s
        self.server = None
        self.console = None
        self.started = None
        self.restarts: list[float] = []
        self.stopped = False
        self.stop_reason = None

    # ---- helpers ------------------------------------------------------------
    def _with_store(self, fn):
        store = self.store_factory()
        try:
            return fn(store)
        finally:
            store.close()

    def _void(self, why: str) -> int:
        def go(store):
            n = store.void_unconsumed_approvals()
            store.log("watchdog", f"{why}: voided {n} unconsumed approval(s)")
            return n
        return self._with_store(go)

    def _log(self, kind, detail) -> None:
        self._with_store(lambda s: s.log(kind, detail))

    # ---- lifecycle ----------------------------------------------------------
    def boot(self) -> None:
        self._void("boot")
        self.started = self.clock()
        self.server = self.spawn(SERVER_CMD)
        ccmd = console_cmd(self.cfg)
        if ccmd:
            self.console = self.spawn(ccmd)
            self._log("console", f"console enabled on {self.cfg.console_iface}:{self.cfg.console_port}")

    def tick(self) -> bool:
        """One supervision step. Returns False once the watchdog has shut down."""
        if self.stopped:
            return False
        now = self.clock()
        if now - self.started >= self.cfg.session_limit_s:
            self.shutdown(f"session time limit ({self.cfg.session_limit_s}s) reached")
            return False
        if self.server.poll() is not None:
            self.restarts = [t for t in self.restarts if now - t < self.window_s] + [now]
            if len(self.restarts) > self.max_restarts:
                self.shutdown(f"crash loop: {len(self.restarts)} restarts in {self.window_s:.0f}s")
                return False
            # The dead process can't write; void before the new one comes up (fail-closed).
            self._void(f"server exited ({self.server.poll()}), restarting")
            self.sleep(self.backoff_s)
            self.server = self.spawn(SERVER_CMD)
        if self.console is not None and self.console.poll() is not None:
            self._log("console", "console exited, restarting")
            self.console = self.spawn(console_cmd(self.cfg))
        return True

    @staticmethod
    def _stop(proc, grace: float = 10.0) -> None:
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=grace)
        except Exception:
            proc.kill()

    def shutdown(self, reason: str) -> None:
        if self.stopped:
            return
        self.stopped, self.stop_reason = True, reason
        self._stop(self.console)
        self._stop(self.server)

        def finish(store):
            store.log("watchdog", f"clean shutdown: {reason}")
            store.cx.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self._with_store(finish)
        try:
            os.sync()
        except AttributeError:  # pragma: no cover
            pass
        if self.poweroff:
            self.poweroff()

    def run(self, interval_s: float = 2.0) -> None:  # pragma: no cover - Pi entry point
        signal.signal(signal.SIGTERM, lambda *_: self.shutdown("SIGTERM"))
        signal.signal(signal.SIGINT, lambda *_: self.shutdown("SIGINT"))
        self.boot()
        while self.tick():
            self.sleep(interval_s)


def main() -> None:  # pragma: no cover
    Watchdog(BoxConfig.load()).run()


if __name__ == "__main__":  # pragma: no cover
    main()
