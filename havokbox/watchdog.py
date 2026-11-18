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
    """ttyd on the box-LAN interface with its own password. None = don't run."""
    if not cfg.console_enabled or not cfg.console_password or not cfg.tls_ready():
        return None   # off by default; needs its own password AND TLS (design-check #10)
    # Own credential, never the dashboard token (ttyd's -c is visible in /proc/*/cmdline).
    # -O: reject cross-origin websocket upgrades. Restrict :console_port to box-LAN clients with
    # the nftables rule in docs/console.md — ttyd itself can only bind an interface.
    return ["ttyd", "-W", "-O", "-S", "-C", cfg.tls_cert, "-K", cfg.tls_key,
            "-i", cfg.console_iface, "-p", str(cfg.console_port),
            "-c", f"havok:{cfg.console_password}", sys.executable, "-m", "havokbox.console_session"]


def desktop_cmd(cfg) -> list[str] | None:
    """websockify serving noVNC over TLS on the box-LAN interface, proxying to the LOCAL VNC server.
    None = don't run. Off by default; needs TLS. No secret on the argv (the VNC server holds the
    password in its own 0600 vncpasswd file); the port is restricted to the box LAN by the nftables
    rule in docs/desktop.md."""
    if not cfg.desktop_enabled or not cfg.tls_ready() or not cfg.desktop_vnc_password_set:
        return None   # won't run until a VNC password is attested (parity with the Console)
    # websockify has no ttyd-style -O origin check; the TLS cert is pinned to the box IP (SAN=IP,
    # from provision), so a DNS-rebinding page on another hostname fails cert validation. The port
    # is also box-LAN only via nftables (docs/desktop.md), and the VNC password gates the session.
    return ["websockify", "--web", cfg.novnc_web_dir,
            "--cert", cfg.tls_cert, "--key", cfg.tls_key,
            f"{cfg.box_address}:{cfg.desktop_port}", f"localhost:{cfg.desktop_vnc_port}"]


class Watchdog:
    def __init__(self, cfg: BoxConfig, store_factory=None, spawn=None, clock=time.monotonic,
                 sleep=time.sleep, poweroff=None, max_restarts: int = 5, window_s: float = 300,
                 backoff_s: float = 2.0):
        self.cfg = cfg
        self.store_factory = store_factory or (lambda: Store(cfg.db_path))
        # Each child gets its own process group so the whole group (incl. nmap children) dies
        # with it (design-check #9).
        self.spawn = spawn or (lambda cmd: subprocess.Popen(cmd, start_new_session=True))
        self.clock = clock
        self.sleep = sleep
        self.poweroff = poweroff
        self.max_restarts = max_restarts
        self.window_s = window_s
        self.backoff_s = backoff_s
        self.server = None
        self.console = None
        self.desktop = None
        self._aux_restarts = {"console": [], "desktop": []}   # bounded restarts for aux children
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
    def _limit(self) -> float:
        """Sentry (parked, Guard #5) gets its own longer limit; everything else session_limit_s."""
        def q(store):
            try:
                r = store.cx.execute("SELECT 1 FROM wardrive_sessions WHERE status='running' "
                                     "AND mode='sentry'").fetchone()
                return r is not None
            except Exception:
                return False
        try:
            sentry = self._with_store(q)
        except Exception:
            sentry = False
        if sentry:
            self._sentry_seen = True
            return getattr(self.cfg, "sentry_limit_s", self.cfg.session_limit_s)
        if getattr(self, "_sentry_seen", False):
            # Sentry just ended (disarmed to drive): the drive gets a fresh session limit
            # instead of inheriting the overnight uptime (Guard review #2).
            self._sentry_seen = False
            self.started = self.clock()
        return self.cfg.session_limit_s

    def boot(self) -> None:
        self._void("boot")
        self.started = self.clock()
        self.server = self.spawn(SERVER_CMD)
        ccmd = console_cmd(self.cfg)
        if ccmd:
            self.console = self.spawn(ccmd)
            self._log("console", f"console enabled on {self.cfg.console_iface}:{self.cfg.console_port}")
        dcmd = desktop_cmd(self.cfg)
        if dcmd:
            self.desktop = self.spawn(dcmd)
            self._log("desktop", f"remote desktop on {self.cfg.desktop_iface}:{self.cfg.desktop_port}")

    def tick(self) -> bool:
        """One supervision step. Returns False once the watchdog has shut down."""
        if self.stopped:
            return False
        now = self.clock()
        if now - self.started >= self._limit():
            self.shutdown(f"session time limit ({int(self._limit())}s) reached")
            return False
        if self.server.poll() is not None:
            self.restarts = [t for t in self.restarts if now - t < self.window_s] + [now]
            if len(self.restarts) > self.max_restarts:
                self.shutdown(f"crash loop: {len(self.restarts)} restarts in {self.window_s:.0f}s")
                return False
            # Kill any tool children the dead server left behind, then void before the new one
            # comes up (fail-closed).
            self._stop(self.server)
            self._void(f"server exited ({self.server.poll()}), restarting")
            self.sleep(self.backoff_s)
            self.server = self.spawn(SERVER_CMD)
        self.console = self._supervise_aux("console", self.console, console_cmd, now)
        self.desktop = self._supervise_aux("desktop", self.desktop, desktop_cmd, now)
        return True

    def _supervise_aux(self, name, proc, cmd_fn, now):
        """Restart a crashed console/desktop child, but stop respawning after too many in a window
        (a persistently-failing bridge must not respawn every tick forever)."""
        if proc is None or proc.poll() is None:
            return proc
        hist = [t for t in self._aux_restarts[name] if now - t < self.window_s] + [now]
        self._aux_restarts[name] = hist
        if len(hist) > self.max_restarts:
            self._log(name, f"{name} crash-looped ({len(hist)} in {self.window_s:.0f}s); not restarting")
            self._stop(proc)
            return None
        self._log(name, f"{name} exited, restarting")
        new = cmd_fn(self.cfg)
        return self.spawn(new) if new else None

    @staticmethod
    def _signal_group(proc, sig) -> bool:
        pid = getattr(proc, "pid", None)
        if not isinstance(pid, int):
            return False
        try:
            os.killpg(pid, sig)   # pgid == pid because of start_new_session
            return True
        except (ProcessLookupError, PermissionError):
            return False

    @classmethod
    def _stop(cls, proc, grace: float = 10.0) -> None:
        if proc is None:
            return
        if proc.poll() is not None:
            cls._signal_group(proc, signal.SIGKILL)   # leader gone; reap orphaned tool children
            return
        if not cls._signal_group(proc, signal.SIGTERM):
            proc.terminate()
        try:
            proc.wait(timeout=grace)
        except Exception:
            if not cls._signal_group(proc, signal.SIGKILL):
                proc.kill()

    def shutdown(self, reason: str) -> None:
        if self.stopped:
            return
        self.stopped, self.stop_reason = True, reason
        self._stop(self.desktop)
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
