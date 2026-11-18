"""One Console session (ttyd spawns this per connection).

Logs the session start and end to the evidence store and records the full transcript with
`script`, then hashes it so the evidence log can show the transcript wasn't altered later.
This is the human-at-the-keyboard escape hatch: it bypasses the scope gate by design, which is
why it is OFF by default, box-LAN only, behind the dashboard token, and fully logged.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import time

from .config import BoxConfig
from .store import Store


def transcript_path(cfg: BoxConfig, ts: float) -> str:
    return os.path.join(cfg.evidence_dir, time.strftime("console-%Y%m%d-%H%M%S.log", time.gmtime(ts)))


def sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return "(missing)"
    return h.hexdigest()


def session(cfg: BoxConfig, run=subprocess.call, now=time.time) -> int:
    ts = now()
    path = transcript_path(cfg, ts)
    os.makedirs(cfg.evidence_dir, exist_ok=True)
    peer = os.environ.get("TTYD_CLIENT") or os.environ.get("REMOTE_ADDR") or "unknown"

    def log(detail):
        store = Store(cfg.db_path)
        try:
            store.log("console", detail)
        finally:
            store.close()

    log(f"session start from {peer}; transcript {path}")
    rc = run(["script", "-q", "-f", "-c", "bash -l", path])
    log(f"session end rc={rc}; {path} sha256={sha256(path)}")
    return rc


def main() -> None:  # pragma: no cover
    raise SystemExit(session(BoxConfig.load()))


if __name__ == "__main__":  # pragma: no cover
    main()
