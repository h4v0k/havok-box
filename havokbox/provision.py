"""First-boot provisioning: dashboard token + self-signed TLS cert.

- Generates a 32-byte urlsafe access token into the box config if it has none.
- Generates a self-signed cert/key (openssl) if missing and prints its SHA-256 fingerprint so you
  can check it on the phone the first time you connect.
Config and key files are written 0600. Safe to re-run: existing token/cert are kept.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess

from .config import BoxConfig


def ensure_token(path: str) -> str:
    data = {}
    if os.path.exists(path):
        with open(path) as fh:
            data = json.load(fh)
    if not data.get("token"):
        data["token"] = secrets.token_urlsafe(32)
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
    return data["token"]


def ensure_cert(cfg: BoxConfig, run=subprocess.run) -> str:
    if not cfg.tls_ready():
        os.makedirs(os.path.dirname(cfg.tls_cert), exist_ok=True)
        run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-days", "825", "-subj", "/CN=havok-box",
             "-addext", f"subjectAltName=IP:{cfg.box_address}",
             "-keyout", cfg.tls_key, "-out", cfg.tls_cert], check=True, capture_output=True)
        os.chmod(cfg.tls_key, 0o600)
    out = run(["openssl", "x509", "-in", cfg.tls_cert, "-noout", "-fingerprint", "-sha256"],
              check=True, capture_output=True, text=True)
    return out.stdout.strip().split("=", 1)[-1]


def main() -> None:  # pragma: no cover
    path = os.environ.get("HAVOKBOX_CONFIG", "config/box.json")
    ensure_token(path)
    cfg = BoxConfig.load(path)
    fp = ensure_cert(cfg)
    print(f"config: {path} (token stored there, 0600)")
    print(f"cert:   {cfg.tls_cert}")
    print(f"SHA-256 fingerprint: {fp}")


if __name__ == "__main__":  # pragma: no cover
    main()
