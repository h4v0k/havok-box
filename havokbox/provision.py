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
    changed = False
    for key in ("token", "guard_token"):     # dashboard token + tablet-only token (Guard #4)
        if not data.get(key):
            data[key] = secrets.token_urlsafe(32)
            changed = True
    if changed:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
    return data["token"]


def ca_paths(cfg: BoxConfig) -> tuple[str, str]:
    d = os.path.dirname(cfg.tls_cert)
    return os.path.join(d, "box-ca.crt"), os.path.join(d, "box-ca.key")


def ensure_cert(cfg: BoxConfig, run=subprocess.run) -> str:
    """A small box CA signs the server cert. Install box-ca.crt on the tablet/phone once and the
    browser treats the box as a secure context (Wake Lock etc., Guard #4)."""
    ca_crt, ca_key = ca_paths(cfg)
    os.makedirs(os.path.dirname(cfg.tls_cert), exist_ok=True)
    if not (os.path.exists(ca_crt) and os.path.exists(ca_key)):
        run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-days", "3650", "-subj", "/CN=havok-box local CA",
             "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", ca_key, "-out", ca_crt], check=True, capture_output=True)
        os.chmod(ca_key, 0o600)
    if not cfg.tls_ready():
        csr = cfg.tls_cert + ".csr"
        ext = cfg.tls_cert + ".ext"
        run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-subj", "/CN=havok-box", "-keyout", cfg.tls_key, "-out", csr],
            check=True, capture_output=True)
        with open(ext, "w") as fh:
            fh.write(f"subjectAltName=IP:{cfg.box_address}\nextendedKeyUsage=serverAuth\n"
                     "basicConstraints=CA:FALSE\n")
        run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
             "-CAcreateserial", "-days", "397", "-sha256", "-extfile", ext, "-out", cfg.tls_cert],
            check=True, capture_output=True)
        for f in (csr, ext):
            try:
                os.remove(f)
            except OSError:
                pass
        os.chmod(cfg.tls_key, 0o600)
    out = run(["openssl", "x509", "-in", ca_crt, "-noout", "-fingerprint", "-sha256"],
              check=True, capture_output=True, text=True)
    return out.stdout.strip().split("=", 1)[-1]


def main() -> None:  # pragma: no cover
    path = os.environ.get("HAVOKBOX_CONFIG", "config/box.json")
    ensure_token(path)
    cfg = BoxConfig.load(path)
    fp = ensure_cert(cfg)
    print(f"config: {path} (token stored there, 0600)")
    print(f"cert:   {cfg.tls_cert} (signed by {ca_paths(cfg)[0]})")
    print(f"Install {ca_paths(cfg)[0]} on the tablet and phone as a trusted CA.")
    print(f"CA SHA-256 fingerprint: {fp}")
    print("Tablet: open https://<box>:8443/guard.html and enter guard_token from the config.")


if __name__ == "__main__":  # pragma: no cover
    main()
