"""The tool manifest: the single place that says which tools exist, what gate category each
runs under, and what typed params each takes. The orchestrator runs only what's declared here.
"""
from __future__ import annotations

from . import ToolSpec, kismet, nmap


def default_registry() -> dict[str, ToolSpec]:
    specs = [
        ToolSpec(
            name="nmap.discovery",
            category="recon.discovery",
            params={"network": {"type": "cidr", "required": True}},
            fn=nmap.discovery,
            space="wired",
        ),
        ToolSpec(
            name="nmap.services",
            category="recon.active",
            params={"ip": {"type": "ip", "required": True}},
            fn=nmap.services,
            space="wired",
        ),
        ToolSpec(
            name="kismet.scan",
            category="recon.passive",
            params={},
            fn=kismet.scan,
            space="wifi",
        ),
    ]
    return {s.name: s for s in specs}
