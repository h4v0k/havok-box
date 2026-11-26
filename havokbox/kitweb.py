"""Desktop GUI for the command toolbox: a local-only web page (127.0.0.1) opened in the browser.

`hb kit --gui` starts this on a random localhost port with a one-time token and opens the browser.
The page can only list recipes, preview a filled command, copy it, or run it in a terminal window;
it can't take a free-form command. Requests must carry the token and a localhost Host header.
"""
from __future__ import annotations

import os
import secrets
import socket
import webbrowser
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

from . import kit

STATIC = Path(__file__).with_name("static")


def _serial_ports() -> list[str]:
    out = []
    for pat in ("/dev/serial/by-id/*", "/dev/ttyACM*", "/dev/ttyUSB*"):
        out += sorted(str(p) for p in Path("/").glob(pat.lstrip("/")))
    return out[:32]


def choices(ctx: kit.Context) -> dict:
    """Pick-lists for the form: engagement ranges, interfaces, Mine BLE, wordlists, recent hosts."""
    sc = ctx.scope
    eng = sc.engagement() if hasattr(sc, "engagement") else None
    hosts = []
    try:
        from . import hbcli
        hosts = [h["ip"] for h in hbcli.parse(hbcli.latest_xml().read_text()) if h.get("ip")][:200]
    except Exception:   # no scans yet is normal
        pass
    wls = []
    for root in kit.WORDLIST_ROOTS[:2]:
        for p in sorted(Path(root).glob("**/*.txt"))[:400] if Path(root).is_dir() else []:
            wls.append(str(p))
    return {
        "engagement": {"name": eng["name"], "networks": eng["networks"]} if eng else None,
        "target": [str(n) for n in sc.include],
        "host": [h for h in hosts if sc.ip_in_scope(h)],
        "iface": ctx.ifaces, "wlan": [i for i in ctx.ifaces if i.startswith("wl")],
        "mon": [i for i in ctx.ifaces if "mon" in i or i.startswith("wl")],
        "bdaddr": sorted(sc.ble), "hci": ["hci0", "hci1"], "wordlist": wls[:400],
        "never": [str(n) for n in sc.exclude],
        "tty": _serial_ports(),
    }


def build_app(cat: kit.Catalog, ctx_factory, token: str, port_holder: dict,
              launcher=kit.launch_terminal, writer=kit.write) -> Starlette:
    def local(request: Request) -> Response | None:
        host = (request.headers.get("host") or "").rsplit(":", 1)[0]
        if host not in ("127.0.0.1", "localhost"):
            return JSONResponse({"error": "local only"}, status_code=403)
        return None

    def guard(request: Request) -> Response | None:
        if (bad := local(request)):
            return bad
        sent = request.query_params.get("t") or request.headers.get("x-kit-token", "")
        if not secrets.compare_digest(sent.encode(), token.encode()):
            return JSONResponse({"error": "bad token"}, status_code=403)
        return None

    async def page(request):
        return guard(request) or FileResponse(STATIC / "kit.html")

    async def asset(request):   # static files carry no secrets; Host check only
        if (bad := local(request)):
            return bad
        name = request.path_params["name"]
        if name not in ("kit.js", "kit.css"):
            return Response(status_code=404)
        return FileResponse(STATIC / name)

    async def recipes(request):
        if (bad := guard(request)):
            return bad
        return JSONResponse({
            "categories": cat.categories(),
            "recipes": [{**r.__dict__, "params": r.params} for r in cat.recipes.values()],
            "chains": [{**c.__dict__, "params": cat.chain_params(c.id)} for c in cat.chains.values()],
            "labels": kit.LABELS, "defaults": kit.DEFAULTS,
        })

    async def opts(request):
        if (bad := guard(request)):
            return bad
        return JSONResponse(choices(ctx_factory()))

    async def _plan(request):
        body = await request.json()
        if not isinstance(body, dict):
            raise kit.KitError("bad request")
        values = body.get("values") or {}
        if not isinstance(values, dict) or not all(isinstance(v, str) for v in values.values()):
            raise kit.KitError("values must be text")
        return kit.plan(cat, str(body.get("id", "")), values, ctx_factory())

    async def preview(request):
        if (bad := guard(request)):
            return bad
        try:
            p = await _plan(request)
        except (kit.KitError, ValueError) as e:
            return JSONResponse({"ok": False, "error": str(e)})
        return JSONResponse({"ok": True, "commands": [c for _, c, _ in p.commands], "root": p.root,
                             "active": p.active,
                             "outdir": str(p.outdir)})

    async def run(request):
        if (bad := guard(request)):
            return bad
        try:
            p = await _plan(request)
            body = await request.json()
            if not kit.confirmed(p, body.get("confirm") if isinstance(body, dict) else None):
                return JSONResponse({"ok": False, "need_confirm": True,
                                     "error": 'This tries logins on the device. Type yes in the box to run it.'})
            script = writer(p)
            launcher(script)
        except (kit.KitError, ValueError, OSError) as e:
            return JSONResponse({"ok": False, "error": str(e)})
        return JSONResponse({"ok": True, "outdir": str(p.outdir)})

    return Starlette(routes=[
        Route("/", page), Route("/static/{name}", asset), Route("/api/recipes", recipes),
        Route("/api/choices", opts), Route("/api/preview", preview, methods=["POST"]),
        Route("/api/run", run, methods=["POST"]),
    ])


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve(scope_loader, open_browser: bool = True) -> int:
    import uvicorn
    cat = kit.load()
    token = secrets.token_urlsafe(24)
    port = _free_port()
    app = build_app(cat, lambda: kit.Context(scope=scope_loader()), token, {"port": port})
    url = f"http://127.0.0.1:{port}/?t={token}"
    print(f"havok-box toolbox: {url}\n(close this window or press Ctrl+C to stop it)")
    if open_browser and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        webbrowser.open(url)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0
