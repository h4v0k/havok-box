"""Discord webhook notifier: RAM queue, rate limits, no redirects. The URL is never exposed."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections import deque

PREFIX = "https://discord.com/api/webhooks/"
MAX_QUEUE = 50
MAX_AGE_S = 2 * 3600
KEY_GAP_S = 600
HOURLY_MAX = 20
MAX_CONTENT = 300


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _default_transport(url, data, timeout):
    """-> (status, body_bytes). Network errors raise (message never reaches callers)."""
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "havok-box/1"})
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as r:
            return r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(65536)
        except Exception:
            return e.code, b""


class Discord:
    def __init__(self, url, transport=None, clock=time.time, map_links=False):
        ok = isinstance(url, str) and url.startswith(PREFIX) and len(url) > len(PREFIX)
        self._url = url if ok else None
        self.enabled = ok
        self._transport = transport or _default_transport
        self._clock = clock
        self.map_links = bool(map_links)
        self._q = deque(maxlen=MAX_QUEUE)
        self._key_last: dict[str, float] = {}
        self._sent: deque = deque()
        self._retry_until = 0.0

    def __repr__(self):
        return f"Discord(enabled={self.enabled}, queued={len(self._q)})"

    __str__ = __repr__

    def __getstate__(self):
        raise TypeError("Discord is not serialisable")

    def _content(self, kind, severity, text, ts, lat, lon):
        when = time.strftime("%I:%M %p", time.localtime(ts)).lstrip("0")
        tail = f" · {when}"
        link = ""
        if self.map_links and lat is not None and lon is not None:
            link = f" https://maps.google.com/?q={lat:.5f},{lon:.5f}"
        head = f"[{str(severity).upper()}] "
        room = MAX_CONTENT - len(head) - len(tail) - len(link)
        body = str(text) if kind is None else f"{kind} — {text}"
        if len(body) > room:
            body = body[:max(0, room - 1)] + "…"
        return head + body + tail + link

    def send(self, key, kind, severity, text, ts, lat=None, lon=None):
        """Enqueue. Returns False when disabled or rate limited."""
        if not self.enabled:
            return False
        now = self._clock()
        last = self._key_last.get(key)
        if last is not None and now - last < KEY_GAP_S:
            return False
        while self._sent and now - self._sent[0] >= 3600:
            self._sent.popleft()
        if len(self._sent) >= HOURLY_MAX:
            return False
        self._key_last[key] = now
        self._sent.append(now)
        self._q.append((now, self._content(kind, severity, text, ts, lat, lon)))
        return True

    def flush(self):
        """Post queued messages; returns number delivered."""
        if not self.enabled:
            return 0
        n = 0
        while self._q:
            now = self._clock()
            while self._q and now - self._q[0][0] > MAX_AGE_S:
                self._q.popleft()
            if not self._q or now < self._retry_until:
                break
            body = json.dumps({"content": self._q[0][1], "allowed_mentions": {"parse": []}}).encode()
            try:
                status, resp = self._transport(self._url, body, 10)
            except Exception:
                break  # keep queued; never surface the URL
            if 200 <= status < 300:
                self._q.popleft()
                n += 1
            elif status == 429:
                wait = 1.0
                try:
                    v = json.loads(resp).get("retry_after")
                    if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0:
                        wait = float(v)
                except Exception:
                    pass
                self._retry_until = self._clock() + wait
                break
            elif 400 <= status < 500:
                self._q.popleft()  # permanently rejected; drop
            else:
                break
        return n
