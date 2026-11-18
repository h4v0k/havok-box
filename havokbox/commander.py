"""API commander — the online planner that plugs in behind planner.plan.

It sees only the on-box digest of a finding (never raw tool output) and returns proposed tasks.
It never runs anything and never writes the store: the drain loop sanitises its output, and the
orchestrator + scope gate + human approval still stand between any proposal and a run.

Spend cap (req 8): a hard per-day call ceiling; 0 disables the commander entirely.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"

SYSTEM = (
    "You are the planning commander for a lab-only recon box. You only PROPOSE next steps for the "
    "owner's own in-scope lab, using the listed tools; a scope gate and a human approve every active "
    "step. Reply with JSON only: {\"tasks\": [{\"tool\": <name>, \"target\": {...}, \"label\": <short "
    "button text>, \"why\": <one sentence>}]}. Use only tools from the provided list and only targets "
    "that appear in the finding. Propose at most 3 tasks; propose none if nothing is worth doing."
)


class SpendCapReached(RuntimeError):
    pass


class ApiCommander:
    def __init__(self, api_key: str, model: str, max_calls_per_day: int, tools: dict,
                 transport=None, clock=time.time, max_tokens: int = 600, counter_path=None):
        self.api_key = api_key
        self.model = model
        self.max_calls = max_calls_per_day
        self.tools = tools          # registry: name -> ToolSpec
        self.transport = transport or self._http
        self.clock = clock
        self.max_tokens = max_tokens
        self.counter_path = counter_path   # persisted so restarts can't reset the cap
        self._day, self._calls = self._load()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and self.max_calls > 0

    def _charge(self) -> None:
        day = int(self.clock() // 86400)
        if day != self._day:
            self._day, self._calls = day, 0
        if self._calls >= self.max_calls:
            raise SpendCapReached(f"commander cap of {self.max_calls} calls/day reached")
        self._calls += 1
        self._save()

    def _load(self):
        if self.counter_path:
            try:
                with open(self.counter_path) as fh:
                    d = json.load(fh)
                return int(d["day"]), int(d["calls"])
            except (OSError, ValueError, KeyError, TypeError):
                pass
        return None, 0

    def _save(self):
        if self.counter_path:
            tmp = self.counter_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump({"day": self._day, "calls": self._calls}, fh)
            os.replace(tmp, self.counter_path)

    def _tool_menu(self) -> list[dict]:
        return [{"tool": s.name, "category": s.category, "params": s.params} for s in self.tools.values()]

    def propose(self, digest: dict) -> list[dict]:
        if not self.enabled:
            raise RuntimeError("commander disabled")
        self._charge()
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": SYSTEM,
            "messages": [{"role": "user", "content": json.dumps(
                {"tools": self._tool_menu(), "finding": digest})}],
        }
        resp = self.transport(body)
        text = "".join(b.get("text", "") for b in resp.get("content", []) if b.get("type") == "text")
        return parse_tasks(text)

    def _http(self, body: dict) -> dict:
        req = urllib.request.Request(
            API_URL, data=json.dumps(body).encode(), method="POST",
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())


def parse_tasks(text: str) -> list[dict]:
    """Pull the tasks list out of the model reply. Anything malformed -> no tasks."""
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return []
    try:
        obj = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    tasks = obj.get("tasks") if isinstance(obj, dict) else None
    return [t for t in tasks if isinstance(t, dict)] if isinstance(tasks, list) else []
