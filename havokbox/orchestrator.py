"""Ties the scope gate to tool dispatch and the store. The only thing that runs tools,
and (with the store) the only writer of findings.

A task is a dict: {id, category, tool, target, mode}. Before anything runs the orchestrator:
  1. looks the tool up in the registry (unknown -> refuse);
  2. binds category: the task's claimed category must equal the tool's true category, so a
     task can't mislabel an active tool as passive to dodge approval;
  3. gates the task against scope (out-of-scope -> refuse);
  4. validates the typed params against the tool spec;
  5. for active categories, requires and consumes a matching approval;
  6. runs the tool and writes the finding.
"""
from __future__ import annotations

from .scope import Gate, Scope
from .store import Store
from .tools import ToolCtx, validate_params


class Orchestrator:
    def __init__(self, scope: Scope, store: Store, registry: dict, runner, hw: dict | None = None):
        self.scope = scope
        self.gate = Gate(scope)
        self.store = store
        self.registry = registry   # tool name -> ToolSpec
        self.runner = runner        # callable(list[str]) -> str; injected for testability
        from .tools import DEFAULT_HW
        self.hw = {**DEFAULT_HW, **(hw or {})}

    def execute(self, task: dict) -> dict:
        task_id = task.get("id")
        spec = self.registry.get(task.get("tool"))
        if spec is None:
            self.store.log("error", f"no such tool: {task.get('tool')!r}")
            return {"status": "error", "reason": "unknown tool"}

        if task.get("category") != spec.category:
            self.store.log(
                "refused",
                f"category/tool mismatch: task={task.get('category')} {spec.name}={spec.category}",
            )
            return {"status": "refused", "reason": "category/tool mismatch"}

        decision = self.gate.evaluate(task)
        if not decision.allowed:
            self.store.log("refused", f"{spec.category} {task.get('target')}: {decision.reason}")
            return {"status": "refused", "reason": decision.reason}

        ok, why = validate_params(spec, task.get("target"))
        if not ok:
            self.store.log("refused", f"{spec.name}: bad params: {why}")
            return {"status": "refused", "reason": why}

        if decision.needs_approval:
            if not self.store.consume_approval(task_id):
                return {"status": "awaiting_approval", "task_id": task_id}

        ctx = ToolCtx(runner=self.runner, mode=task.get("mode", "stealth"), scope=self.scope,
                      hw=self.hw)
        try:
            res = spec.fn(task, ctx)
        except Exception as exc:  # a tool crash must not take the orchestrator down
            self.store.log("error", f"{spec.name} failed: {exc}")
            return {"status": "error", "reason": str(exc)}

        fresh = self.store.add_finding(
            res["result_id"], res["space"], res["kind"], res["summary"],
            res.get("data", {}), ctx.mode,
        )
        self.store.log("ran", f"{spec.category} [{ctx.mode}] -> {res['summary']}")
        return {"status": "ok", "result_id": res["result_id"], "summary": res["summary"], "new": fresh}
