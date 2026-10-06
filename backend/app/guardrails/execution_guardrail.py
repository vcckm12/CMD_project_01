"""ExecutionGuardrailEngine.authorize_tool() (DES-006 §5.2).

The model only proposes. Identity comes from AuthContext, never from arguments; staff verification
chats get no customer tools; client tokens need the tool's scope; arguments must match the strict
schema; rounds/calls are budgeted by the published policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.guardrails.ruleset import RuleSnapshot
from app.security.auth import AuthContext
from app.shop.tools import REGISTRY, ToolSpec, parse_args


@dataclass(frozen=True)
class ExecutionDecision:
    allowed: bool
    rule_id: str | None = None
    spec: ToolSpec | None = None
    arguments: Any = None


def available_tools(ctx: AuthContext) -> list[ToolSpec]:
    if ctx.role != "customer":
        return []  # operator/admin verification chat: no customer data tools (DES-005 §1.1)
    return [t for t in REGISTRY.values() if t.scope in ctx.scopes]


class ToolBudget:
    def __init__(self, snapshot: RuleSnapshot) -> None:
        self.max_rounds = snapshot.limit("max_tool_rounds")
        self.max_calls = snapshot.limit("max_tool_calls")
        self.rounds = 0
        self.calls = 0

    def next_round(self) -> bool:
        self.rounds += 1
        return self.rounds <= self.max_rounds

    def next_call(self) -> bool:
        self.calls += 1
        return self.calls <= self.max_calls


def authorize_tool(ctx: AuthContext, name: Any, raw_arguments: Any) -> ExecutionDecision:
    allowed = {t.name: t for t in available_tools(ctx)}
    if not isinstance(name, str) or name not in allowed:
        return ExecutionDecision(False, "RULE_TOOL_NOT_ALLOWED")
    spec = allowed[name]
    try:
        arguments = parse_args(spec, raw_arguments)
    except ValueError:
        return ExecutionDecision(False, "RULE_TOOL_ARGUMENT_INVALID")
    return ExecutionDecision(True, None, spec, arguments)
