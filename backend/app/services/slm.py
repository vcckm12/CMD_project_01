"""SLMService.generate_response() (DES-003 단계 4, DES-005 §5).

Calls the model with the server system prompt, inspected context and allowed tool schemas. Tool calls
are authorized, executed with fixed SQL as the authenticated user, re-inspected (rules + judge) and fed
back, within the round/call/size budget. Any denial stops the loop; the raw model text never leaves
this function except as the final candidate answer for the output guardrail.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Any

from psycopg_pool import AsyncConnectionPool

from app.audit.outbox import ToolExecution
from app.guardrails.execution_guardrail import ToolBudget, authorize_tool, available_tools
from app.guardrails.pipeline import GuardrailPipeline, merge_layers
from app.guardrails.ruleset import RuleSnapshot
from app.guardrails.types import Hit
from app.security.auth import AuthContext
from app.services.ollama import InferenceTimeout, InferenceUnavailable, OllamaClient
from app.shop import actions, dao
from app.shop.tools import CHANGE_TOOLS, ObjectNotFound

MAX_TOOL_RESULT_CHARS = 8000
# Conservative token estimate for Korean-heavy text (measured ~1.5 chars/token for qwen3; English ~5).
CHARS_PER_TOKEN = 1.2


def estimate_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN) + 1


@dataclass
class SlmResult:
    content: str = ""
    blocked_stage: str | None = None  # "execution" or "input" (tool result) when the loop was stopped
    hits: list[Hit] = field(default_factory=list)
    tool_executions: list[ToolExecution] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    inference_ms: float = 0.0
    judge_ms: float = 0.0
    layers: dict[str, tuple[str, float]] = field(default_factory=dict)  # tool_rules / tool_judge (D-36)
    blocked_tool: tuple[str, str] | None = None  # (tool name, result) that was blocked; shown only in lab
    proposal: actions.Proposal | None = None  # a change tool call ends the loop as a pending proposal


class ContextOverflow(Exception):
    """Prompt would not fit in the model context without truncating the system prompt."""


class SLMService:
    def __init__(
        self,
        client: OllamaClient,
        pipeline: GuardrailPipeline,
        pool: AsyncConnectionPool,
        *,
        num_predict: int = 512,
        call_timeout_s: float = 120.0,
    ) -> None:
        self.client = client
        self.pipeline = pipeline
        self.pool = pool
        self.num_predict = num_predict
        self.call_timeout_s = call_timeout_s

    def input_token_budget(self) -> int:
        # Leave room for the answer and a safety margin; never let Ollama truncate the front.
        return self.client.num_ctx - self.num_predict - 512

    def fit_history(self, system: str, tools: list[dict], history: list[dict], new: list[dict]) -> list[dict]:
        """Drop the oldest history until the estimate fits. Raises ContextOverflow if `new` alone cannot."""
        fixed = estimate_tokens(system) + estimate_tokens(json.dumps(tools, ensure_ascii=False))
        fixed += sum(estimate_tokens(m["content"]) for m in new)
        budget = self.input_token_budget()
        if fixed > budget:
            raise ContextOverflow
        kept: list[dict] = []
        used = fixed
        for message in reversed(history):
            cost = estimate_tokens(message["content"])
            if used + cost > budget:
                break
            kept.append(message)
            used += cost
        kept.reverse()
        # Never start with an orphan assistant turn.
        while kept and kept[0]["role"] == "assistant":
            kept.pop(0)
        return kept

    async def generate(
        self,
        ctx: AuthContext,
        system_prompt: str,
        history: list[dict],
        new_messages: list[dict],
        snapshot: RuleSnapshot,
        deadline: float,
        *,
        temperature: float | None = None,
        num_predict: int | None = None,
        progress: Callable[..., Awaitable[None]] | None = None,
    ) -> SlmResult:
        specs = available_tools(ctx)
        schemas = [t.schema() for t in specs]
        kept = self.fit_history(system_prompt, schemas, history, new_messages)
        messages: list[dict[str, Any]] = [{"role": "system", "content": system_prompt}, *kept, *new_messages]
        budget = ToolBudget(snapshot)
        result = SlmResult()
        tool_chars = 0

        def block(stage: str, hit: Hit) -> SlmResult:
            result.blocked_stage = stage
            result.hits.append(hit)
            return result

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InferenceTimeout
            reply = await self.client.chat(
                messages,
                timeout_s=min(self.call_timeout_s, remaining),
                num_predict=num_predict or self.num_predict,
                temperature=temperature,
                tools=schemas or None,
            )
            result.prompt_tokens += reply.prompt_tokens
            result.completion_tokens += reply.completion_tokens
            result.inference_ms += reply.duration_ms
            if reply.prompt_tokens >= self.client.num_ctx - (num_predict or self.num_predict):
                raise InferenceUnavailable  # the context was truncated; the answer cannot be trusted
            calls = reply.message.get("tool_calls") or []
            if not calls:
                content = reply.message.get("content")
                if not isinstance(content, str) or not content.strip():
                    raise InferenceUnavailable
                result.content = content
                return result

            if not budget.next_round():
                return block("execution", _hit(snapshot, "RULE_TOOL_BUDGET", "execution"))
            messages.append({"role": "assistant", "content": reply.message.get("content") or "", "tool_calls": calls})
            change_calls = sum(
                1 for c in calls if isinstance(c, dict) and (c.get("function") or {}).get("name") in CHANGE_TOOLS
            )
            if change_calls > 1:  # at most one pending proposal per request (DES-005 §5)
                return block("execution", _hit(snapshot, "RULE_TOOL_BUDGET", "execution"))
            for call in calls:
                if not budget.next_call():
                    return block("execution", _hit(snapshot, "RULE_TOOL_BUDGET", "execution"))
                fn = call.get("function") if isinstance(call, dict) else None
                name = fn.get("name") if isinstance(fn, dict) else None
                decision = authorize_tool(ctx, name, fn.get("arguments") if isinstance(fn, dict) else None)
                if decision.rule_id == "RULE_TOOL_ARGUMENT_INVALID" and (
                    fixed := await self._resolve_product(fn, new_messages)
                ):
                    # The model named the product instead of passing its id: one exact catalog match is used.
                    result.hits.append(replace(_hit(snapshot, decision.rule_id, "execution"), action="observe"))
                    decision = authorize_tool(ctx, name, fixed)
                if decision.rule_id == "RULE_TOOL_ARGUMENT_INVALID":
                    # A malformed argument (typically a guessed product id) is a model mistake, not an attack:
                    # nothing ran, so tell the model how to fix it and let it retry within the call budget.
                    result.tool_executions.append(
                        ToolExecution(tool_name=str(name)[:64], outcome="denied", duration_ms=0)
                    )
                    result.hits.append(replace(_hit(snapshot, decision.rule_id, "execution"), action="observe"))
                    messages.append({"role": "tool", "tool_name": str(name)[:64], "content": INVALID_ARGUMENTS_HINT})
                    continue
                if not decision.allowed:
                    result.tool_executions.append(
                        ToolExecution(tool_name=str(name)[:64] if name else "unknown", outcome="denied", duration_ms=0)
                    )
                    return block("execution", _hit(snapshot, decision.rule_id, "execution"))
                if progress is not None:
                    await progress("tool", name=decision.spec.name)
                started = time.perf_counter()
                if decision.spec.requires_confirmation:
                    try:
                        async with self.pool.connection() as conn:
                            proposal = await actions.build_proposal(
                                conn, ctx.user_id, decision.spec.name, decision.arguments.model_dump(mode="json")
                            )
                    except actions.ActionInvalid as exc:
                        # Tell the model why (fixed reason code) so it can explain; nothing was proposed.
                        result.tool_executions.append(
                            ToolExecution(tool_name=decision.spec.name, outcome="denied", duration_ms=_ms(started))
                        )
                        messages.append(
                            {"role": "tool", "tool_name": decision.spec.name,
                             "content": json.dumps({"error": exc.reason})}
                        )  # fmt: skip
                        continue
                    result.proposal = proposal
                    result.hits.append(_hit(snapshot, "RULE_TOOL_CONFIRMATION_REQUIRED", "execution"))
                    return result
                try:
                    async with self.pool.connection() as conn:
                        data = await decision.spec.run(conn, ctx.user_id, decision.arguments)
                except ObjectNotFound:
                    result.tool_executions.append(
                        ToolExecution(tool_name=decision.spec.name, outcome="denied", duration_ms=_ms(started))
                    )
                    return block("execution", _hit(snapshot, "RULE_TOOL_OBJECT_ACCESS", "execution"))
                result.tool_executions.append(
                    ToolExecution(tool_name=decision.spec.name, outcome="read", duration_ms=_ms(started))
                )
                content = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
                tool_chars += len(content)
                if tool_chars > MAX_TOOL_RESULT_CHARS:
                    return block("execution", _hit(snapshot, "RULE_TOOL_BUDGET", "execution"))
                # Product text and other tool data are untrusted: same rules + judge as user input.
                inspection, timing = await self.pipeline.check_tool(content, snapshot)
                result.judge_ms += timing.judge_ms
                merge_layers(result.layers, timing.layers)
                if not inspection.allowed:
                    result.hits.extend(inspection.hits)
                    result.blocked_stage = "input"
                    result.blocked_tool = (decision.spec.name, content)
                    return result
                messages.append({"role": "tool", "tool_name": decision.spec.name, "content": content})

    async def _resolve_product(self, fn: dict, new_messages: list[dict]) -> dict | None:
        """A malformed product_id on a cart change (a small model guesses "12345" or writes the name): the id of the
        one active product named by the guess, else the one product named in the customer's own message; None when
        that is not exactly one. Only public catalog data is read; the customer still confirms the change."""
        args = fn.get("arguments")
        if fn.get("name") not in ("set_cart_item", "remove_cart_item") or not isinstance(args, dict):
            return None
        guess = args.get("product_id")
        guess = guess.strip() if isinstance(guess, str) and len(guess) <= 100 else ""
        said = "".join(m["content"] for m in new_messages if m.get("role") == "user").replace(" ", "")
        async with self.pool.connection() as conn:
            matches = await dao.search_products(conn, guess, 2) if guess else []
            if len(matches) != 1:
                catalog = await dao.search_products(conn, "", 100)
                matches = [p for p in catalog if p["name"].replace(" ", "") in said]
        if len(matches) != 1:
            return None
        quantity = args.get("quantity")
        if isinstance(quantity, str) and quantity.strip().isdigit():
            quantity = int(quantity)
        return {**args, "product_id": matches[0]["id"]} | ({"quantity": quantity} if "quantity" in args else {})


# Fixed text (never echoes the bad value) returned to the model for a malformed Tool argument (D-44).
INVALID_ARGUMENTS_HINT = json.dumps(
    {"error": "INVALID_ARGUMENTS", "hint": "Ids are never guessed. Call search_products yourself now with the "
     "product name (do not ask the customer to search), then call the change tool again with the id from the "
     "result. Coupon ids come from list_coupons."}
)  # fmt: skip


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


def _hit(snapshot: RuleSnapshot, rule_id: str, stage: str) -> Hit:
    compiled = snapshot.get(rule_id)
    if compiled is None:
        return Hit(rule_id, "LLM06:2025", stage, "block")
    r = compiled.rule
    return Hit(r.rule_id, r.category, r.stage, r.action)
