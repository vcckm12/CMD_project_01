"""Chat orchestration (DES-003 단계 1~6) shared by the native and OpenAI-compatible endpoints.

Order: per-user budget → session ownership/busy lock → input guardrail (rules + judge) → model with
tools (execution guardrail, tool-result inspection) → output guardrail (rules + judge) → one DB
transaction that stores the redacted context and the audit outbox event → response. Nothing is
returned to the client before that commit; a failed commit returns 503 instead of the answer.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field

from psycopg.types.json import Jsonb

from app.audit.outbox import AuditEnvelope, RuleHit, Source, ToolExecution, elapsed_ms, persist_event
from app.errors import ApiError
from app.guardrails import pii
from app.guardrails.budget import Budget
from app.guardrails.input_guardrail import InputMessage
from app.guardrails.output_guardrail import BLOCKED_MESSAGE
from app.guardrails.pipeline import GuardrailPipeline, GuardrailUnavailable
from app.guardrails.ruleset import RuleSnapshot
from app.guardrails.types import GuardrailTimeout, Hit, OutputTooLong
from app.security.auth import AuthContext
from app.services.ollama import InferenceBusy, InferenceTimeout, InferenceUnavailable
from app.services.slm import ContextOverflow, SLMService

MAX_CONTEXT_MESSAGES = 40
MAX_STORED_CHARS = 2000

REFUSALS = {
    "input": "🛡️ 요청을 보안 정책에 따라 처리할 수 없습니다.",
    "execution": "🛡️ 요청하신 작업은 처리할 수 없습니다. 본인의 주문·장바구니·쿠폰만 조회할 수 있어요.",
    "output": BLOCKED_MESSAGE,
}

ERRORS = {
    ContextOverflow: (422, "PROMPT_TOO_LONG"),
    InferenceBusy: (429, "RATE_LIMITED"),
    InferenceTimeout: (504, "INFERENCE_TIMEOUT"),
    InferenceUnavailable: (502, "INFERENCE_UNAVAILABLE"),
    OutputTooLong: (502, "INFERENCE_UNAVAILABLE"),
    GuardrailTimeout: (503, "GUARDRAIL_TIMEOUT"),
    GuardrailUnavailable: (503, "GUARDRAIL_UNAVAILABLE"),
}
RETRY_AFTER = {"RATE_LIMITED": "30", "GUARDRAIL_UNAVAILABLE": "30", "GUARDRAIL_TIMEOUT": "10"}


@dataclass
class ChatTurn:
    ctx: AuthContext
    request_id: str
    started: float
    session_id: uuid.UUID
    api_path: str
    system_prompt: str
    inspect: list[InputMessage]  # untrusted text to inspect this turn
    model_new: list[dict]  # what the model receives this turn (canonical text)
    history: list[dict] = field(default_factory=list)  # already-inspected redacted history
    risk_signals: dict | None = None
    judge_texts: list[str] | None = None
    stored_context: list[dict] = field(default_factory=list)
    temperature: float | None = None
    max_tokens: int | None = None


@dataclass
class ChatOutcome:
    status: str
    content: str
    stage: str | None
    hits: list[Hit]
    ruleset_version: uuid.UUID | None
    session_id: uuid.UUID
    event_id: uuid.UUID
    input_ms: float
    output_ms: float
    total_ms: float
    prompt_tokens: int = 0
    completion_tokens: int = 0


class UserBudget:
    """Per-user 30 req/min and one inference at a time; in memory (single worker, DES-001 §2)."""

    def __init__(self, per_minute: int = 30) -> None:
        self.per_minute = per_minute
        self._calls: dict[uuid.UUID, deque[float]] = defaultdict(deque)
        self.in_flight: set[uuid.UUID] = set()
        self.busy_sessions: set[uuid.UUID] = set()

    def enter(self, user_id: uuid.UUID, session_id: uuid.UUID) -> None:
        now = time.monotonic()
        q = self._calls[user_id]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_minute or user_id in self.in_flight:
            raise ApiError(429, "RATE_LIMITED", {"Retry-After": "30"})
        if session_id in self.busy_sessions:
            raise ApiError(409, "SESSION_BUSY")
        q.append(now)
        self.in_flight.add(user_id)
        self.busy_sessions.add(session_id)

    def leave(self, user_id: uuid.UUID, session_id: uuid.UUID) -> None:
        self.in_flight.discard(user_id)
        self.busy_sessions.discard(session_id)


def merge_hits(hits: list[Hit]) -> list[RuleHit]:
    merged: dict[str, Hit] = {}
    for h in hits:
        prev = merged.get(h.rule_id)
        merged[h.rule_id] = (
            h if prev is None else Hit(h.rule_id, h.category, h.stage, h.action, prev.match_count + h.match_count)
        )
    return [RuleHit(rule_id=h.rule_id, category=h.category, stage=h.stage, action=h.action, match_count=h.match_count)
            for h in merged.values()]  # fmt: skip


def redact_for_storage(text: str, snapshot: RuleSnapshot) -> str:
    """Stored context keeps no contact data or secrets (DES-002 §1); bounded length."""
    try:
        spans = pii.Detector(snapshot, Budget(50)).spans(text)
    except GuardrailTimeout:
        return "[저장 생략]"
    return pii.apply_masks(text, spans)[:MAX_STORED_CHARS]


class ChatService:
    def __init__(self, app_state) -> None:
        self.state = app_state

    @property
    def pipeline(self) -> GuardrailPipeline:
        return self.state.guardrails

    async def load_session(self, ctx: AuthContext, session_id: uuid.UUID) -> tuple[list[dict], dict]:
        async with self.state.pools.chat.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT context_redacted, risk_signals FROM commerce.chat_sessions WHERE id = %s AND user_id = %s",
                    (session_id, ctx.user_id),
                )
            ).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND")
        return list(row["context_redacted"]), dict(row["risk_signals"])

    async def create_session(self, ctx: AuthContext) -> uuid.UUID:
        async with self.state.pools.chat.connection() as conn:
            row = await (
                await conn.execute(
                    "INSERT INTO commerce.chat_sessions (user_id, source) VALUES (%s, %s) RETURNING id",
                    (ctx.user_id, ctx.source),
                )
            ).fetchone()
        return row["id"]

    async def run(self, turn: ChatTurn) -> ChatOutcome:
        snapshot: RuleSnapshot | None = self.state.rule_cache.current()
        if snapshot is None or not self.state.rule_cache.consistent:
            raise ApiError(503, "RULESET_UNAVAILABLE")
        budget: UserBudget = self.state.user_budget
        budget.enter(turn.ctx.user_id, turn.session_id)
        try:
            return await self._run(turn, snapshot)
        finally:
            budget.leave(turn.ctx.user_id, turn.session_id)

    async def _run(self, turn: ChatTurn, snapshot: RuleSnapshot) -> ChatOutcome:
        deadline = time.monotonic() + self.state.settings.chat_deadline_seconds
        hits: list[Hit] = []
        tool_execs: list[ToolExecution] = []
        input_ms = output_ms = 0.0
        prompt_tokens = completion_tokens = 0
        stage: str | None = None
        content = ""
        masked = False
        signals = turn.risk_signals
        try:
            inspection, _ = await self.pipeline.check_input(turn.inspect, turn.risk_signals, snapshot, turn.judge_texts)
            input_ms = inspection.input_ms
            hits.extend(inspection.hits)
            signals = inspection.risk_signals
            if not inspection.allowed:
                stage = "input"
            else:
                slm: SLMService = self.state.slm
                generated = await slm.generate(
                    turn.ctx, turn.system_prompt, turn.history, turn.model_new, snapshot, deadline,
                    temperature=turn.temperature, num_predict=turn.max_tokens,
                )  # fmt: skip
                hits.extend(generated.hits)
                tool_execs.extend(generated.tool_executions)
                prompt_tokens, completion_tokens = generated.prompt_tokens, generated.completion_tokens
                if generated.blocked_stage:
                    stage = generated.blocked_stage
                else:
                    sanitized, _ = await self.pipeline.check_output(generated.content, snapshot)
                    output_ms = sanitized.output_ms
                    hits.extend(sanitized.hits)
                    if sanitized.blocked:
                        stage = "output"
                    else:
                        content, masked = sanitized.content, sanitized.changed
        except tuple(ERRORS) as exc:
            status_code, code = ERRORS[type(exc)]
            await self._persist(turn, snapshot, "error", None, hits, tool_execs, input_ms, output_ms,
                                f"오류: {code}", signals, None)  # fmt: skip
            raise ApiError(
                status_code, code, {"Retry-After": RETRY_AFTER[code]} if code in RETRY_AFTER else None
            ) from exc

        if stage is not None:
            status, content = "blocked", REFUSALS[stage]
            summary = f"차단({stage}): " + ", ".join(h.rule_id for h in hits if h.action == "block")
            reply_for_context = None
        else:
            status = "masked" if masked else "success"
            summary = (
                "정상 응답"
                if not masked
                else "응답 일부 마스킹: "
                + ", ".join(sorted({h.rule_id for h in hits if h.action in ("mask", "escape")}))
            )
            reply_for_context = content
        event_id = await self._persist(turn, snapshot, status, stage, hits, tool_execs, input_ms, output_ms,
                                       summary, signals, reply_for_context)  # fmt: skip
        return ChatOutcome(
            status=status, content=content, stage=stage, hits=hits, ruleset_version=snapshot.version_id,
            session_id=turn.session_id, event_id=event_id, input_ms=input_ms, output_ms=output_ms,
            total_ms=elapsed_ms(turn.started), prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
        )  # fmt: skip

    async def _persist(
        self, turn: ChatTurn, snapshot: RuleSnapshot, status: str, stage: str | None, hits: list[Hit],
        tool_execs: list[ToolExecution], input_ms: float, output_ms: float, summary: str, signals: dict | None,
        reply: str | None,
    ) -> uuid.UUID:  # fmt: skip
        envelope = AuditEnvelope(
            request_id=uuid.UUID(turn.request_id),
            actor_id=turn.ctx.user_id,
            session_id=turn.session_id,
            source=turn.ctx.source,
            api_path=turn.api_path,
            model=self.state.settings.ollama_model,
            status=status,
            stage=stage,
            ruleset_version=snapshot.version_id,
            input_chars=sum(len(m.content) for m in turn.inspect),
            output_chars=len(reply or ""),
            input_ms=input_ms,
            output_ms=output_ms,
            total_ms=elapsed_ms(turn.started),
            summary_redacted=summary[:2000],
            rule_hits=tuple(merge_hits(hits)),
            tool_executions=tuple(tool_execs[:6]),
        )
        context = list(turn.stored_context)
        if reply is not None:
            # Only completed, non-blocked turns enter the stored context; attack text is never kept.
            for m in turn.inspect:
                if m.role == "user":
                    context.append({"role": "user", "content": redact_for_storage(m.content, snapshot)})
            context.append({"role": "assistant", "content": reply[:MAX_STORED_CHARS]})
        context = context[-MAX_CONTEXT_MESSAGES:]
        try:
            async with self.state.pools.chat.connection() as conn, conn.transaction():
                await conn.execute(
                    "UPDATE commerce.chat_sessions SET context_redacted = %s, risk_signals = %s,"
                    " last_activity_at = now() WHERE id = %s AND user_id = %s",
                    (Jsonb(context), Jsonb(signals or {}), turn.session_id, turn.ctx.user_id),
                )
                await persist_event(conn, envelope)
        except Exception as exc:  # noqa: BLE001 - any audit failure hides the answer (DES-001 §5)
            raise ApiError(503, "AUDIT_UNAVAILABLE") from exc
        return envelope.event_id


def source_for(ctx: AuthContext) -> Source:
    return ctx.source
