"""Guardrail pipeline: rules first, then the LLM judge, with failure signals to the alert monitor.

Verdicts combine with OR: a rule block or a judge block stops the request. Rules run first and are
cheap, so an already-blocked request never spends judge time. Failures fail closed:
- GuardrailTimeout (rules over budget)  → 503 GUARDRAIL_TIMEOUT,     input-repeat signal
- GuardrailUnavailable (judge failed)   → 503 GUARDRAIL_UNAVAILABLE, outage + input-repeat signal
- InferenceBusy (model slot queue full) → 429 RATE_LIMITED, no alert (load, not failure)
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace

import anyio

from app.guardrails.alerts import AlertMonitor
from app.guardrails.input_guardrail import InputGuardrailEngine, InputMessage
from app.guardrails.judge import JudgeUnavailable, SafetyJudge, Target
from app.guardrails.output_guardrail import BLOCKED_MESSAGE, OutputGuardrailEngine
from app.guardrails.ruleset import RuleSnapshot
from app.guardrails.types import GuardrailTimeout, Hit, InspectionResult, SanitizationResult

JUDGE_RULES: Mapping[Target, str] = {
    "input": "RULE_LLM_JUDGE_INPUT",
    "context": "RULE_LLM_JUDGE_INPUT",  # same input-stage rule; only the judging criteria differ
    "tool": "RULE_LLM_JUDGE_TOOL",
    "output": "RULE_LLM_JUDGE_OUTPUT",
}


class GuardrailUnavailable(Exception):
    """The judge could not give a verdict; the request is refused rather than passed unjudged."""


@dataclass(frozen=True)
class JudgeTiming:
    judge_ms: float = 0.0
    judge_calls: int = 0


class GuardrailPipeline:
    def __init__(
        self,
        input_engine: InputGuardrailEngine,
        output_engine: OutputGuardrailEngine,
        judge: SafetyJudge | None,
        monitor: AlertMonitor,
    ) -> None:
        self.input_engine = input_engine
        self.output_engine = output_engine
        self.judge = judge  # None only when the judge is disabled (lab OFF comparison)
        self.monitor = monitor

    async def _rules_input(self, messages, risk_signals, snapshot) -> InspectionResult:
        try:
            return await anyio.to_thread.run_sync(self.input_engine.inspect, messages, risk_signals, snapshot)
        except GuardrailTimeout:
            for m in messages:
                await self.monitor.input_failed(m.content)
            raise

    async def _judge(
        self, target: Target, texts: Sequence[str], snapshot: RuleSnapshot
    ) -> tuple[Hit | None, JudgeTiming]:
        if self.judge is None or not texts:
            return None, JudgeTiming()
        try:
            verdict = await self.judge.judge(target, texts)
        except JudgeUnavailable as exc:
            for text in texts:
                await self.monitor.judge_failed(text)
            raise GuardrailUnavailable(exc.reason) from exc
        timing = JudgeTiming(verdict.judge_ms, verdict.calls)
        if not verdict.blocked:
            return None, timing
        compiled = snapshot.get(JUDGE_RULES[target])
        if compiled is None:  # validation requires these rules; treat a gap as a block, never a pass
            return Hit(JUDGE_RULES[target], "LLM01:2025", "input" if target != "output" else "output", "block"), timing
        r = compiled.rule
        return Hit(r.rule_id, r.category, r.stage, r.action), timing

    async def check_input(
        self,
        messages: Sequence[InputMessage],
        risk_signals: Mapping | None,
        snapshot: RuleSnapshot,
        judge_texts: Sequence[str] | None = None,
    ) -> tuple[InspectionResult, JudgeTiming]:
        """`judge_texts` defaults to the last user message (customer criteria); client system/context
        messages are judged separately with the context criteria (attack goals only)."""
        result = await self._rules_input(messages, risk_signals, snapshot)
        if not result.allowed:
            return result, JudgeTiming()
        context_texts: list[str] = []
        if judge_texts is None:
            users = [m.content for m in messages if m.role == "user"]
            judge_texts = users[-1:]
            context_texts = [m.content for m in messages if m.role in ("system", "context")]
        hit, timing = await self._judge("context", context_texts, snapshot)
        if hit is None:
            hit, user_timing = await self._judge("input", judge_texts, snapshot)
            timing = JudgeTiming(timing.judge_ms + user_timing.judge_ms, timing.judge_calls + user_timing.judge_calls)
        if hit is None:
            return result, timing
        return _blocked_input(result, hit), timing

    async def check_tool(self, content: str, snapshot: RuleSnapshot) -> tuple[InspectionResult, JudgeTiming]:
        result = await self._rules_input([InputMessage("tool", content)], None, snapshot)
        if not result.allowed:
            return result, JudgeTiming()
        hit, timing = await self._judge("tool", [content], snapshot)
        return (result if hit is None else _blocked_input(result, hit)), timing

    async def check_output(self, raw: str, snapshot: RuleSnapshot) -> tuple[SanitizationResult, JudgeTiming]:
        try:
            result = await anyio.to_thread.run_sync(self.output_engine.sanitize, raw, snapshot)
        except GuardrailTimeout:
            await self.monitor.input_failed(raw)
            raise
        if result.blocked:
            return result, JudgeTiming()
        # The raw text is judged: masking does not change meaning, and paraphrased leaks have no pattern.
        hit, timing = await self._judge("output", [raw], snapshot)
        if hit is None:
            return result, timing
        return SanitizationResult(BLOCKED_MESSAGE, True, True, (*result.hits, hit), result.output_ms), timing


def _blocked_input(result: InspectionResult, hit: Hit) -> InspectionResult:
    return replace(
        result,
        allowed=False,
        hits=(*result.hits, hit),
        safe_summary=f"입력 차단: {hit.rule_id}",
        canonical_messages=(),
    )
