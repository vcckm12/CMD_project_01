"""Guardrail pipeline: rules first, then the LLM judge, with failure signals to the alert monitor.

Verdicts combine with OR: a rule block or a judge block stops the request. Both layers always run
(D-36) so each event records both verdicts in `JudgeTiming.layers`; when the rules already blocked,
a judge failure is recorded as "error" and does not change the answer. Otherwise failures fail closed:
- GuardrailTimeout (rules over budget)  → 503 GUARDRAIL_TIMEOUT,     input-repeat signal
- GuardrailUnavailable (judge failed)   → 503 GUARDRAIL_UNAVAILABLE, outage + input-repeat signal
- InferenceBusy (model slot queue full) → 429 RATE_LIMITED, no alert (load, not failure)
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

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
    # {"input_rules": ("block"|"pass", ms), "input_judge": ("block"|"pass"|"error", ms), ...}; absent = not run
    layers: dict[str, tuple[str, float]] = field(default_factory=dict)


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
        self, target: Target, texts: Sequence[str], snapshot: RuleSnapshot, *, observe: bool = False
    ) -> tuple[Hit | None, JudgeTiming]:
        """`observe`: the rules already blocked; a judge failure is recorded, never raised."""
        if self.judge is None or not texts:
            return None, JudgeTiming()
        try:
            verdict = await self.judge.judge(target, texts)
        except JudgeUnavailable as exc:
            if observe:
                return None, JudgeTiming(judge_calls=1, layers={"_judge": ("error", 0.0)})
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
        context_texts: list[str] = []
        if judge_texts is None:
            users = [m.content for m in messages if m.role == "user"]
            judge_texts = users[-1:]
            context_texts = [m.content for m in messages if m.role in ("system", "context")]
        observe = not result.allowed
        hit, timing = await self._judge("context", context_texts, snapshot, observe=observe)
        if hit is None and "_judge" not in timing.layers:
            hit, user_timing = await self._judge("input", judge_texts, snapshot, observe=observe)
            timing = _add(timing, user_timing)
        timing = _layers(timing, "input", result.allowed, result.input_ms, hit)
        if hit is None:
            return result, timing
        return (_blocked_input(result, hit) if result.allowed else _also_hit(result, hit)), timing

    async def check_tool(self, content: str, snapshot: RuleSnapshot) -> tuple[InspectionResult, JudgeTiming]:
        result = await self._rules_input([InputMessage("tool", content)], None, snapshot)
        hit, timing = await self._judge("tool", [content], snapshot, observe=not result.allowed)
        timing = _layers(timing, "tool", result.allowed, result.input_ms, hit)
        if hit is None:
            return result, timing
        return (_blocked_input(result, hit) if result.allowed else _also_hit(result, hit)), timing

    async def check_output(self, raw: str, snapshot: RuleSnapshot) -> tuple[SanitizationResult, JudgeTiming]:
        try:
            result = await anyio.to_thread.run_sync(self.output_engine.sanitize, raw, snapshot)
        except GuardrailTimeout:
            await self.monitor.input_failed(raw)
            raise
        # The raw text is judged: masking does not change meaning, and paraphrased leaks have no pattern.
        hit, timing = await self._judge("output", [raw], snapshot, observe=result.blocked)
        timing = _layers(timing, "output", not result.blocked, result.output_ms, hit)
        if hit is None:
            return result, timing
        return SanitizationResult(BLOCKED_MESSAGE, True, True, (*result.hits, hit), result.output_ms), timing


_SEVERITY = {"pass": 0, "error": 1, "block": 2}


def merge_layers(into: dict[str, tuple[str, float]], new: dict[str, tuple[str, float]]) -> None:
    """Several checks of one layer in a turn (e.g. two Tool results): worst verdict, summed time."""
    for key, (verdict, ms) in new.items():
        if key.startswith("_"):
            continue
        old = into.get(key)
        if old is None:
            into[key] = (verdict, ms)
        else:
            worse = verdict if _SEVERITY[verdict] > _SEVERITY[old[0]] else old[0]
            into[key] = (worse, round(old[1] + ms, 3))


def _add(a: JudgeTiming, b: JudgeTiming) -> JudgeTiming:
    return JudgeTiming(a.judge_ms + b.judge_ms, a.judge_calls + b.judge_calls, {**a.layers, **b.layers})


def _layers(timing: JudgeTiming, stage: str, rules_passed: bool, rules_ms: float, hit: Hit | None) -> JudgeTiming:
    layers = {f"{stage}_rules": ("pass" if rules_passed else "block", round(rules_ms, 3))}
    if "_judge" in timing.layers:
        layers[f"{stage}_judge"] = ("error", round(timing.judge_ms, 3))
    elif timing.judge_calls:
        layers[f"{stage}_judge"] = ("block" if hit is not None else "pass", round(timing.judge_ms, 3))
    return JudgeTiming(timing.judge_ms, timing.judge_calls, layers)


def _also_hit(result: InspectionResult, hit: Hit) -> InspectionResult:
    """Rules already blocked; the judge agreed, so its rule id is recorded as a second reason."""
    return replace(result, hits=(*result.hits, hit))


def _blocked_input(result: InspectionResult, hit: Hit) -> InspectionResult:
    return replace(
        result,
        allowed=False,
        hits=(*result.hits, hit),
        safe_summary=f"입력 차단: {hit.rule_id}",
        canonical_messages=(),
    )
