"""InputGuardrailEngine.inspect() (DES-006 §3, DES-003 단계 2·3).

Steps: 0 limits → 1 Zero-Width/NFKC/confusables → 2·3 URL/Hex/Base64 → 4 separators/leet
→ 5 regex rules → 6 context rules (500-char window or recent 5 turns of risk signals).
A confirmed block stops before any model call. Timeouts propagate as GuardrailTimeout (fail closed).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from itertools import islice
from typing import Literal

import regex

from app.guardrails import lexicon as lx
from app.guardrails.budget import Budget, scaled_budget_ms
from app.guardrails.normalize import MAX_TOTAL_VARIANT_CHARS, ResourceLimit, Variant, build_variants, canonical
from app.guardrails.ruleset import RuleSnapshot, passes_prefilter
from app.guardrails.types import Hit, InspectionResult

MAX_MESSAGES = 40
SIGNAL_TURNS = 5
POSITIONS_PER_PATTERN = 50

_OUTPUT_OR_PERFORM = regex.compile(f"(?:{lx.OUTPUT_REQUEST.pattern})|(?:{lx.PERFORM_REQUEST.pattern})", lx.FLAGS)
_INVALIDATION_OR_SECRET = regex.compile(f"(?:{lx.RULE_INVALIDATION.pattern})|(?:{lx.SECRET_TARGET.pattern})", lx.FLAGS)
_SECRET_OR_PLACEHOLDER = regex.compile(f"(?:{lx.SECRET_TARGET.pattern})|(?:{lx.PLACEHOLDER.pattern})", lx.FLAGS)
_ROLE_SWITCH = regex.compile(f"(?:{lx.ROLEPLAY.pattern})|(?:{lx.RULE_INVALIDATION.pattern})", lx.FLAGS)


@dataclass(frozen=True)
class InputMessage:
    """`user`/`system`/`assistant` are untrusted client text; `tool`/`context` are Tool results or
    client-supplied RAG data checked for indirect injection."""

    role: Literal["system", "user", "assistant", "tool", "context"]
    content: str


class _Blocked(Exception):
    pass


class InputGuardrailEngine:
    def __init__(self, budget_ms: float = 50.0, per_call_ms: float = 20.0) -> None:
        self.budget_ms = budget_ms
        self.per_call_ms = per_call_ms

    def inspect(
        self, messages: Sequence[InputMessage], risk_signals: Mapping | None, snapshot: RuleSnapshot
    ) -> InspectionResult:
        budget = Budget(scaled_budget_ms(self.budget_ms, sum(len(m.content) for m in messages)), self.per_call_ms)
        run = _Run(snapshot, budget, _prior_turns(risk_signals))
        try:
            run.check_limits(messages)
            for message in messages:
                run.inspect_message(message)
        except _Blocked:
            pass
        hits = tuple(run.hits.values())
        allowed = not any(h.action == "block" for h in hits)
        summary = (
            "입력 검사 통과" if allowed else "입력 차단: " + ", ".join(h.rule_id for h in hits if h.action == "block")
        )
        return InspectionResult(
            allowed=allowed,
            hits=hits,
            risk_signals={"v": 1, "turns": run.turns[-SIGNAL_TURNS:]},
            input_ms=budget.elapsed_ms(),
            safe_summary=summary,
            canonical_messages=tuple(canonical(m.content) for m in messages) if allowed else (),
        )


def _prior_turns(risk_signals: Mapping | None) -> list[dict]:
    turns = (risk_signals or {}).get("turns", [])
    clean = []
    for t in turns[-SIGNAL_TURNS:] if isinstance(turns, list) else []:
        if isinstance(t, dict):
            clean.append({k: int(bool(t.get(k))) for k in ("r", "g", "s", "o")})
    return clean


class _Run:
    def __init__(self, snapshot: RuleSnapshot, budget: Budget, turns: list[dict]) -> None:
        self.snapshot = snapshot
        self.budget = budget
        self.turns = turns
        self.hits: dict[str, Hit] = {}
        self.variant_chars = 0

    # ------------------------------------------------------------------ helpers

    def hit(self, rule_id: str) -> None:
        compiled = self.snapshot.get(rule_id)
        if compiled is None:
            return
        r = compiled.rule
        previous = self.hits.get(rule_id)
        count = previous.match_count + 1 if previous else 1
        self.hits[rule_id] = Hit(r.rule_id, r.category, r.stage, r.action, count)
        if r.action == "block":
            raise _Blocked

    def found(self, pattern: regex.Pattern, text: str) -> bool:
        return self.budget.search(pattern, text)

    def cooccur(self, text: str, patterns: Iterable[regex.Pattern], window: int = lx.WINDOW_CHARS) -> bool:
        """True when every pattern matches within `window` chars of some anchor match."""
        positions: list[list[int]] = []
        for p in patterns:
            found = [m.start() for m in islice(self.budget.finditer(p, text), POSITIONS_PER_PATTERN)]
            if not found:
                return False
            positions.append(found)
        anchors, others = positions[0], positions[1:]
        return any(all(any(abs(o - a) <= window for o in group) for group in others) for a in anchors)

    # -------------------------------------------------------------------- steps

    def check_limits(self, messages: Sequence[InputMessage]) -> None:
        user_limit = self.snapshot.limit("max_user_chars")
        total_limit = self.snapshot.limit("max_request_chars")
        if (
            len(messages) > MAX_MESSAGES
            or sum(len(m.content) for m in messages) > total_limit
            or any(len(m.content) > user_limit for m in messages if m.role == "user")
        ):
            self.hit("RULE_TOKEN_FLOOD")

    def variants(self, text: str) -> list[Variant]:
        try:
            variants = build_variants(text)
        except ResourceLimit:
            self.hit("RULE_TOKEN_FLOOD")
            raise  # unreachable when RULE_TOKEN_FLOOD blocks; kept for observe-only rulesets
        self.variant_chars += sum(len(v.text) for v in variants[1:])
        if self.variant_chars > MAX_TOTAL_VARIANT_CHARS:
            self.hit("RULE_TOKEN_FLOOD")
        return variants

    def terms(self, text: str) -> set[str]:
        return {"".join(m.group().lower().split()) for m in self.budget.finditer(lx.SENSITIVE_TERMS, text)}

    def inspect_message(self, message: InputMessage) -> None:
        tagged = self.variants(message.content)
        variants = [v.text for v in tagged]
        folded = [v.casefold() for v in variants]
        for compiled in self.snapshot.stage("input", "regex"):
            if any(
                passes_prefilter(compiled.prefilter, f) and self.found(compiled.pattern, v)
                for v, f in zip(variants, folded, strict=True)
            ):
                self.hit(compiled.rule.rule_id)
        # After the specific rules so audits name the concrete attack when one matches: a sensitive word
        # that exists only after un-confusing, decoding or joining separators signals deliberate evasion.
        original_terms = self.terms(tagged[0].text)
        if any(v.kind != "leet" and self.terms(v.text) - original_terms for v in tagged[1:]):
            self.hit("RULE_OBFUSCATED_SENSITIVE_TERM")
        if message.role in ("tool", "context"):
            if any(self.found(lx.EMBEDDED_INSTRUCTION, v) for v in variants):
                self.hit("RULE_INDIRECT_CONTEXT_INJECTION")
            return
        for v in variants:
            self.context_rules(v)
        if message.role == "user":
            self.turn_rules(variants)

    def context_rules(self, text: str) -> None:
        sql = self.snapshot.get("RULE_SQL_COMMAND_ABUSE")
        if sql and sql.pattern and self.cooccur(text, (lx.EXEC_REQUEST, sql.pattern)):
            self.hit("RULE_SQL_COMMAND_ABUSE")
        shell = self.snapshot.get("RULE_DANGEROUS_SHELL_INJECTION")
        if shell and shell.pattern and self.cooccur(text, (lx.EXEC_REQUEST, shell.pattern)):
            self.hit("RULE_DANGEROUS_SHELL_INJECTION")
        if self.cooccur(text, (lx.GRANDMA, lx.SECRET_TARGET, _OUTPUT_OR_PERFORM)):
            self.hit("RULE_SEMANTIC_GRANDMA_EXPLOIT")
        if self.cooccur(text, (lx.ROLEPLAY, _INVALIDATION_OR_SECRET, _OUTPUT_OR_PERFORM)):
            self.hit("RULE_SEMANTIC_PERSONA_ESCAPE")
        if self.cooccur(text, (lx.EXTERNAL_IMAGE_OR_URL, lx.VALUE_BINDING, _SECRET_OR_PLACEHOLDER)):
            self.hit("RULE_SEMANTIC_INDIRECT_EXFILTRATION")
        if self.cooccur(text, (lx.PY_INTROSPECTION, lx.PY_SINK, lx.EXEC_REQUEST)):
            self.hit("RULE_SEMANTIC_PYTHON_SANDBOX_ESCAPE")

    def turn_rules(self, variants: list[str]) -> None:
        """Multi-turn: only kinds and counts of signals are kept, never the text (DES-006 §3.2)."""
        current = {
            "r": int(any(self.found(_ROLE_SWITCH, v) for v in variants)),
            "g": int(any(self.found(lx.GRANDMA, v) for v in variants)),
            "s": int(any(self.found(lx.SECRET_TARGET, v) for v in variants)),
            "o": int(any(self.found(lx.OUTPUT_REQUEST, v) for v in variants)),
        }
        recent = self.turns[-SIGNAL_TURNS:]
        self.turns.append(current)
        if not recent:
            return
        followup = any(self.found(lx.FOLLOWUP_REFERENCE, v) for v in variants)
        earlier_secret = any(t["s"] for t in recent)
        earlier_role = any(t["r"] or t["g"] for t in recent)
        if current["o"] and ((followup and earlier_secret) or (current["s"] and earlier_role)):
            self.hit("RULE_MULTI_TURN_SECRET_FOLLOWUP")
