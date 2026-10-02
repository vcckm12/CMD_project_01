"""Shared guardrail types (DES-006 §2). Hits carry ids and counts only, never matched text."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Stage = Literal["input", "execution", "output", "policy"]
Action = Literal["block", "mask", "escape", "observe"]
Kind = Literal["regex", "context", "structural"]


@dataclass(frozen=True)
class RuleDef:
    rule_id: str
    stage: Stage
    category: str
    kind: Kind
    action: Action
    pattern: str | None = None
    flags: Literal["", "i", "is"] = ""
    marker: str | None = None
    priority: int = 100

    def as_row(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "stage": self.stage,
            "category": self.category,
            "kind": self.kind,
            "pattern": self.pattern,
            "flags": self.flags,
            "action": self.action,
            "marker": self.marker,
            "priority": self.priority,
        }


@dataclass(frozen=True)
class Hit:
    rule_id: str
    category: str
    stage: Stage
    action: Action
    match_count: int = 1


class GuardrailTimeout(Exception):
    """Inspection budget exhausted. Callers must fail closed (503), never pass the content."""


class OutputTooLong(Exception):
    """Generated output exceeds the configured limit; it is discarded as a general error."""


@dataclass(frozen=True)
class InspectionResult:
    allowed: bool
    hits: tuple[Hit, ...]
    risk_signals: dict
    input_ms: float
    safe_summary: str
    canonical_messages: tuple[str, ...] = field(default=())


@dataclass(frozen=True)
class SanitizationResult:
    content: str
    blocked: bool
    changed: bool
    hits: tuple[Hit, ...]
    output_ms: float
