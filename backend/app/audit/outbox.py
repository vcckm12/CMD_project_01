"""AuditLogger.persist_event (DES-006 §7, DES-002 §6).

The envelope is built from an allowlist of fields and validated strictly, then inserted
into audit.outbox inside the caller's transaction so business changes and their audit
record commit or roll back together. Raw input, tokens and passwords never enter it.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Literal

from psycopg import AsyncConnection
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, model_validator

Status = Literal["success", "blocked", "masked", "confirmation_required", "error"]
Stage = Literal["input", "execution", "output", "policy"]
Source = Literal["web", "anythingllm", "streamlit", "system"]


class RuleHit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    rule_id: str = Field(pattern=r"^RULE_[A-Z0-9_]+$", max_length=80)
    category: str = Field(pattern=r"^LLM(0[1-9]|10):2025$")
    stage: Stage
    action: Literal["block", "mask", "escape", "observe"]
    match_count: int = Field(gt=0)


class ToolExecution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    action_id: uuid.UUID | None = None
    tool_name: str = Field(max_length=64)
    outcome: Literal["read", "proposed", "executed", "denied", "error"]
    target_id: uuid.UUID | None = None
    duration_ms: float = Field(ge=0)


class AuditEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    request_id: uuid.UUID
    actor_id: uuid.UUID | None
    session_id: uuid.UUID | None = None
    source: Source
    api_path: str = Field(max_length=200)
    model: str | None = Field(default=None, max_length=80)
    status: Status
    stage: Stage | None = None
    ruleset_version: uuid.UUID | None = None
    input_chars: int = Field(default=0, ge=0)
    output_chars: int = Field(default=0, ge=0)
    input_ms: float = Field(default=0, ge=0)
    output_ms: float = Field(default=0, ge=0)
    total_ms: float = Field(default=0, ge=0)
    summary_redacted: str = Field(max_length=2000)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    rule_hits: tuple[RuleHit, ...] = Field(default=(), max_length=128)
    tool_executions: tuple[ToolExecution, ...] = Field(default=(), max_length=6)

    @model_validator(mode="after")
    def _stage_matches_status(self) -> AuditEnvelope:
        # Mirrors the audit.events CHECK so a bad envelope fails before commit, not in the worker.
        if (self.status == "blocked") != (self.stage is not None):
            raise ValueError("stage is required exactly when status is blocked")
        return self


def elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


async def persist_event(conn: AsyncConnection, envelope: AuditEnvelope) -> uuid.UUID:
    """Insert into audit.outbox using the caller's open transaction."""
    await conn.execute(
        "INSERT INTO audit.outbox (event_id, payload) VALUES (%s, %s)",
        (envelope.event_id, Jsonb(envelope.model_dump(mode="json"))),
    )
    return envelope.event_id
