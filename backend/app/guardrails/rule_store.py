"""Ruleset persistence: draft → validated → active → retired (DES-006 §6, DES-002 threat_intel).

Writes run on the rule_publisher pool; DB triggers freeze validated content. Publishing commits the
state change, the publication row and its outbox event in one transaction. All reads use explicit
tuple/dict cursors, so the caller's pool row factory does not matter.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping

from psycopg import AsyncConnection
from psycopg.rows import dict_row, tuple_row
from psycopg.types.json import Jsonb

from app.audit.outbox import AuditEnvelope, Source, persist_event
from app.guardrails.ruleset import (
    DEFAULT_RULES,
    ENGINE_VERSION,
    RulesetInvalid,
    RuleSnapshot,
    build_snapshot,
    checksum,
    validate,
)
from app.guardrails.types import RuleDef

RULE_COLUMNS = "rule_id, stage, category, kind, pattern, flags, action, marker, priority"


class PublishConflict(Exception):
    """expected_active_id did not match the current active ruleset (409 RULESET_CONFLICT)."""


async def _one(conn: AsyncConnection, query: str, params: tuple = ()) -> tuple | None:
    async with conn.cursor(row_factory=tuple_row) as cur:
        await cur.execute(query, params)
        return await cur.fetchone()


async def _rules(conn: AsyncConnection, ruleset_id: uuid.UUID) -> list[RuleDef]:
    async with conn.cursor(row_factory=dict_row) as cur:
        # RULE_COLUMNS is a module constant; values are bound parameters.
        await cur.execute(f"SELECT {RULE_COLUMNS} FROM threat_intel.rules WHERE ruleset_id = %s", (ruleset_id,))  # noqa: S608
        return [RuleDef(**row) for row in await cur.fetchall()]


async def create_draft(
    conn: AsyncConnection,
    *,
    label: str,
    actor_id: uuid.UUID,
    rules: Iterable[RuleDef] = DEFAULT_RULES,
    policy: Mapping[str, int] | None = None,
    parent_id: uuid.UUID | None = None,
) -> uuid.UUID:
    async with conn.transaction():
        (ruleset_id,) = await _one(
            conn,
            "INSERT INTO threat_intel.rulesets (version_label, parent_id, policy, created_by)"
            " VALUES (%s, %s, %s, %s) RETURNING id",
            (label, parent_id, Jsonb(dict(policy or {})), actor_id),
        )
        async with conn.cursor() as cur:
            await cur.executemany(
                f"INSERT INTO threat_intel.rules (ruleset_id, {RULE_COLUMNS})"  # noqa: S608 - constant columns
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [
                    (ruleset_id, r.rule_id, r.stage, r.category, r.kind, r.pattern, r.flags, r.action, r.marker,
                     r.priority)
                    for r in rules
                ],
            )  # fmt: skip
    return ruleset_id


async def validate_draft(conn: AsyncConnection, ruleset_id: uuid.UUID) -> list[str]:
    """Validate and freeze a draft. Returns failure codes; empty means it is now `validated`."""
    async with conn.transaction():
        row = await _one(
            conn, "SELECT state, policy FROM threat_intel.rulesets WHERE id = %s FOR UPDATE", (ruleset_id,)
        )
        if row is None or row[0] != "draft":
            return ["NOT_A_DRAFT"]
        state, policy = row
        rules = await _rules(conn, ruleset_id)
        failures = validate(rules, policy)
        if failures:
            return failures
        await conn.execute(
            "UPDATE threat_intel.rulesets SET state = 'validated', checksum = %s, validated_at = now() WHERE id = %s",
            (checksum(rules, policy), ruleset_id),
        )
    return []


async def publish(
    conn: AsyncConnection,
    *,
    ruleset_id: uuid.UUID,
    expected_active_id: uuid.UUID | None,
    actor_id: uuid.UUID,
    request_id: uuid.UUID,
    source: Source = "streamlit",
    api_path: str = "/api/v1/rulesets/publish",
) -> RuleSnapshot:
    """Activate a validated (or retired, for rollback) ruleset. Raises PublishConflict / RulesetInvalid."""
    async with conn.transaction():
        active = await _one(conn, "SELECT id FROM threat_intel.rulesets WHERE state = 'active' FOR UPDATE")
        current_active = active[0] if active else None
        if current_active != expected_active_id:
            raise PublishConflict
        row = await _one(
            conn,
            "SELECT state, policy, checksum, version_label FROM threat_intel.rulesets WHERE id = %s FOR UPDATE",
            (ruleset_id,),
        )
        if row is None or row[0] not in ("validated", "retired"):
            raise RulesetInvalid(["NOT_PUBLISHABLE"])
        state, policy, stored_checksum, label = row
        # Re-validate exactly what will run; a stored checksum mismatch means tampering or drift.
        snapshot = build_snapshot(
            await _rules(conn, ruleset_id), policy, version_id=ruleset_id, label=label,
            expected_checksum=stored_checksum,
        )  # fmt: skip
        outcome = "rolled_back" if state == "retired" else "published"
        if current_active is not None:
            await conn.execute("UPDATE threat_intel.rulesets SET state = 'retired' WHERE id = %s", (current_active,))
        await conn.execute(
            "UPDATE threat_intel.rulesets SET state = 'active', activated_at = now() WHERE id = %s", (ruleset_id,)
        )
        await conn.execute(
            "INSERT INTO threat_intel.policy_publications"
            " (ruleset_id, previous_id, actor_id, request_id, outcome, detail) VALUES (%s, %s, %s, %s, %s, %s)",
            (ruleset_id, current_active, actor_id, request_id, outcome,
             f"engine={ENGINE_VERSION} checksum={stored_checksum[:12]}"),
        )  # fmt: skip
        await persist_event(
            conn,
            AuditEnvelope(
                request_id=request_id, actor_id=actor_id, source=source, api_path=api_path, status="success",
                ruleset_version=ruleset_id, summary_redacted=f"룰셋 {outcome}: {label}",
            ),
        )  # fmt: skip
    return snapshot


async def load_active(conn: AsyncConnection) -> RuleSnapshot | None:
    """Load and fully re-validate the active ruleset (rule_reader). None when nothing is active."""
    row = await _one(
        conn, "SELECT id, version_label, policy, checksum FROM threat_intel.rulesets WHERE state = 'active'"
    )
    if row is None:
        return None
    ruleset_id, label, policy, stored_checksum = row
    rules = await _rules(conn, ruleset_id)
    return build_snapshot(rules, policy, version_id=ruleset_id, label=label, expected_checksum=stored_checksum)


async def active_id(conn: AsyncConnection) -> uuid.UUID | None:
    row = await _one(conn, "SELECT id FROM threat_intel.rulesets WHERE state = 'active'")
    return row[0] if row else None
