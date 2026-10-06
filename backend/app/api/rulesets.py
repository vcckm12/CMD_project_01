"""RULE-01~07 (DES-005 §2.4, DES-006 §6). Reads: operator/admin. Changes: admin, ops channel only.

Drafts are edited as a whole (rules + policy allowlist). Validation freezes a draft; publishing and
rollback re-check the admin's password, compare the expected active id, re-validate what will run,
commit state + publication + outbox, then swap the in-process snapshot immediately.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from app.api.auth import ok
from app.api.ops import ops_staff
from app.audit.outbox import AuditEnvelope, persist_event
from app.errors import ApiError
from app.guardrails import rule_store
from app.guardrails.ruleset import MAX_RULES, POLICY_KEYS, RulesetInvalid
from app.security import passwords
from app.security.auth import AuthContext

router = APIRouter(prefix="/api/v1/rulesets", tags=["rulesets"])
Staff = Annotated[AuthContext, Depends(ops_staff)]


async def ops_admin(ctx: Staff) -> AuthContext:
    if ctx.role != "admin":
        raise ApiError(403, "FORBIDDEN")
    return ctx


Admin = Annotated[AuthContext, Depends(ops_admin)]


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(pattern=r"^RULE_[A-Z0-9_]+$", max_length=80)
    stage: Literal["input", "execution", "output", "policy"]
    category: str = Field(pattern=r"^LLM(0[1-9]|10):2025$")
    kind: Literal["regex", "context", "structural"]
    pattern: str | None = Field(default=None, min_length=1, max_length=4096)
    flags: Literal["", "i", "is"] = ""
    action: Literal["block", "mask", "escape", "observe"]
    marker: str | None = Field(default=None, max_length=40)
    priority: StrictInt = Field(default=100, ge=0)


class DraftUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: list[RuleIn] = Field(min_length=1, max_length=MAX_RULES)
    policy: dict[str, StrictInt] = Field(default_factory=dict)


class CloneRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    parent_id: uuid.UUID
    version_label: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")


class PublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=128)
    expected_active_id: uuid.UUID | None


async def _record(conn, request: Request, ctx: AuthContext, summary: str, ruleset_id=None) -> None:
    await persist_event(
        conn,
        AuditEnvelope(
            request_id=uuid.UUID(request.state.request_id), actor_id=ctx.user_id, source=ctx.source,
            api_path=request.url.path, status="success", summary_redacted=summary, ruleset_version=ruleset_id,
        ),
    )  # fmt: skip


def _summary(row: dict) -> dict:
    return {
        "id": str(row["id"]),
        "version_label": row["version_label"],
        "state": row["state"],
        "parent_id": str(row["parent_id"]) if row["parent_id"] else None,
        "checksum": row["checksum"],
        "created_at": row["created_at"].isoformat(),
        "validated_at": row["validated_at"].isoformat() if row["validated_at"] else None,
        "activated_at": row["activated_at"].isoformat() if row["activated_at"] else None,
    }


@router.get("")
async def list_rulesets(request: Request, ctx: Staff) -> JSONResponse:
    async with request.app.state.pools.rules.connection() as conn:
        rows = await (
            await conn.execute(
                "SELECT id, version_label, state, parent_id, checksum, created_at, validated_at, activated_at"
                " FROM threat_intel.rulesets ORDER BY created_at DESC LIMIT 100"
            )
        ).fetchall()
    loaded = request.app.state.rule_cache.current()
    return ok(
        request,
        {
            "items": [_summary(r) for r in rows],
            "next_cursor": None,
            "loaded_version": str(loaded.version_id) if loaded and loaded.version_id else None,
            "guardrail_enforced": True,
        },
    )


@router.get("/{ruleset_id}")
async def get_ruleset(request: Request, ruleset_id: uuid.UUID, ctx: Staff) -> JSONResponse:
    async with request.app.state.pools.rules.connection() as conn:
        row = await (
            await conn.execute(
                "SELECT id, version_label, state, parent_id, checksum, created_at, validated_at, activated_at, policy"
                " FROM threat_intel.rulesets WHERE id = %s",
                (ruleset_id,),
            )
        ).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND")
        rules = await (
            await conn.execute(
                f"SELECT {rule_store.RULE_COLUMNS} FROM threat_intel.rules WHERE ruleset_id = %s"  # noqa: S608
                " ORDER BY stage, priority, rule_id",
                (ruleset_id,),
            )
        ).fetchall()
    return ok(request, {**_summary(row), "policy": row["policy"], "rules": rules})


@router.post("", status_code=201)
async def clone(request: Request, body: CloneRequest, ctx: Admin) -> JSONResponse:
    async with request.app.state.pools.rules.connection() as conn:
        parent = await (
            await conn.execute("SELECT policy FROM threat_intel.rulesets WHERE id = %s", (body.parent_id,))
        ).fetchone()
        if parent is None:
            raise ApiError(404, "NOT_FOUND")
        rules = await rule_store._rules(conn, body.parent_id)
        try:
            draft = await rule_store.create_draft(
                conn, label=body.version_label, actor_id=ctx.user_id, rules=rules, policy=parent["policy"],
                parent_id=body.parent_id,
            )  # fmt: skip
        except UniqueViolation as exc:
            raise ApiError(409, "RULESET_CONFLICT") from exc
        async with conn.transaction():
            await _record(conn, request, ctx, f"룰셋 draft 복제: {body.version_label}", draft)
    return ok(request, {"id": str(draft), "state": "draft"}, 201)


@router.put("/{ruleset_id}")
async def update_draft(request: Request, ruleset_id: uuid.UUID, body: DraftUpdate, ctx: Admin) -> JSONResponse:
    if set(body.policy) - set(POLICY_KEYS):
        # Includes guardrail_enabled or anything else that is not a known stricter-only limit.
        raise ApiError(422, "VALIDATION_ERROR")
    async with request.app.state.pools.rules.connection() as conn, conn.transaction():
        row = await (
            await conn.execute("SELECT state FROM threat_intel.rulesets WHERE id = %s FOR UPDATE", (ruleset_id,))
        ).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND")
        if row["state"] != "draft":
            raise ApiError(409, "RULESET_CONFLICT")
        await conn.execute("DELETE FROM threat_intel.rules WHERE ruleset_id = %s", (ruleset_id,))
        async with conn.cursor() as cur:
            await cur.executemany(
                f"INSERT INTO threat_intel.rules (ruleset_id, {rule_store.RULE_COLUMNS})"  # noqa: S608
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [(ruleset_id, r.rule_id, r.stage, r.category, r.kind, r.pattern, r.flags, r.action, r.marker,
                  r.priority) for r in body.rules],
            )  # fmt: skip
        await conn.execute(
            "UPDATE threat_intel.rulesets SET policy = %s WHERE id = %s", (Jsonb(body.policy), ruleset_id)
        )
        await _record(conn, request, ctx, f"룰셋 draft 저장: 룰 {len(body.rules)}개", ruleset_id)
    return ok(request, {"id": str(ruleset_id), "state": "draft", "rules": len(body.rules)})


@router.post("/{ruleset_id}/validate")
async def validate(request: Request, ruleset_id: uuid.UUID, ctx: Admin) -> JSONResponse:
    async with request.app.state.pools.rules.connection() as conn:
        failures = await rule_store.validate_draft(conn, ruleset_id)
        if failures == ["NOT_A_DRAFT"]:
            raise ApiError(409, "RULESET_CONFLICT")
        if failures:
            raise ApiError(422, "RULESET_VALIDATION_FAILED", details=failures)
        async with conn.transaction():
            await _record(conn, request, ctx, "룰셋 검증 통과", ruleset_id)
    return ok(request, {"id": str(ruleset_id), "state": "validated"})


async def _reauth(request: Request, ctx: AuthContext, password: str) -> None:
    async with request.app.state.pools.auth.connection() as conn:
        row = await (
            await conn.execute("SELECT password_hash FROM commerce.users WHERE id = %s", (ctx.user_id,))
        ).fetchone()
    if not await passwords.verify_password(row["password_hash"] if row else None, password):
        raise ApiError(403, "REAUTH_FAILED")


async def _activate(request: Request, ruleset_id: uuid.UUID, body: PublishRequest, ctx: AuthContext, rollback: bool):
    await _reauth(request, ctx, body.password)  # the password is never stored or logged
    async with request.app.state.pools.rules.connection() as conn:
        state = await (
            await conn.execute("SELECT state FROM threat_intel.rulesets WHERE id = %s", (ruleset_id,))
        ).fetchone()
        if state is None:
            raise ApiError(404, "NOT_FOUND")
        if (state["state"] == "retired") != rollback:
            raise ApiError(409, "RULESET_CONFLICT")
        try:
            snapshot = await rule_store.publish(
                conn, ruleset_id=ruleset_id, expected_active_id=body.expected_active_id, actor_id=ctx.user_id,
                request_id=uuid.UUID(request.state.request_id), source=ctx.source, api_path=request.url.path,
            )  # fmt: skip
        except rule_store.PublishConflict as exc:
            raise ApiError(409, "RULESET_CONFLICT") from exc
        except RulesetInvalid as exc:
            raise ApiError(422, "RULESET_VALIDATION_FAILED", details=exc.failures) from exc
    # Same process: swap now instead of waiting for the poller (requests keep their own snapshot).
    request.app.state.rule_cache.install(snapshot)
    return ok(request, {"id": str(ruleset_id), "state": "active", "checksum": snapshot.checksum})


@router.post("/{ruleset_id}/publish")
async def publish(request: Request, ruleset_id: uuid.UUID, body: PublishRequest, ctx: Admin) -> JSONResponse:
    return await _activate(request, ruleset_id, body, ctx, rollback=False)


@router.post("/{ruleset_id}/rollback")
async def rollback(request: Request, ruleset_id: uuid.UUID, body: PublishRequest, ctx: Admin) -> JSONResponse:
    return await _activate(request, ruleset_id, body, ctx, rollback=True)
