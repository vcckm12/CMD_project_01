"""ACTION-01~04: propose, view, confirm and cancel cart/coupon changes (DES-005 §2.3, DES-006 §5.3)."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from app.api.auth import ok
from app.errors import ApiError
from app.security.auth import AuthContext, authenticate, require_customer_jwt, require_scope
from app.shop import actions

router = APIRouter(prefix="/api/v1/actions", tags=["actions"])
IDEMPOTENCY_KEY_MAX = 128


class ProposeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str = Field(max_length=64)
    arguments: dict[str, Any]
    base_version: StrictInt = Field(ge=0)
    session_id: uuid.UUID | None = None


def _empty(body: dict | None) -> None:
    # Confirmation carries no arguments: price, quantity or user_id can never be changed at this step.
    if body:
        raise ApiError(422, "VALIDATION_ERROR")


def _ruleset(request: Request):
    cache = request.app.state.rule_cache
    snapshot = cache.current()
    if snapshot is None or not cache.consistent:
        raise ApiError(503, "RULESET_UNAVAILABLE")
    return snapshot


def _map(exc: Exception) -> ApiError:
    if isinstance(exc, actions.ActionInvalid):
        return ApiError(422, "ACTION_INVALID", reason=exc.reason)
    return {
        actions.ActionNotFound: ApiError(404, "NOT_FOUND"),
        actions.ActionStale: ApiError(409, "ACTION_STALE"),
        actions.ActionTerminal: ApiError(409, "ACTION_TERMINAL"),
        actions.ActionExpired: ApiError(410, "ACTION_EXPIRED"),
        actions.IdempotencyConflict: ApiError(409, "IDEMPOTENCY_CONFLICT"),
    }[type(exc)]


ACTION_ERRORS = (
    actions.ActionInvalid,
    actions.ActionNotFound,
    actions.ActionStale,
    actions.ActionTerminal,
    actions.ActionExpired,
    actions.IdempotencyConflict,
)


@router.post("", status_code=201)
async def propose(request: Request, body: ProposeRequest, ctx: Annotated[AuthContext, Depends(authenticate)]):
    if ctx.role != "customer":
        raise ApiError(403, "FORBIDDEN")
    if ctx.kind == "client_token":
        require_scope(ctx, "actions:propose")
    snapshot = _ruleset(request)
    if body.session_id is not None:
        async with request.app.state.pools.chat.connection() as conn:
            owned = await (
                await conn.execute(
                    "SELECT 1 FROM commerce.chat_sessions WHERE id = %s AND user_id = %s",
                    (body.session_id, ctx.user_id),
                )
            ).fetchone()
        if owned is None:
            raise ApiError(404, "NOT_FOUND")
    try:
        async with request.app.state.pools.chat.connection() as conn:
            row, proposal = await actions.propose(
                conn,
                user_id=ctx.user_id,
                tool_name=body.tool_name,
                raw_arguments=body.arguments,
                base_version=body.base_version,
                session_id=body.session_id,
                request_id=request.state.request_id,
                source=ctx.source,
                ruleset_version=snapshot.version_id,
                ttl_seconds=request.app.state.settings.action_ttl_seconds,
            )
    except ACTION_ERRORS as exc:
        raise _map(exc) from exc
    return ok(
        request,
        {
            "action_id": str(row["id"]),
            "state": "pending",
            "expires_at": row["expires_at"].isoformat(),
            "preview": proposal.preview,
            "confirmation_url": f"{request.app.state.settings.shop_origin}/actions/{row['id']}",
        },
        201,
    )


@router.get("/{action_id}")
async def get_action(
    request: Request, action_id: uuid.UUID, ctx: Annotated[AuthContext, Depends(require_customer_jwt)]
) -> JSONResponse:
    try:
        async with request.app.state.pools.chat.connection() as conn:
            return ok(request, await actions.get(conn, ctx.user_id, action_id))
    except ACTION_ERRORS as exc:
        raise _map(exc) from exc


@router.post("/{action_id}/confirm")
async def confirm(
    request: Request,
    action_id: uuid.UUID,
    ctx: Annotated[AuthContext, Depends(require_customer_jwt)],
    body: Annotated[dict | None, Body()] = None,
) -> JSONResponse:
    _empty(body)
    key = request.headers.get("idempotency-key", "")
    if not (1 <= len(key) <= IDEMPOTENCY_KEY_MAX and key.isascii() and key.isprintable()):
        raise ApiError(422, "VALIDATION_ERROR")
    snapshot = _ruleset(request)
    try:
        async with request.app.state.pools.chat.connection() as conn:
            data = await actions.confirm(
                conn,
                user_id=ctx.user_id,
                action_id=action_id,
                idempotency_key=key,
                request_id=request.state.request_id,
                ruleset_version=snapshot.version_id,
            )
    except ACTION_ERRORS as exc:
        raise _map(exc) from exc
    except Exception as exc:  # noqa: BLE001 - DB/outbox failure: the transaction rolled back, nothing changed
        raise ApiError(503, "AUDIT_UNAVAILABLE") from exc
    return ok(request, data)


@router.post("/{action_id}/cancel")
async def cancel(
    request: Request,
    action_id: uuid.UUID,
    ctx: Annotated[AuthContext, Depends(require_customer_jwt)],
    body: Annotated[dict | None, Body()] = None,
) -> JSONResponse:
    _empty(body)
    try:
        async with request.app.state.pools.chat.connection() as conn:
            data = await actions.cancel(
                conn, user_id=ctx.user_id, action_id=action_id, request_id=request.state.request_id
            )
    except ACTION_ERRORS as exc:
        raise _map(exc) from exc
    return ok(request, data)
