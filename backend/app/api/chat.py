"""CHAT-01 native chat, SESSION-01/02, TOOL-01 (DES-005 §2.1·§2.2·§3)."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from app.api.auth import ok
from app.chat.service import ChatOutcome, ChatService, ChatTurn
from app.errors import FIXED_MESSAGES, ApiError
from app.guardrails.execution_guardrail import available_tools
from app.guardrails.input_guardrail import InputMessage
from app.guardrails.normalize import canonical
from app.security.auth import AuthContext, authenticate, require_scope
from app.services.prompts import CUSTOMER_SYSTEM_PROMPT, STAFF_SYSTEM_PROMPT

router = APIRouter(tags=["chat"])
SSE_CHUNK = 256
NATIVE_TEMPERATURE = 0.2  # factual shop answers; fewer paraphrased numbers


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: uuid.UUID
    prompt: str = Field(min_length=1, max_length=8000)
    model: str = "qwen3:8b"
    stream: bool = False


def _empty_body(body: dict) -> None:
    if body:
        raise ApiError(422, "VALIDATION_ERROR")


def check_model(request: Request, model: str) -> None:
    if model != request.app.state.settings.ollama_model:
        raise ApiError(400, "UNSUPPORTED_MODEL")


async def require_jwt(request: Request) -> AuthContext:
    ctx = await authenticate(request)
    if ctx.kind != "jwt":
        raise ApiError(403, "FORBIDDEN")
    return ctx


@router.post("/api/v1/sessions", status_code=201)
async def create_session(
    request: Request, ctx: Annotated[AuthContext, Depends(authenticate)], body: Annotated[dict, Body()] = None
) -> JSONResponse:
    _empty_body(body or {})
    if ctx.kind == "client_token":
        require_scope(ctx, "chat:write")
    session_id = await ChatService(request.app.state).create_session(ctx)
    return ok(request, {"session_id": str(session_id), "source": ctx.source}, 201)


@router.get("/api/v1/sessions/{session_id}")
async def get_session(
    request: Request, session_id: uuid.UUID, ctx: Annotated[AuthContext, Depends(authenticate)]
) -> JSONResponse:
    async with request.app.state.pools.chat.connection() as conn:
        row = await (
            await conn.execute(
                "SELECT context_redacted, last_activity_at FROM commerce.chat_sessions WHERE id = %s AND user_id = %s",
                (session_id, ctx.user_id),
            )
        ).fetchone()
    if row is None:
        raise ApiError(404, "NOT_FOUND")
    # risk_signals stay internal.
    return ok(
        request,
        {"session_id": str(session_id), "context": row["context_redacted"],
         "last_activity_at": row["last_activity_at"].isoformat()},
    )  # fmt: skip


@router.get("/api/v1/tools")
async def list_tools(request: Request, ctx: Annotated[AuthContext, Depends(authenticate)]) -> JSONResponse:
    if ctx.kind == "client_token":
        require_scope(ctx, "tools:read")
    tools = [
        {"name": t.name, "description": t.description, "arguments": t.schema()["function"]["parameters"],
         "requires_confirmation": t.requires_confirmation}
        for t in available_tools(ctx)
    ]  # fmt: skip
    return ok(request, {"items": tools, "next_cursor": None})


def _native_body(request: Request, ctx: AuthContext, outcome: ChatOutcome) -> dict:
    blocked = outcome.status == "blocked"
    staff = ctx.role in ("operator", "admin")
    return {
        "request_id": request.state.request_id,
        "session_id": str(outcome.session_id),
        "status": outcome.status,
        "content": outcome.content,
        "guardrail": {
            "active": True,
            "ruleset_version": str(outcome.ruleset_version) if outcome.ruleset_version else None,
            "stage": outcome.stage,
            # Customers never see rule ids; staff verification chats do (DES-005 §3.2).
            "rule_ids": sorted({h.rule_id for h in outcome.hits}) if staff else [],
        },
        "action": outcome.action,
        "error": {"code": "GUARDRAIL_BLOCKED", "message": FIXED_MESSAGES["GUARDRAIL_BLOCKED"]} if blocked else None,
        "timing": {"input_ms": outcome.input_ms, "output_ms": outcome.output_ms, "total_ms": outcome.total_ms},
    }


async def _native_sse(body: dict) -> AsyncIterator[bytes]:
    def event(name: str, data: dict) -> bytes:
        return f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode()

    yield event("meta", {"request_id": body["request_id"], "status": body["status"], "session_id": body["session_id"]})
    content = body["content"]
    for i in range(0, len(content), SSE_CHUNK):  # already sanitized text, split on code points
        yield event("delta", {"content": content[i : i + SSE_CHUNK]})
    yield event("done", {k: body[k] for k in ("status", "action", "guardrail", "timing")})


@router.post("/api/v1/chat/completions")
async def chat_completions(request: Request, body: ChatRequest, ctx: Annotated[AuthContext, Depends(require_jwt)]):
    check_model(request, body.model)
    if not body.prompt.strip():
        raise ApiError(422, "VALIDATION_ERROR")
    service = ChatService(request.app.state)
    history, signals = await service.load_session(ctx, body.session_id)
    turn = ChatTurn(
        ctx=ctx,
        request_id=request.state.request_id,
        started=request.state.started,
        session_id=body.session_id,
        api_path="/api/v1/chat/completions",
        system_prompt=CUSTOMER_SYSTEM_PROMPT if ctx.role == "customer" else STAFF_SYSTEM_PROMPT,
        inspect=[InputMessage("user", body.prompt)],
        model_new=[{"role": "user", "content": canonical(body.prompt)}],
        history=history,
        risk_signals=signals,
        stored_context=history,
        temperature=NATIVE_TEMPERATURE,
    )
    outcome = await service.run(turn)
    payload = _native_body(request, ctx, outcome)
    if outcome.status == "blocked":
        return JSONResponse(payload, status_code=403)
    if body.stream:
        return StreamingResponse(
            _native_sse(payload),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )
    return JSONResponse(payload)
