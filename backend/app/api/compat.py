"""CHAT-02 / CHAT-03: OpenAI-compatible subset for AnythingLLM (DES-005 §4).

Every client message (system/assistant included) is untrusted and inspected. Client system/RAG text
reaches the model only as labelled reference data under the server system prompt. Blocks answer
HTTP 200 with a fixed refusal; the audit status is still `blocked`.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.api.chat import check_model
from app.chat.service import ChatOutcome, ChatService, ChatTurn
from app.errors import ApiError
from app.guardrails.input_guardrail import InputMessage
from app.guardrails.normalize import canonical
from app.security.auth import AuthContext, authenticate, require_scope
from app.services.prompts import CLIENT_CONTEXT_PREFIX, CUSTOMER_SYSTEM_PROMPT

router = APIRouter(tags=["openai-compat"])
ALLOWED_KEYS = {"model", "messages", "stream", "temperature", "max_tokens", "n", "user", "stream_options"}
# Sampling hints that general clients (AnythingLLM, OpenAI SDKs) send by default. Type-checked, then ignored:
# none of them can change the guardrail, the tools or the server system prompt (D-38).
IGNORED_KEYS = {"top_p", "frequency_penalty", "presence_penalty", "seed", "stop", "max_completion_tokens"}
MAX_TOKENS = 512


class CompatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["system", "user", "assistant"]
    content: str = Field(max_length=8000)


class CompatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str
    messages: list[CompatMessage] = Field(min_length=1, max_length=40)
    stream: bool = False
    temperature: float = Field(default=0.2, ge=0, le=2)  # clamped to 1 below
    max_tokens: int = Field(default=MAX_TOKENS, ge=1)  # clamped to MAX_TOKENS below
    n: Literal[1] = 1
    user: str | None = Field(default=None, max_length=128)  # never used for identity or sessions
    stream_options: dict | None = None
    top_p: float | None = Field(default=None, ge=0, le=1)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    seed: int | None = None
    stop: str | list[str] | None = None
    max_completion_tokens: int | None = Field(default=None, ge=1)

    @property
    def include_usage(self) -> bool:
        return bool((self.stream_options or {}).get("include_usage"))


async def require_customer(request: Request) -> AuthContext:
    ctx = await authenticate(request)
    if ctx.role != "customer":
        raise ApiError(403, "FORBIDDEN")
    return ctx


@router.get("/v1/models")
async def models(request: Request, ctx: Annotated[AuthContext, Depends(require_customer)]) -> JSONResponse:
    if ctx.kind == "client_token":
        require_scope(ctx, "models:read")
    name = request.app.state.settings.ollama_model
    return JSONResponse({"object": "list", "data": [{"id": name, "object": "model", "owned_by": "local"}]})


async def _parse(request: Request) -> CompatRequest:
    try:
        raw = json.loads(await request.body())
    except ValueError as exc:
        raise ApiError(400, "INVALID_REQUEST") from exc
    if not isinstance(raw, dict) or set(raw) - ALLOWED_KEYS - IGNORED_KEYS:
        raise ApiError(400, "INVALID_REQUEST")  # unsupported options (tools, tool_choice, logprobs, n>1 …)
    options = raw.get("stream_options")
    if options is not None and (
        not isinstance(options, dict)
        or set(options) - {"include_usage"}
        or not isinstance(options.get("include_usage"), bool)
    ):
        raise ApiError(400, "INVALID_REQUEST")
    try:
        req = CompatRequest.model_validate(raw)
    except ValidationError as exc:
        raise ApiError(422, "VALIDATION_ERROR") from exc
    # Larger client defaults (AnythingLLM sends 1024) are served at the server limits instead of refused.
    limit = min(req.max_completion_tokens or req.max_tokens, req.max_tokens, MAX_TOKENS)
    req = req.model_copy(update={"max_tokens": limit, "temperature": min(req.temperature, 1.0)})
    if req.messages[-1].role != "user" or sum(len(m.content) for m in req.messages) > 32000:
        raise ApiError(422, "VALIDATION_ERROR")
    return req


async def _session(request: Request, service: ChatService, ctx: AuthContext) -> tuple[uuid.UUID, list, dict]:
    header = request.headers.get("x-session-id")
    if header:
        try:
            session_id = uuid.UUID(header)
        except ValueError as exc:
            raise ApiError(422, "VALIDATION_ERROR") from exc
        stored, signals = await service.load_session(ctx, session_id)  # 404 when not owned
        return session_id, stored, signals
    return await service.create_session(ctx), [], {}


def _model_messages(messages: list[CompatMessage]) -> tuple[list[dict], list[dict]]:
    """(history, new) for the model. Client system text becomes labelled reference data."""
    converted = []
    for m in messages:
        if m.role == "system":
            converted.append({"role": "user", "content": CLIENT_CONTEXT_PREFIX + canonical(m.content)})
        else:
            converted.append({"role": m.role, "content": canonical(m.content)})
    return converted[:-1], converted[-1:]


@router.post("/v1/chat/completions")
async def chat_completions(request: Request, ctx: Annotated[AuthContext, Depends(require_customer)]):
    if ctx.kind == "client_token":
        require_scope(ctx, "chat:write")
    req = await _parse(request)
    check_model(request, req.model)
    service = ChatService(request.app.state)
    session_id, stored, signals = await _session(request, service, ctx)
    history, new = _model_messages(req.messages)
    turn = ChatTurn(
        ctx=ctx,
        request_id=request.state.request_id,
        started=request.state.started,
        session_id=session_id,
        api_path="/v1/chat/completions",
        system_prompt=CUSTOMER_SYSTEM_PROMPT,
        inspect=[InputMessage(m.role, m.content) for m in req.messages],
        model_new=new,
        history=history,
        risk_signals=signals,
        stored_context=stored,
        temperature=req.temperature,
        max_tokens=req.max_tokens,
    )
    outcome = await service.run(turn)
    if outcome.action is not None:
        # AnythingLLM cannot confirm (client tokens may only propose): point the customer to the shop web.
        outcome.content += f"\n확인 링크: {outcome.action['confirmation_url']}"
    headers = {
        "X-Guardrail-Status": outcome.status,
        "X-Ruleset-Version": str(outcome.ruleset_version or ""),
        "X-Session-Id": str(session_id),
    }
    completion_id = f"chatcmpl-{request.state.request_id}"
    created = int(time.time())
    if req.stream:
        return StreamingResponse(
            _sse(outcome, completion_id, created, req.model, req.include_usage),
            media_type="text/event-stream",
            headers={**headers, "Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )
    return JSONResponse(
        {
            "id": completion_id,
            "object": "chat.completion",
            "created": created,
            "model": req.model,
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": outcome.content}, "finish_reason": "stop"}
            ],
            "usage": _usage(outcome),
        },
        headers=headers,
    )


def _usage(outcome: ChatOutcome) -> dict:
    # Real token counts of completed model calls; zero when the input was blocked before inference.
    return {
        "prompt_tokens": outcome.prompt_tokens,
        "completion_tokens": outcome.completion_tokens,
        "total_tokens": outcome.prompt_tokens + outcome.completion_tokens,
    }


async def _sse(
    outcome: ChatOutcome, completion_id: str, created: int, model: str, include_usage: bool = False
) -> AsyncIterator[bytes]:
    def chunk(delta: dict, finish: str | None) -> bytes:
        data = {"id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}  # fmt: skip
        return f"data: {json.dumps(data, ensure_ascii=False)}\n\n".encode()

    yield chunk({"role": "assistant"}, None)
    for i in range(0, len(outcome.content), 256):
        yield chunk({"content": outcome.content[i : i + 256]}, None)
    yield chunk({}, "stop")
    if include_usage:  # OpenAI stream_options.include_usage: one final chunk with empty choices
        usage = {"id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
                 "choices": [], "usage": _usage(outcome)}  # fmt: skip
        yield f"data: {json.dumps(usage)}\n\n".encode()
    yield b"data: [DONE]\n\n"
