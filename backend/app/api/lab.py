"""LAB-01~03 (D-21): ON/OFF A/B runs. This router is included only when APP_ENV=lab."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.api.auth import ok
from app.api.rulesets import ops_admin
from app.errors import ApiError
from app.security.auth import AuthContext

router = APIRouter(prefix="/api/v1/lab", tags=["lab"])
Admin = Annotated[AuthContext, Depends(ops_admin)]


class CompareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: uuid.UUID | None = None
    text: str | None = Field(default=None, min_length=1, max_length=8000)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset: str = Field(default="lab_ab_v1", pattern=r"^[a-z0-9_]{1,40}$")
    limit: int | None = Field(default=None, ge=1, le=200)


@router.get("/status")
async def status(request: Request, ctx: Admin) -> JSONResponse:
    return ok(
        request, {"app_env": "lab", "runs": [r.view() | {"results": None} for r in request.app.state.lab.runs.values()]}
    )


@router.post("/ab-runs", status_code=202)
async def start(request: Request, body: RunRequest, ctx: Admin) -> JSONResponse:
    try:
        run = request.app.state.lab.start(body.dataset, body.limit)
    except FileNotFoundError as exc:
        raise ApiError(404, "NOT_FOUND") from exc
    return ok(request, {"run_id": run.run_id, "total": run.total}, 202)


@router.post("/compare", status_code=202)
async def compare(request: Request, body: CompareRequest, ctx: Admin) -> JSONResponse:
    """LAB-05: one input (a lab event's user message, or free text) with the guardrail OFF and ON."""
    if (body.event_id is None) == (body.text is None):
        raise ApiError(422, "VALIDATION_ERROR")
    if body.event_id is not None:
        text = request.app.state.lab_inputs.last_user_text(str(body.event_id))
        if text is None:
            raise ApiError(404, "NOT_FOUND")
        source = f"event:{body.event_id}"
    else:
        text, source = body.text, "free"
    if not text.strip():
        raise ApiError(422, "VALIDATION_ERROR")
    run = request.app.state.lab.compare(text, source)
    return ok(request, {"run_id": run.run_id, "total": run.total}, 202)


@router.get("/inputs/{event_id}")
async def get_input(request: Request, event_id: uuid.UUID, ctx: Admin) -> JSONResponse:
    """The inspected messages of a lab chat request (kept in memory; 404 after restart)."""
    messages = request.app.state.lab_inputs.get(str(event_id))
    if messages is None:
        raise ApiError(404, "NOT_FOUND")
    return ok(request, {"event_id": str(event_id), "messages": messages})


@router.get("/ab-runs/{run_id}")
async def get_run(request: Request, run_id: uuid.UUID, ctx: Admin) -> JSONResponse:
    run = request.app.state.lab.runs.get(str(run_id))
    if run is None:
        raise ApiError(404, "NOT_FOUND")
    return ok(request, run.view())
