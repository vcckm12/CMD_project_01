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


@router.get("/ab-runs/{run_id}")
async def get_run(request: Request, run_id: uuid.UUID, ctx: Admin) -> JSONResponse:
    run = request.app.state.lab.runs.get(str(run_id))
    if run is None:
        raise ApiError(404, "NOT_FOUND")
    return ok(request, run.view())
