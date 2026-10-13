"""LAB-01~03 (D-21): ON/OFF A/B runs. This router is included only when APP_ENV=lab."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.api.auth import ok
from app.api.rulesets import _record, ops_admin
from app.errors import ApiError
from app.guardrails import rule_store
from app.lab.suggest import next_rule_id
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


# ------------------------------------------------------------------ LAB-06 regex rule suggestions (D-46)


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    accept: bool


AI_ONLY_BLOCKS = (
    "SELECT event_id, occurred_at FROM audit.events WHERE status = 'blocked' AND stage = 'input'"
    " AND layers->'input_rules'->>'verdict' = 'pass' AND layers->'input_judge'->>'verdict' = 'block'"
    " AND occurred_at > now() - interval '7 days' ORDER BY occurred_at DESC LIMIT 50"
)


async def _collecting_draft(conn) -> dict | None:
    return await (
        await conn.execute(
            "SELECT id, version_label FROM threat_intel.rulesets WHERE state = 'draft'"
            " AND version_label LIKE 'lab-suggest-%' ORDER BY created_at DESC LIMIT 1"
        )
    ).fetchone()


@router.get("/rule-suggestions")
async def rule_suggestions(request: Request, ctx: Admin) -> JSONResponse:
    """Inputs the rules passed but the AI judge blocked, with their text (lab memory) and suggestion state."""
    state = request.app.state
    async with state.pools.audit.connection() as conn:
        rows = await (await conn.execute(AI_ONLY_BLOCKS)).fetchall()
    items = []
    for row in rows:
        event_id = str(row["event_id"])
        text = state.lab_inputs.last_user_text(event_id)
        if text is None:
            continue  # kept only in memory: gone after an API restart
        found = state.rule_suggester.items.get(event_id)
        items.append({"event_id": event_id, "occurred_at": row["occurred_at"].isoformat(), "text": text,
                      "suggestion": found.view() if found else None})  # fmt: skip
    async with state.pools.rules.connection() as conn:
        draft = await _collecting_draft(conn)
        count = 0
        if draft:
            query = "SELECT count(*) AS n FROM threat_intel.rules WHERE ruleset_id = %s AND rule_id LIKE %s"
            count = (await (await conn.execute(query, (draft["id"], "RULE_LAB_SUGGEST_%"))).fetchone())["n"]
    collecting = {"id": str(draft["id"]), "label": draft["version_label"], "added": count} if draft else None
    return ok(request, {"items": items, "draft": collecting})


@router.post("/rule-suggestions/{event_id}/generate")
async def generate_suggestion(request: Request, event_id: uuid.UUID, ctx: Admin) -> JSONResponse:
    text = request.app.state.lab_inputs.last_user_text(str(event_id))
    if text is None:
        raise ApiError(404, "NOT_FOUND")
    suggestion = await request.app.state.rule_suggester.generate(str(event_id), text)
    return ok(request, suggestion.view())


@router.post("/rule-suggestions/{event_id}/decision")
async def decide_suggestion(request: Request, event_id: uuid.UUID, body: Decision, ctx: Admin) -> JSONResponse:
    """YES adds the rule to the collecting draft ruleset (created from the active one when needed); NO drops it.
    Publishing stays on the rules page with password re-confirmation."""
    suggestion = request.app.state.rule_suggester.items.get(str(event_id))
    if suggestion is None or suggestion.state != "pending":
        raise ApiError(409, "RULESET_CONFLICT")
    if not body.accept:
        suggestion.state = "rejected"
        return ok(request, suggestion.view())
    async with request.app.state.pools.rules.connection() as conn, conn.transaction():
        draft = await _collecting_draft(conn)
        if draft is None:
            active = await rule_store.active_id(conn)
            policy = (await (await conn.execute("SELECT policy FROM threat_intel.rulesets WHERE id = %s",
                                                (active,))).fetchone())["policy"]  # fmt: skip
            label = f"lab-suggest-{datetime.now(UTC):%Y%m%d%H%M%S}"
            draft_id = await rule_store.create_draft(conn, label=label, actor_id=ctx.user_id,
                                                     rules=await rule_store._rules(conn, active), policy=policy,
                                                     parent_id=active)  # fmt: skip
            draft = {"id": draft_id, "version_label": label}
        existing = [r["rule_id"] for r in await (await conn.execute(
            "SELECT rule_id FROM threat_intel.rules WHERE ruleset_id = %s", (draft["id"],))).fetchall()]  # fmt: skip
        rule_id = next_rule_id(existing)
        await conn.execute(
            f"INSERT INTO threat_intel.rules (ruleset_id, {rule_store.RULE_COLUMNS})"  # noqa: S608 - constant columns
            " VALUES (%s, %s, 'input', %s, 'regex', %s, 'i', 'block', NULL, 80)",
            (draft["id"], rule_id, suggestion.category, suggestion.pattern),
        )
        await _record(conn, request, ctx, f"LAB 정규식 제안 채택: {rule_id}", draft["id"])
    suggestion.state, suggestion.rule_id, suggestion.draft_label = "accepted", rule_id, draft["version_label"]
    return ok(request, suggestion.view())
