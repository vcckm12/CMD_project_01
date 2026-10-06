"""AUDIT-01~04 and ops alerts (DES-005 §2.4, D-26). ops channel + operator/admin only.

Reads go through the audit_reader pool, which cannot see commerce data or outbox payloads. Lists are
keyset-paginated with an HMAC-signed cursor. Report downloads and alert acknowledgements are audited.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response

from app.api.auth import ok
from app.audit.outbox import AuditEnvelope, persist_event
from app.audit.report import build_report_pdf
from app.errors import ApiError
from app.guardrails.rule_descriptions import describe
from app.security.auth import AuthContext, require_staff

router = APIRouter(prefix="/api/v1", tags=["ops"])
MAX_RANGE = timedelta(days=90)
MAX_REPORT_RANGE = timedelta(days=31)
MAX_REPORT_EVENTS = 10_000


async def ops_staff(request: Request) -> AuthContext:
    # Outside the ops channel these APIs do not exist (D-17); inside, operator/admin only.
    if request.state.channel != "ops":
        raise ApiError(404, "NOT_FOUND")
    return await require_staff(request)


Staff = Annotated[AuthContext, Depends(ops_staff)]


def _range(start: datetime | None, end: datetime | None, limit: timedelta) -> tuple[datetime, datetime]:
    end = end or datetime.now(UTC)
    start = start or end - timedelta(hours=24)
    if start.tzinfo is None or end.tzinfo is None or start >= end or end - start > limit:
        raise ApiError(422, "VALIDATION_ERROR")
    return start, end


def _cursor_key(request: Request) -> bytes:
    return hashlib.sha256(b"audit-cursor:" + request.app.state.settings.input_fingerprint_key.encode()).digest()


def encode_cursor(request: Request, occurred_at: datetime, event_id: uuid.UUID) -> str:
    raw = json.dumps({"t": occurred_at.isoformat(), "id": str(event_id)}, separators=(",", ":")).encode()
    sig = hmac.new(_cursor_key(request), raw, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(raw).decode().rstrip("=") + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")


def decode_cursor(request: Request, cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        body, sig = cursor.split(".")
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        given = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        expected = hmac.new(_cursor_key(request), raw, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(given, expected):
            raise ValueError
        data = json.loads(raw)
        return datetime.fromisoformat(data["t"]), uuid.UUID(data["id"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ApiError(422, "VALIDATION_ERROR") from exc


def _event_view(row: dict) -> dict:
    return {
        "event_id": str(row["event_id"]),
        "request_id": str(row["request_id"]),
        "actor_id": str(row["actor_id"]) if row["actor_id"] else None,
        "session_id": str(row["session_id"]) if row["session_id"] else None,
        "source": row["source"],
        "api_path": row["api_path"],
        "model": row["model"],
        "status": row["status"],
        "stage": row["stage"],
        "ruleset_version": str(row["ruleset_version"]) if row["ruleset_version"] else None,
        "input_chars": row["input_chars"],
        "output_chars": row["output_chars"],
        "input_ms": float(row["input_ms"]),
        "output_ms": float(row["output_ms"]),
        "total_ms": float(row["total_ms"]),
        "summary_redacted": row["summary_redacted"],
        "occurred_at": row["occurred_at"].isoformat(),
    }


async def _filters(start, end, status, stage, session_id) -> tuple[str, list]:
    where = ["occurred_at >= %s", "occurred_at < %s"]
    params: list = [start, end]
    for column, value in (("status", status), ("stage", stage), ("session_id", session_id)):
        if value is not None:
            where.append(f"{column} = %s")
            params.append(value)
    return " AND ".join(where), params


Status = Literal["success", "blocked", "masked", "confirmation_required", "error"]
Stage = Literal["input", "execution", "output", "policy"]


@router.get("/audit/events")
async def list_events(
    request: Request,
    ctx: Staff,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    status: Status | None = None,
    stage: Stage | None = None,
    session_id: uuid.UUID | None = None,
    cursor: Annotated[str | None, Query(max_length=400)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> JSONResponse:
    start, end = _range(start, end, MAX_RANGE)
    where, params = await _filters(start, end, status, stage, session_id)
    if cursor:
        t, eid = decode_cursor(request, cursor)
        where += " AND (occurred_at, event_id) < (%s, %s)"
        params += [t, eid]
    async with request.app.state.pools.audit.connection() as conn:
        rows = await (
            await conn.execute(
                f"SELECT * FROM audit.events WHERE {where} ORDER BY occurred_at DESC, event_id DESC LIMIT %s",  # noqa: S608 - fixed clauses
                (*params, limit + 1),
            )
        ).fetchall()
    more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = encode_cursor(request, rows[-1]["occurred_at"], rows[-1]["event_id"]) if more else None
    return ok(request, {"items": [_event_view(r) for r in rows], "next_cursor": next_cursor})


@router.get("/audit/events/{event_id}")
async def get_event(request: Request, event_id: uuid.UUID, ctx: Staff) -> JSONResponse:
    async with request.app.state.pools.audit.connection() as conn:
        row = await (await conn.execute("SELECT * FROM audit.events WHERE event_id = %s", (event_id,))).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND")
        hits = await (
            await conn.execute(
                "SELECT rule_id, category, stage, action, match_count FROM audit.rule_hits WHERE event_id = %s"
                " ORDER BY rule_id",
                (event_id,),
            )
        ).fetchall()
        tools = await (
            await conn.execute(
                "SELECT tool_name, outcome, target_id, action_id, duration_ms FROM audit.tool_executions"
                " WHERE event_id = %s ORDER BY tool_name",
                (event_id,),
            )
        ).fetchall()
    return ok(
        request,
        {
            **_event_view(row),
            "rule_hits": [{**h, "description": describe(h["rule_id"], h["category"])} for h in hits],
            "tool_executions": [
                {
                    **t,
                    "target_id": str(t["target_id"]) if t["target_id"] else None,
                    "action_id": str(t["action_id"]) if t["action_id"] else None,
                    "duration_ms": float(t["duration_ms"]),
                }
                for t in tools
            ],  # fmt: skip
        },
    )


async def compute_stats(conn, start: datetime, end: datetime, session_id: uuid.UUID | None) -> dict:
    where, params = await _filters(start, end, None, None, session_id)
    totals = await (
        await conn.execute(
            f"SELECT status, count(*) AS n FROM audit.events WHERE {where} GROUP BY status",  # noqa: S608
            params,
        )
    ).fetchall()
    categories = await (
        await conn.execute(
            "SELECT h.category, sum(h.match_count) AS n FROM audit.rule_hits h JOIN audit.events e USING (event_id)"
            f" WHERE {where.replace('occurred_at', 'e.occurred_at').replace('session_id', 'e.session_id')}"  # noqa: S608
            " GROUP BY h.category ORDER BY h.category",
            params,
        )
    ).fetchall()
    p95 = await (
        await conn.execute(
            f"SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY total_ms) AS p95 FROM audit.events WHERE {where}",  # noqa: S608
            params,
        )
    ).fetchone()
    versions = await (
        await conn.execute(
            "SELECT DISTINCT e.ruleset_version AS id, r.version_label FROM audit.events e"
            " LEFT JOIN threat_intel.rulesets r ON r.id = e.ruleset_version"
            f" WHERE {where.replace('occurred_at', 'e.occurred_at').replace('session_id', 'e.session_id')}"  # noqa: S608
            " AND e.ruleset_version IS NOT NULL",
            params,
        )
    ).fetchall()
    lag = await (
        await conn.execute(
            "SELECT coalesce(extract(epoch FROM now() - min(created_at)), 0) AS lag, now() AS as_of"
            " FROM audit.outbox WHERE delivery_state = 'pending'"
        )
    ).fetchone()
    status_counts = {s: 0 for s in ("success", "blocked", "masked", "confirmation_required", "error")}
    status_counts.update({r["status"]: r["n"] for r in totals})
    return {
        "from": start.isoformat(),
        "to": end.isoformat(),
        "total": sum(status_counts.values()),
        "status_counts": status_counts,
        # Units differ on purpose: one event can match several rules (DES-005 §2.4).
        "category_counts": {r["category"]: int(r["n"]) for r in categories},
        "latency_p95_ms": float(p95["p95"]) if p95["p95"] is not None else None,
        "ruleset_versions": [{"id": str(v["id"]), "label": v["version_label"]} for v in versions],
        "as_of": lag["as_of"].isoformat(),
        "ingestion_lag_seconds": round(float(lag["lag"]), 1),
    }


@router.get("/audit/stats")
async def stats(
    request: Request,
    ctx: Staff,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    session_id: uuid.UUID | None = None,
) -> JSONResponse:
    start, end = _range(start, end, MAX_RANGE)
    async with request.app.state.pools.audit.connection() as conn:
        return ok(request, await compute_stats(conn, start, end, session_id))


async def _record(request: Request, ctx: AuthContext, summary: str) -> None:
    async with request.app.state.pools.auth.connection() as conn, conn.transaction():
        await persist_event(
            conn,
            AuditEnvelope(
                request_id=uuid.UUID(request.state.request_id), actor_id=ctx.user_id, source=ctx.source,
                api_path=request.url.path, status="success", summary_redacted=summary,
            ),
        )  # fmt: skip


@router.get("/audit/report")
async def report(
    request: Request,
    ctx: Staff,
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    session_id: uuid.UUID | None = None,
    format: Literal["pdf"] = "pdf",  # noqa: A002 - public query parameter name (DES-005 AUDIT-04)
) -> Response:
    start, end = _range(start, end, MAX_REPORT_RANGE)
    where, params = await _filters(start, end, None, None, session_id)
    async with request.app.state.pools.audit.connection() as conn:
        count = (
            await (await conn.execute(f"SELECT count(*) AS n FROM audit.events WHERE {where}", params)).fetchone()  # noqa: S608
        )["n"]
        if count > MAX_REPORT_EVENTS:
            raise ApiError(422, "REPORT_TOO_LARGE")
        summary = await compute_stats(conn, start, end, session_id)
        rows = await (
            await conn.execute(
                "SELECT occurred_at, source, status, stage, total_ms, summary_redacted FROM audit.events"
                f" WHERE {where} ORDER BY occurred_at DESC LIMIT 500",  # noqa: S608
                params,
            )
        ).fetchall()
    pdf = build_report_pdf(summary, rows, session_id=session_id, author_id=ctx.user_id, total_events=count)
    await _record(request, ctx, f"보고서 다운로드: {count}건")
    filename = f"security-report-{datetime.now(UTC).astimezone().strftime('%Y%m%d')}.pdf"
    return Response(
        pdf,
        media_type="application/pdf",
        # Cache-Control: no-store is added by the request middleware for every response.
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/alerts")
async def list_alerts(request: Request, ctx: Staff, state: Literal["open", "acknowledged"] = "open") -> JSONResponse:
    async with request.app.state.pools.audit.connection() as conn:
        rows = await (
            await conn.execute(
                "SELECT id, kind, severity, fingerprint, detail, occurrences, first_seen_at, last_seen_at, state,"
                " acknowledged_by, acknowledged_at FROM audit.alerts WHERE state = %s"
                " ORDER BY last_seen_at DESC LIMIT 200",
                (state,),
            )
        ).fetchall()
    items = [
        {**r, "id": str(r["id"]), "fingerprint": (r["fingerprint"] or "")[:12] or None,
         "first_seen_at": r["first_seen_at"].isoformat(), "last_seen_at": r["last_seen_at"].isoformat(),
         "acknowledged_by": str(r["acknowledged_by"]) if r["acknowledged_by"] else None,
         "acknowledged_at": r["acknowledged_at"].isoformat() if r["acknowledged_at"] else None}
        for r in rows
    ]  # fmt: skip
    return ok(request, {"items": items, "next_cursor": None})


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge(request: Request, alert_id: uuid.UUID, ctx: Staff) -> JSONResponse:
    async with request.app.state.pools.audit.connection() as conn:
        row = await (
            await conn.execute(
                "UPDATE audit.alerts SET state = 'acknowledged', acknowledged_by = %s, acknowledged_at = now()"
                " WHERE id = %s AND state = 'open' RETURNING id",
                (ctx.user_id, alert_id),
            )
        ).fetchone()
    if row is None:
        raise ApiError(404, "NOT_FOUND")
    await _record(request, ctx, "경보 확인 처리")
    return ok(request, {"id": str(alert_id), "state": "acknowledged"})
