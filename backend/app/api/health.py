"""HEALTH-01/02 (DES-005 §2.4). Readiness grows as components are added (ruleset, model, outbox)."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.security.auth import require_staff

router = APIRouter(prefix="/api/v1/health", tags=["health"])


@router.get("/live")
async def live() -> dict[str, str]:
    return {"status": "alive"}


@router.get("/ready")
async def ready(request: Request) -> JSONResponse:
    # Internal monitors call without an edge channel; through an edge it requires operator/admin.
    if request.state.channel is not None:
        await require_staff(request)
    settings = request.app.state.settings
    cache = request.app.state.rule_cache
    checks = {
        "guardrail_enforced": settings.app_env == "lab" or settings.guardrail_enforced,
        "database": False,
        "ruleset_loaded": cache.current() is not None,
        "ruleset_consistent": cache.consistent,
    }
    try:
        async with request.app.state.pools.auth.connection(timeout=2) as conn:
            await conn.execute("SELECT 1")
        checks["database"] = True
    except Exception:  # noqa: BLE001 - readiness reports, never raises
        checks["database"] = False
    is_ready = all(checks.values())
    return JSONResponse(
        {
            "request_id": request.state.request_id,
            "data": {"status": "ready" if is_ready else "not_ready", "checks": checks},
        },
        status_code=200 if is_ready else 503,
    )
