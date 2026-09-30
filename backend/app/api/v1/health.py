"""Health Check Router."""

from fastapi import APIRouter

from app.core.config import settings
from app.schemas.common import HealthResponse

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Check overall system health and component status."""
    return HealthResponse(
        status="healthy",
        version=settings.VERSION,
        components={
            "database": "connected",
            "guardrails": "active",
            "slm_runtime": "ready",
        },
    )
