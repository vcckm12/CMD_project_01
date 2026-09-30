"""Common Schemas and Base Models."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """System health check response model."""

    status: str = Field(default="healthy", description="Overall health status")
    version: str = Field(default="1.0.0", description="Application version")
    components: dict[str, str] = Field(
        default_factory=lambda: {
            "database": "connected",
            "guardrails": "active",
            "slm_runtime": "ready",
        }
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ErrorResponse(BaseModel):
    """Standard error response model."""

    success: bool = False
    message: str
    error_code: str = "GENERIC_ERROR"
    details: Any = None
