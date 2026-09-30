"""Guardrail Rule Management Schemas."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class RuleBaseSchema(BaseModel):
    """Base fields for guardrail rule."""

    rule_id: str = Field(..., min_length=2, max_length=64)
    category: str = Field(..., description="'INPUT', 'OUTPUT', 'EXECUTION'")
    pattern_type: str = Field(..., description="'KEYWORD', 'REGEX', 'HOMOGLYPH', 'SEMANTIC'")
    pattern_value: str = Field(..., min_length=1)
    action: str = Field(default="BLOCK", description="'BLOCK', 'REDACT', 'ALERT'")
    severity: str = Field(default="HIGH", description="'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'")
    is_active: bool = Field(default=True)
    description: str | None = None


class RuleCreateSchema(RuleBaseSchema):
    """Schema for registering a new rule."""

    pass


class RuleUpdateSchema(BaseModel):
    """Schema for updating an existing rule."""

    pattern_type: str | None = None
    pattern_value: str | None = None
    action: str | None = None
    severity: str | None = None
    is_active: bool | None = None
    description: str | None = None


class RuleResponseSchema(RuleBaseSchema):
    """Schema for returning rule data."""

    id: int
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
