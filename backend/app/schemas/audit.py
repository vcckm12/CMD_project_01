"""Audit Log Schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class AuditLogCreate(BaseModel):
    """Payload to record a new security audit event."""

    event_id: UUID
    client_ip: str
    stage: str
    threat_type: str
    rule_id: str | None = None
    payload_hash: str
    payload_snippet: str | None = None
    action_taken: str
    execution_time_ms: float


class AuditLogResponse(BaseModel):
    """Security audit log response."""

    id: int
    event_id: UUID
    timestamp: datetime
    client_ip: str
    stage: str
    threat_type: str
    rule_id: str | None
    payload_hash: str
    payload_snippet: str | None
    action_taken: str
    execution_time_ms: float


class AuditLogListResponse(BaseModel):
    """Paginated list of audit logs."""

    total: int
    logs: list[AuditLogResponse]
