"""Security Audit Logs API Router."""

from fastapi import APIRouter, Query

from app.repositories.audit_dao import audit_dao
from app.schemas.audit import AuditLogListResponse

router = APIRouter(prefix="/audit/logs", tags=["Audit Logs"])


@router.get("", response_model=AuditLogListResponse)
async def get_audit_logs(
    limit: int = Query(default=50, ge=1, le=500),
    threat_type: str | None = Query(default=None),
    stage: str | None = Query(default=None),
) -> AuditLogListResponse:
    """Query recorded security audit logs."""
    logs = await audit_dao.get_logs(limit=limit, threat_type=threat_type, stage=stage)
    total = await audit_dao.get_total_count()
    return AuditLogListResponse(total=total, logs=logs)
