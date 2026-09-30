"""Security Audit Log DAO."""

import asyncio
from datetime import UTC, datetime

from app.core.logging import logger
from app.schemas.audit import AuditLogCreate, AuditLogResponse


class AuditDAO:
    """DAO for recording and querying security audit logs."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._logs: list[dict] = []
        self._next_id = 1

    async def log_event(self, log_in: AuditLogCreate) -> AuditLogResponse:
        """Insert a security audit event."""
        async with self._lock:
            log_dict = log_in.model_dump()
            log_dict["id"] = self._next_id
            self._next_id += 1
            log_dict["timestamp"] = datetime.now(UTC)
            self._logs.append(log_dict)
            logger.info(
                f"AUDIT EVENT [{log_in.stage}] - Threat: {log_in.threat_type} | Action: {log_in.action_taken} | IP: {log_in.client_ip}"
            )
            return AuditLogResponse(**log_dict)

    async def get_logs(
        self,
        limit: int = 50,
        threat_type: str | None = None,
        stage: str | None = None,
    ) -> list[AuditLogResponse]:
        """Fetch audit logs with optional filters."""
        async with self._lock:
            filtered = self._logs
            if threat_type:
                filtered = [r for r in filtered if r["threat_type"] == threat_type]
            if stage:
                filtered = [r for r in filtered if r["stage"] == stage]

            # Return recent logs first
            sliced = list(reversed(filtered))[:limit]
            return [AuditLogResponse(**r) for r in sliced]

    async def get_total_count(self) -> int:
        """Get total number of audit logs."""
        async with self._lock:
            return len(self._logs)


audit_dao = AuditDAO()
