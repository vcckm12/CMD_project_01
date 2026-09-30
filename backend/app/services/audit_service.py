"""Async Security Audit Logging Service."""

import uuid

from app.core.logging import logger
from app.core.security import compute_sha256
from app.repositories.audit_dao import audit_dao
from app.schemas.audit import AuditLogCreate


class AuditService:
    """Handles asynchronous audit logging of security events."""

    @staticmethod
    async def log_security_event(
        client_ip: str,
        stage: str,
        threat_type: str,
        raw_payload: str,
        action_taken: str,
        execution_time_ms: float,
        rule_id: str | None = None,
    ) -> None:
        """Asynchronously record security event to audit repository."""
        try:
            payload_hash = compute_sha256(raw_payload)
            # Truncate snippet safely
            snippet = raw_payload[:200] if raw_payload else ""

            event = AuditLogCreate(
                event_id=uuid.uuid4(),
                client_ip=client_ip,
                stage=stage,
                threat_type=threat_type,
                rule_id=rule_id,
                payload_hash=payload_hash,
                payload_snippet=snippet,
                action_taken=action_taken,
                execution_time_ms=execution_time_ms,
            )
            await audit_dao.log_event(event)
        except Exception as err:
            logger.error(f"Failed to record audit log: {err}")


audit_service = AuditService()
