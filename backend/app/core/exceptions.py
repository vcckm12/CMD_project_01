"""Custom Application and Security Exceptions."""

from typing import Any


class AppBaseException(Exception):
    """Base exception for all application errors."""

    def __init__(self, message: str, status_code: int = 400, details: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details


class GuardrailBlockException(AppBaseException):
    """Raised when Input or Output Guardrail blocks a request/response."""

    def __init__(
        self,
        reason: str,
        threat_type: str = "SECURITY_POLICY_VIOLATION",
        rule_id: str | None = None,
    ) -> None:
        super().__init__(
            message="🚨 [보안 정책 알림] 요청하신 내용에서 비정상적인 접근 또는 시스템 정책 위반 패턴이 감지되어 차단되었습니다.",
            status_code=403,
            details={"reason": reason, "threat_type": threat_type, "rule_id": rule_id},
        )
        self.reason = reason
        self.threat_type = threat_type
        self.rule_id = rule_id


class BOLAAuthorizationException(AppBaseException):
    """Raised when an unauthorized object access or IDOR attempt is detected."""

    def __init__(self, message: str = "접근 권한이 없는 리소스에 대한 요청입니다.") -> None:
        super().__init__(
            message=message,
            status_code=403,
            details={"threat_type": "BOLA_IDOR_VIOLATION"},
        )


class ResourceNotFoundException(AppBaseException):
    """Raised when a requested resource does not exist."""

    def __init__(self, message: str = "요청하신 리소스를 찾을 수 없습니다.") -> None:
        super().__init__(message=message, status_code=404)


class ExternalServiceException(AppBaseException):
    """Raised when an external service (e.g. Ollama runtime) fails."""

    def __init__(self, message: str = "외부 AI 서비스 연결에 실패했습니다.") -> None:
        super().__init__(message=message, status_code=502)
