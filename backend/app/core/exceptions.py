"""Custom Application and Security Exceptions (커스텀 예외 및 보안 에러 처리 모듈).

이 모듈은 가드레일 차단, BOLA(IDOR) 권한 침해, 리소스 미존재, 외부 연동 실패 등
시스템에서 발생하는 모든 오류 상황을 일관된 HTTP 상태 코드와 구조화된 메시지로 정의합니다.
"""

from typing import Any


class AppBaseException(Exception):
    """애플리케이션 내 모든 커스텀 예외의 기본(Base) 부모 클래스입니다.

    Attributes:
        message (str): 사용자/클라이언트에게 전달할 에러 설명 문구
        status_code (int): 반환할 HTTP 상태 코드 (기본값: 400 Bad Request)
        details (Any): 디버깅 및 감사 로깅을 위한 세부 메타데이터 딕셔너리
    """

    def __init__(self, message: str, status_code: int = 400, details: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details


class GuardrailBlockException(AppBaseException):
    """입력(Input) 또는 출력(Output) 가드레일에서 보안 위협이 감지되어 요청이 차단되었을 때 발생합니다.

    - HTTP 상태 코드: 403 Forbidden (접근 거부)
    - 발생 시점: 프롬프트 인젝션, 탈옥 시도, 대외비 정보 조회 시그니처 감지 시

    Attributes:
        reason (str): 차단 사유 (예: 'Rule INJ-001 match')
        threat_type (str): 탐지된 위협 유형 (예: 'PROMPT_INJECTION')
        rule_id (str): 트리거된 보안 룰 ID (예: 'INJ-001')
    """

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
    """BOLA (Broken Object Level Authorization / IDOR) 권한 위반 시 발생합니다.

    - HTTP 상태 코드: 403 Forbidden
    - 발생 시점: 고객 A(cust_101)가 고객 B(cust_102)의 주문 번호(ORD-2026-002)를 조회하거나 취소하려고 시도할 때
    """

    def __init__(self, message: str = "접근 권한이 없는 리소스에 대한 요청입니다.") -> None:
        super().__init__(
            message=message,
            status_code=403,
            details={"threat_type": "BOLA_IDOR_VIOLATION"},
        )


class ResourceNotFoundException(AppBaseException):
    """조회하고자 하는 상품, 주문 번호, 쿠폰 등이 데이터베이스에 존재하지 않을 때 발생합니다.

    - HTTP 상태 코드: 404 Not Found
    """

    def __init__(self, message: str = "요청하신 리소스를 찾을 수 없습니다.") -> None:
        super().__init__(message=message, status_code=404)


class ExternalServiceException(AppBaseException):
    """외부 종속성 서비스(예: Ollama 로컬 LLM 엔드포인트) 호출 실패 또는 타임아웃 발생 시 사용됩니다.

    - HTTP 상태 코드: 502 Bad Gateway
    """

    def __init__(self, message: str = "외부 AI 서비스 연결에 실패했습니다.") -> None:
        super().__init__(message=message, status_code=502)
