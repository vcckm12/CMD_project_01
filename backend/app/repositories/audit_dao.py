"""보안 감사 로그(Security Audit Log) 관리 DAO 모듈.

[개념 설명: 보안 감사 로그(Audit Log)란?]
누군가 시스템에 접속하여 정상 대화를 나누었는지, 혹은 악의적인 프롬프트 인젝션이나
타인의 주문을 탈취하려는 BOLA 공격을 시도하다 차단되었는지를 1건도 빠짐없이 기록하는 보안 원장(Audit Trail)입니다.
보안 사고 발생 시 사후 추적(Forensics)과 실시간 관제 대시보드(Admin UI)의 통계 분석에 필수적입니다.
"""

import asyncio
from datetime import UTC, datetime

from app.core.logging import logger
from app.schemas.audit import AuditLogCreate, AuditLogResponse


class AuditDAO:
    """보안 감사 이벤트 로그를 기록하고 필터링 조회하는 DAO 클래스."""

    def __init__(self) -> None:
        # 비동기 동시 로깅 시 ID 증가 및 리스트 추가의 안전성을 위한 Lock
        self._lock = asyncio.Lock()

        # 감사 로그 인메모리 저장소
        self._logs: list[dict] = []
        self._next_id = 1

    async def log_event(self, log_in: AuditLogCreate) -> AuditLogResponse:
        """가드레일 검사 단계(Input, Execution, Output, Judge)에서 발생한 보안 이벤트를 기록합니다.

        - timestamp: UTC 기준 현재 시각 자동 기록
        - logger.info: 콘솔 및 파일 로그에도 표준 감사 형식으로 출력
        """
        async with self._lock:
            log_dict = log_in.model_dump()
            log_dict["id"] = self._next_id
            self._next_id += 1
            log_dict["timestamp"] = datetime.now(UTC)
            self._logs.append(log_dict)

            logger.info(
                f"보안 감사 이벤트 [{log_in.stage}] - 위협 유형: {log_in.threat_type} | 조치: {log_in.action_taken} | 클라이언트 IP: {log_in.client_ip}"
            )
            return AuditLogResponse(**log_dict)

    async def get_logs(
        self,
        limit: int = 50,
        threat_type: str | None = None,
        stage: str | None = None,
    ) -> list[AuditLogResponse]:
        """필터 조건(위협 유형, 검사 단계)에 맞는 감사 로그를 최신순으로 조회합니다."""
        async with self._lock:
            filtered = self._logs
            if threat_type:
                filtered = [r for r in filtered if r["threat_type"] == threat_type]
            if stage:
                filtered = [r for r in filtered if r["stage"] == stage]

            # 최신 로그가 먼저 보이도록 역순 정렬 후 limit 개수만큼 슬라이싱
            sliced = list(reversed(filtered))[:limit]
            return [AuditLogResponse(**r) for r in sliced]

    async def get_total_count(self) -> int:
        """전체 누적 기록된 보안 감사 로그 건수 반환."""
        async with self._lock:
            return len(self._logs)


# 싱글톤 인스턴스 생성
audit_dao = AuditDAO()

