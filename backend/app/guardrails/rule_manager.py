"""인메모리 보안 규칙 캐시 및 무중단 핫 리로드(Hot-Reload) 관리자 모듈.

[왜 이 모듈이 필요한가?]
보안 위협(Jailbreak, Prompt Injection, 정보 탈출 등)을 차단할 때 매 요청마다
데이터베이스(DB/DAO)를 직접 조회하면 I/O 지연이 발생하여 시스템 응답 속도가 느려집니다.
따라서, 활성화된 모든 보안 규칙(Regex 정규식 등)을 'RAM(인메모리)'에 상주시키고,
정규식을 미리 컴파일(Pre-compile)해 두어 서브 밀리초(sub-millisecond) 단위로 초고속 탐지하도록 합니다.
또한, 관리자가 웹 UI에서 규칙을 추가/수정했을 때 서버를 재시작하지 않고도
실시간으로 메모리에 즉시 반영하는 '핫 리로드(Hot-Reload)' 기능을 제공합니다.
"""

import asyncio
import contextlib
import re

from app.core.logging import logger
from app.repositories.threat_dao import threat_dao
from app.schemas.guardrails import RuleResponseSchema


class RuleManager:
    """스레드 안전(Thread-Safe) 인메모리 위협 탐지 규칙 캐시 매니저 클래스.

    - Input/Output/Execution 카테고리별 규칙 분리 저장
    - 정규식(Regex) 사전 컴파일 맵 유지로 탐지 속도 극대화
    - asyncio.Lock()을 통한 동시성 안전 보장 (경쟁 상태 방지)
    """

    def __init__(self) -> None:
        # 비동기 동시 접근 제어를 위한 Lock 객체 (핫 리로드 중 다른 요청과의 충돌 방지)
        self._lock = asyncio.Lock()

        # 카테고리별 활성 규칙 목록 (입력 검사, 출력 검사, 실행 권한 검사)
        self._input_rules: list[RuleResponseSchema] = []
        self._output_rules: list[RuleResponseSchema] = []
        self._execution_rules: list[RuleResponseSchema] = []

        # 미리 컴파일된 정규식 패턴 캐시 { "RULE_ID": Pattern객체 }
        # re.compile()을 매번 호출하지 않고 미리 컴파일해두면 정규식 매칭 속도가 수십 배 향상됩니다.
        self._compiled_regexes: dict[str, re.Pattern] = {}

        # 초기화 완료 플래그
        self._initialized = False

        # 서버 기동 시 초기 시드(기본) 규칙들을 동기식으로 먼저 로딩하여 공백 기간(규칙 없는 틈)을 방지
        self._sync_load_seed_rules()

    def _sync_load_seed_rules(self) -> None:
        """서버 시작 시 메모리에 즉시 기본 시드 규칙들을 동기식으로 로드합니다."""
        # threat_dao에 등록된 활성화(is_active=True) 규칙들만 선별
        all_rules = [
            RuleResponseSchema(**r) for r in threat_dao._rules_store.values() if r.get("is_active", True)
        ]

        # 카테고리별로 규칙 분류 (대소문자 무관하게 처리)
        self._input_rules = [r for r in all_rules if r.category.upper() == "INPUT"]
        self._output_rules = [r for r in all_rules if r.category.upper() == "OUTPUT"]
        self._execution_rules = [r for r in all_rules if r.category.upper() == "EXECUTION"]

        # 정규표현식(REGEX) 타입의 규칙들을 대소문자 무시(re.IGNORECASE) 옵션으로 사전 컴파일
        for r in all_rules:
            if r.pattern_type.upper() == "REGEX":
                with contextlib.suppress(re.error):
                    self._compiled_regexes[r.rule_id] = re.compile(r.pattern_value, re.IGNORECASE)

    async def initialize(self) -> None:
        """비동기 수명주기(Lifespan) 시작 시 호출되는 초기화 메서드."""
        await self.reload_rules()
        self._initialized = True

    async def reload_rules(self) -> int:
        """데이터베이스(DAO)로부터 모든 최신 활성 규칙을 다시 읽어와 인메모리 캐시를 갱신(Hot-Reload)합니다.

        운영 중에 새로운 공격 패턴을 차단하는 규칙을 추가했을 때,
        이 메서드를 호출하면 서버 무중단으로 즉시 방어 능력이 업데이트됩니다.
        """
        async with self._lock:
            # 1. DAO에서 현재 활성화된 모든 규칙 조회
            all_rules = await threat_dao.get_all_rules(active_only=True)

            # 2. 카테고리별로 분류하여 메모리 변수 교체
            self._input_rules = [r for r in all_rules if r.category.upper() == "INPUT"]
            self._output_rules = [r for r in all_rules if r.category.upper() == "OUTPUT"]
            self._execution_rules = [r for r in all_rules if r.category.upper() == "EXECUTION"]

            # 3. 새로운 정규식 패턴 맵 생성 및 컴파일
            new_regexes: dict[str, re.Pattern] = {}
            for r in all_rules:
                if r.pattern_type.upper() == "REGEX":
                    try:
                        new_regexes[r.rule_id] = re.compile(r.pattern_value, re.IGNORECASE)
                    except re.error as err:
                        logger.error(f"규칙 {r.rule_id}의 정규식 컴파일 실패 (문법 오류): {err}")

            # 4. 컴파일 맵 원자적(Atomic) 교체
            self._compiled_regexes = new_regexes
            total = len(all_rules)
            logger.info(
                f"RuleCacheManager: 핫 리로드 완료 - 총 {total}개 규칙 로드 (입력 규칙: {len(self._input_rules)}개, 출력 규칙: {len(self._output_rules)}개)"
            )
            return total

    def get_input_rules(self) -> list[RuleResponseSchema]:
        """캐시된 활성 입력 검사(Input) 규칙 목록 반환."""
        return self._input_rules

    def get_output_rules(self) -> list[RuleResponseSchema]:
        """캐시된 활성 출력 검사(Output) 규칙 목록 반환."""
        return self._output_rules

    def get_compiled_regex(self, rule_id: str) -> re.Pattern | None:
        """특정 규칙 ID에 대해 미리 컴파일된 정규식 객체 반환 (미존재 시 None)."""
        return self._compiled_regexes.get(rule_id)


# 싱글톤 인스턴스 (앱 전체에서 동일한 캐시 객체를 공유하여 사용)
rule_manager = RuleManager()

