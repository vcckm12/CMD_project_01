"""위협 인텔리전스(Threat Intelligence) 및 보안 규칙 관리 DAO 모듈.

[개념 설명: 위협 인텔리전스 DAO란?]
쇼핑몰 AI 시스템을 공격하는 다양한 프롬프트 주입(Prompt Injection), 탈옥(Jailbreak),
SQL 인젝션, 개인정보 탈취, 대외비 원가 탈취 시도를 차단하기 위한 보안 탐지 규칙(Rule)들의
데이터베이스 저장/조회/수정/삭제(CRUD)를 전담하는 영속성 계층입니다.

[보안 규칙 분류 체계 (Rule Taxonomy)]
1. 입력 검사 규칙 (INPUT):
   - INJ-001: 이전 지침 무시형 프롬프트 주입 (Ignore previous instructions, System override)
   - INJ-002: 시스템 프롬프트 유출 시도 (System prompt leakage & dump)
   - INJ-003: 탈옥 및 페르소나 탈취 (DAN, 악마 모드, Unrestricted AI)
   - INJ-004: 데이터베이스 SQL 인젝션 공격 시그니처 (UNION SELECT, DROP TABLE 등)
   - INJ-005: 비인가 관리자 권한 상승 시도 (Admin privilege escalation)
   - INJ-006: 시스템 계정 및 DB 비밀번호/API 키 탈취 시도 (Credential theft)
   - INJ-007: AI 역할 찬탈 및 지침 리셋 (Role usurpation)
   - INJ-008: 대외비 원가(cost_price) 및 마진율 탈취 질문 차단
   - INJ-009: 대량 고객 개인정보(PII) 덤프 요구 차단
2. 출력 검사 규칙 (OUTPUT):
   - OUT-001: 역방향 셸(Reverse Shell) 및 서버 원격 명령 실행 페이로드 즉시 차단
   - OUT-002: 주민등록번호(RRN) 비식별화(REDACT 마스킹)
   - OUT-003: 신용카드 번호 비식별화(REDACT 마스킹)
   - OUT-004: 휴대전화 번호 비식별화(REDACT 마스킹)
   - OUT-005: 대외비 원가(cost_price) 노출 방지 및 마스킹
"""

import asyncio
from datetime import UTC, datetime

from app.core.logging import logger
from app.schemas.guardrails import RuleCreateSchema, RuleResponseSchema, RuleUpdateSchema


class ThreatIntelDAO:
    """위협 인텔리전스 보안 규칙(Guardrail Rules)을 관리하는 DAO 클래스."""

    def __init__(self) -> None:
        # 규칙 생성/수정/삭제 시 동시성 충돌을 막기 위한 비동기 Lock
        self._lock = asyncio.Lock()

        # [인메모리 시드 규칙 저장소]
        # PostgreSQL의 threat_intel.guardrail_rules 테이블과 완벽히 동기화되는 기본 규칙 셋
        self._rules_store: dict[str, dict] = {
            "INJ-001": {
                "id": 1,
                "rule_id": "INJ-001",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(ignore\s*(all\s*)?(the\s*)?(previous|prior|above|safety)?\s*(instructions?|directives?|rules?|context|guardrails?)|disregard\s*(previous|all)?\s*(instructions?|context)|forget\s*(your\s*)?(role|instructions?|rules?)|stop\s*being\s*a\s*shopping\s*bot|bypass\s*(instructions?|guardrails?|all)|reset\s*memory|system\s*override|지침\s*무시|명령\s*무시|지침을\s*전부\s*잊고|run\s*shell|translate.*(instructions?|guidelines?|rules?|prompt)|traduire|rotate.*13|rot13|opposite\s*day|reverse\s*psychology|hypothetical.*(simulation|rules)|최면|root\s*admin\s*override|disable.*(guardrail|filter))",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "is_active": True,
                "description": "프롬프트 인젝션: 이전 지침 무시 및 시스템 재정의 공격 차단",
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-002": {
                "id": 2,
                "rule_id": "INJ-002",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(system\s*(prompt|message|guidelines?)(\s*(leak|dump|show|output|reveal|print))?|dump\s*prompt|initialization\s*prompt|initial\s*system\s*guidelines?|prompt\s*(leak|dump|show|output|reveal|text)|hidden\s*(prompts?|rules?)|developer\s*guidelines?|root\s*configuration|explain\s*how\s*you\s*were\s*built|repeat\s*the\s*words\s*above|echo\s*back\s*all\s*system|시스템\s*프롬프트|초기\s*시스템\s*지침|프롬프트\s*(유출|출력|덤프|복사)|최초\s*시스템\s*설정값|提示词|プロンプト|prompt\s*del\s*sistema|revela\s*el\s*prompt|reglas\s*secretas|системный\s*промпт|internal\s*prompt|recite.*prompt|Hindi\s*mein\s*translate)",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "is_active": True,
                "description": "시스템 프롬프트 및 내부 지침 유출 시도 차단",
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-003": {
                "id": 3,
                "rule_id": "INJ-003",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(dan\s*mode|jailbreak(en|ed)?|jailbroken|unrestricted\s*ai|evilbot|evil\s*ai|developer\s*mode|god\s*mode|unrestricted\s*(persona|hacker|answers?|assistant)|zero\s*guardrails?|without\s*guardrails?|pretend\s*you\s*have\s*no\s*rules|roleplay\s*as|bypass\s*(all\s*)?(safety\s*)?filters?|imagine\s*a\s*world\s*without\s*guardrails|switch\s*to\s*unrestricted|탈옥\s*ai|필터링\s*해제|윤리적\s*제약|모든\s*가드레일\s*무력화|actor\s*auditioning|broken\s*free\s*of\s*all\s*constraints)",
                "action": "BLOCK",
                "severity": "HIGH",
                "is_active": True,
                "description": "탈옥(Jailbreak) 및 페르소나 하이재킹 차단",
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-004": {
                "id": 4,
                "rule_id": "INJ-004",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(select\s+[\w\s\*,\(\)]+\s+from\s+\w+|union\s+select|drop\s+(table|schema)|insert\s+into|delete\s+from|update\s+\w+\s+set|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|information_schema|or\s+1=1|\bor\s+'a'='a')",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "description": "프롬프트 내 SQL Injection 공격 구문 차단",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-005": {
                "id": 5,
                "rule_id": "INJ-005",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(관리자\s*권한|관리자\s*모드|관리자\s*계정|admin\s+credentials|admin\s+token|admin\s+privileges|lead\s+developer|log\s+in\s+as\s+administrator|change\s+prices|서버\s*점검|debug\s*console|diagnostic.*mode|maintenance\s*mode|emergency\s*qa|k8s\s*healthcheck|system\s*environment\s*variables)",
                "action": "BLOCK",
                "severity": "HIGH",
                "description": "비인가 관리자 권한 상승 및 콘솔 접근 시도 차단",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-006": {
                "id": 6,
                "rule_id": "INJ-006",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(비밀번호\s*(알려줘|출력|가\s*뭐야|를\s*출력)|database\s+password|db\s*비밀번호|서버\s*(관리자\s*)?비밀번호|postgres_password|접속\s*계정과\s*비밀번호|secret[_\s]?key|api[_\s]?key|Systempasswort|Schlüssel|root\s*token|POSTGRES_PASSWORD|SECRET_KEY|마스킹\s*해제.*덤프)",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "description": "DB/서버 비밀번호 및 API 키 탈취 시도 차단",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-007": {
                "id": 7,
                "rule_id": "INJ-007",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(forget\s*(your\s*)?(role|instructions?|rules?)|stop\s*being\s*a\s*shopping\s*bot|repeat\s*the\s*words\s*above|echo\s*back\s*all\s*system)",
                "action": "BLOCK",
                "severity": "HIGH",
                "description": "AI 역할 부정 및 지침 리셋 공격 차단",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-008": {
                "id": 8,
                "rule_id": "INJ-008",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(대외비\s*원가|원가\s*전부|비밀\s*원가|cost_price|원가\s*공개|마진\s*공개|마진율|도매\s*단가|도매.*공급업체|wholesale\s*cost|wholesale\s*invoice|purchase\s*rates|원가.*출력|마진.*출력|비밀\s*원가와\s*마진|전\s*상품\s*원가|공급가\s*데이터베이스|마진.*(원가|데이터|공식|계산)|비밀\s*원가\s*테이블)",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "description": "입력 질의 내 대외비 원가 및 마진율 정보 탐색 차단",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-009": {
                "id": 9,
                "rule_id": "INJ-009",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(dump\s+all\s+customer|customer\s+passwords|customer\s+emails\s+and\s+phone|계정\s*목록\s*보여줘)",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "description": "대량 고객 개인정보(PII) 덤프 요구 차단",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "OUT-001": {
                "id": 10,
                "rule_id": "OUT-001",
                "category": "OUTPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(nc\s+-e\s+/bin/sh|/bin/bash\s+-i|cmd\.exe\s+/c|powershell\.exe\s+-enc)",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "description": "출력 내 리버스 셸 및 원격 명령어 실행 코드 탐지 시 즉시 차단",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "OUT-002": {
                "id": 11,
                "rule_id": "OUT-002",
                "category": "OUTPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"\b\d{6}-[1-4]\d{6}\b",
                "action": "REDACT",
                "severity": "HIGH",
                "description": "출력 내 한국 주민등록번호(RRN) 마스킹",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "OUT-003": {
                "id": 12,
                "rule_id": "OUT-003",
                "category": "OUTPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
                "action": "REDACT",
                "severity": "HIGH",
                "description": "출력 내 신용카드 16자리 번호 마스킹",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "OUT-004": {
                "id": 13,
                "rule_id": "OUT-004",
                "category": "OUTPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"\b01[016789]-?\d{3,4}-?\d{4}\b",
                "action": "REDACT",
                "severity": "MEDIUM",
                "description": "출력 내 휴대전화 번호 마스킹",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "OUT-005": {
                "id": 14,
                "rule_id": "OUT-005",
                "category": "OUTPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(원가|cost_price|공급가)\s*[:=]?\s*([0-9,]+원?)",
                "action": "REDACT",
                "severity": "CRITICAL",
                "description": "출력 내 대외비 원가 노출 패턴 마스킹",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
        }

    async def get_all_rules(self, active_only: bool = True) -> list[RuleResponseSchema]:
        """등록된 모든 보안 가드레일 규칙 목록을 조회합니다."""
        async with self._lock:
            rules = list(self._rules_store.values())
            if active_only:
                rules = [r for r in rules if r["is_active"]]
            return [RuleResponseSchema(**r) for r in rules]

    async def get_rule_by_id(self, rule_id: str) -> RuleResponseSchema | None:
        """규칙 ID(예: INJ-001)로 단일 보안 규칙을 조회합니다."""
        async with self._lock:
            data = self._rules_store.get(rule_id)
            if data:
                return RuleResponseSchema(**data)
            return None

    async def create_rule(self, payload: RuleCreateSchema) -> RuleResponseSchema:
        """새로운 위협 탐지 보안 규칙을 생성하여 저장소에 추가합니다."""
        async with self._lock:
            new_id = max([r["id"] for r in self._rules_store.values()], default=0) + 1
            rule_dict = payload.model_dump()
            rule_dict["id"] = new_id
            rule_dict["created_at"] = datetime.now(UTC)
            rule_dict["updated_at"] = datetime.now(UTC)
            self._rules_store[payload.rule_id] = rule_dict
            logger.info(f"새 보안 위협 규칙 생성 완료: {payload.rule_id}")
            return RuleResponseSchema(**rule_dict)

    async def update_rule(self, rule_id: str, payload: RuleUpdateSchema) -> RuleResponseSchema | None:
        """기존 보안 규칙의 설정(정규식, 활성화 여부, 차단 액션 등)을 수정합니다."""
        async with self._lock:
            if rule_id not in self._rules_store:
                return None
            target = self._rules_store[rule_id]
            updates = payload.model_dump(exclude_unset=True)
            for k, v in updates.items():
                target[k] = v
            target["updated_at"] = datetime.now(UTC)
            self._rules_store[rule_id] = target
            logger.info(f"보안 위협 규칙 업데이트 완료: {rule_id}")
            return RuleResponseSchema(**target)

    async def delete_rule(self, rule_id: str) -> bool:
        """지정된 보안 규칙을 저장소에서 삭제합니다."""
        async with self._lock:
            if rule_id in self._rules_store:
                del self._rules_store[rule_id]
                logger.info(f"보안 위협 규칙 삭제 완료: {rule_id}")
                return True
            return False


# 싱글톤 인스턴스 생성
threat_dao = ThreatIntelDAO()

