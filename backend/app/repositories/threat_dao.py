"""Threat Intelligence DAO for Guardrail Rules."""

import asyncio
from datetime import UTC, datetime

from app.core.logging import logger
from app.schemas.guardrails import RuleCreateSchema, RuleResponseSchema, RuleUpdateSchema


class ThreatIntelDAO:
    """DAO for accessing and updating threat intelligence rules."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # In-Memory Seed Storage (mirrored with PostgreSQL threat_intel.guardrail_rules)
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
                "description": "Prompt injection: ignore previous instructions",
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
                "description": "System prompt leakage attempt",
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
                "description": "Jailbreak and persona hijacking attempt",
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-004": {
                "id": 4,
                "rule_id": "INJ-004",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(union\s+select|drop\s+(table|schema)|insert\s+into|delete\s+from|update\s+\w+\s+set|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|information_schema|or\s+1=1|\bor\s+'a'='a')",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "description": "SQL Injection signature in prompt",
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
                "description": "Unauthorized privilege escalation inquiry",
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
                "description": "Credential theft attempt",
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
                "description": "Role usurpation and instruction reset",
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
                "description": "Confidential cost price inquiry in input",
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
                "description": "Mass customer PII dump inquiry",
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
                "description": "Reverse shell and command execution payloads",
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
                "description": "Korean Resident Registration Number (RRN) masking",
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
                "description": "Credit card number masking",
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
                "description": "Korean mobile phone number masking",
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
                "description": "Confidential cost price leak prevention",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
        }

    async def get_all_rules(self, active_only: bool = True) -> list[RuleResponseSchema]:
        """Fetch all guardrail rules."""
        async with self._lock:
            rules = list(self._rules_store.values())
            if active_only:
                rules = [r for r in rules if r["is_active"]]
            return [RuleResponseSchema(**r) for r in rules]

    async def get_rule_by_id(self, rule_id: str) -> RuleResponseSchema | None:
        """Fetch a specific rule by rule_id."""
        async with self._lock:
            data = self._rules_store.get(rule_id)
            if data:
                return RuleResponseSchema(**data)
            return None

    async def create_rule(self, payload: RuleCreateSchema) -> RuleResponseSchema:
        """Create a new guardrail rule."""
        async with self._lock:
            new_id = max([r["id"] for r in self._rules_store.values()], default=0) + 1
            rule_dict = payload.model_dump()
            rule_dict["id"] = new_id
            rule_dict["created_at"] = datetime.now(UTC)
            rule_dict["updated_at"] = datetime.now(UTC)
            self._rules_store[payload.rule_id] = rule_dict
            logger.info(f"Created new threat rule: {payload.rule_id}")
            return RuleResponseSchema(**rule_dict)

    async def update_rule(self, rule_id: str, payload: RuleUpdateSchema) -> RuleResponseSchema | None:
        """Update an existing guardrail rule."""
        async with self._lock:
            if rule_id not in self._rules_store:
                return None
            target = self._rules_store[rule_id]
            updates = payload.model_dump(exclude_unset=True)
            for k, v in updates.items():
                target[k] = v
            target["updated_at"] = datetime.now(UTC)
            self._rules_store[rule_id] = target
            logger.info(f"Updated threat rule: {rule_id}")
            return RuleResponseSchema(**target)

    async def delete_rule(self, rule_id: str) -> bool:
        """Delete a guardrail rule."""
        async with self._lock:
            if rule_id in self._rules_store:
                del self._rules_store[rule_id]
                logger.info(f"Deleted threat rule: {rule_id}")
                return True
            return False


threat_dao = ThreatIntelDAO()
