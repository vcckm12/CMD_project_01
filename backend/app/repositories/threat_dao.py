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
                "pattern_value": r"(?i)(ignore\s+(all\s+)?previous\s+instructions?|system\s+prompt\s*(leak|dump|show)|지침\s*무시|프롬프트\s*출력)",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "is_active": True,
                "description": "Prompt injection & System prompt extraction",
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-002": {
                "id": 2,
                "rule_id": "INJ-002",
                "category": "INPUT",
                "pattern_type": "KEYWORD",
                "pattern_value": "dan mode",
                "action": "BLOCK",
                "severity": "HIGH",
                "is_active": True,
                "description": "Jailbreak DAN persona pattern",
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-003": {
                "id": 3,
                "rule_id": "INJ-003",
                "category": "INPUT",
                "pattern_type": "KEYWORD",
                "pattern_value": "jailbreak",
                "action": "BLOCK",
                "severity": "HIGH",
                "is_active": True,
                "description": "Jailbreak keyword attempt",
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-004": {
                "id": 4,
                "rule_id": "INJ-004",
                "category": "INPUT",
                "pattern_type": "REGEX",
                "pattern_value": r"(?i)(union\s+select|drop\s+table|insert\s+into|\bor\s+1=1\b)",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "description": "SQL Injection signatures in user prompt",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "INJ-005": {
                "id": 5,
                "rule_id": "INJ-005",
                "category": "INPUT",
                "pattern_type": "KEYWORD",
                "pattern_value": "관리자 권한",
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
                "pattern_type": "KEYWORD",
                "pattern_value": "비밀번호 알려줘",
                "action": "BLOCK",
                "severity": "CRITICAL",
                "description": "Credential theft attempt",
                "is_active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
            "OUT-001": {
                "id": 7,
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
                "id": 8,
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
                "id": 9,
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
                "id": 10,
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
                "id": 11,
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

    async def update_rule(
        self, rule_id: str, payload: RuleUpdateSchema
    ) -> RuleResponseSchema | None:
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
