"""In-Memory Rule Cache & Hot-Reload Manager."""

import asyncio
import re

from app.core.logging import logger
from app.repositories.threat_dao import threat_dao
from app.schemas.guardrails import RuleResponseSchema


class RuleManager:
    """Thread-safe in-memory cache for dynamic threat intelligence rules."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._input_rules: list[RuleResponseSchema] = []
        self._output_rules: list[RuleResponseSchema] = []
        self._execution_rules: list[RuleResponseSchema] = []
        self._compiled_regexes: dict[str, re.Pattern] = {}
        self._initialized = False
        self._sync_load_seed_rules()

    def _sync_load_seed_rules(self) -> None:
        """Synchronously populate in-memory seed rules to prevent empty rule window."""
        all_rules = [
            RuleResponseSchema(**r) for r in threat_dao._rules_store.values() if r.get("is_active", True)
        ]
        self._input_rules = [r for r in all_rules if r.category.upper() == "INPUT"]
        self._output_rules = [r for r in all_rules if r.category.upper() == "OUTPUT"]
        self._execution_rules = [r for r in all_rules if r.category.upper() == "EXECUTION"]
        for r in all_rules:
            if r.pattern_type.upper() == "REGEX":
                try:
                    self._compiled_regexes[r.rule_id] = re.compile(r.pattern_value, re.IGNORECASE)
                except re.error:
                    pass

    async def initialize(self) -> None:
        """Load initial rules from DAO into memory."""
        await self.reload_rules()
        self._initialized = True

    async def reload_rules(self) -> int:
        """Hot-reload all active rules from database/DAO into in-memory cache."""
        async with self._lock:
            all_rules = await threat_dao.get_all_rules(active_only=True)
            self._input_rules = [r for r in all_rules if r.category.upper() == "INPUT"]
            self._output_rules = [r for r in all_rules if r.category.upper() == "OUTPUT"]
            self._execution_rules = [r for r in all_rules if r.category.upper() == "EXECUTION"]

            # Pre-compile regexes for high-performance matching
            new_regexes: dict[str, re.Pattern] = {}
            for r in all_rules:
                if r.pattern_type.upper() == "REGEX":
                    try:
                        new_regexes[r.rule_id] = re.compile(r.pattern_value, re.IGNORECASE)
                    except re.error as err:
                        logger.error(f"Failed to compile regex for rule {r.rule_id}: {err}")

            self._compiled_regexes = new_regexes
            total = len(all_rules)
            logger.info(
                f"RuleCacheManager: Hot-reloaded {total} rules (Input: {len(self._input_rules)}, Output: {len(self._output_rules)})"
            )
            return total

    def get_input_rules(self) -> list[RuleResponseSchema]:
        """Get cached active input rules."""
        return self._input_rules

    def get_output_rules(self) -> list[RuleResponseSchema]:
        """Get cached active output rules."""
        return self._output_rules

    def get_compiled_regex(self, rule_id: str) -> re.Pattern | None:
        """Get pre-compiled regex pattern by rule_id."""
        return self._compiled_regexes.get(rule_id)


rule_manager = RuleManager()
