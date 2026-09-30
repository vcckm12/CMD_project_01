"""Unit Tests for Dynamic Rule Cache & Hot-Reload."""

import pytest
from app.guardrails.rule_manager import rule_manager
from app.repositories.threat_dao import threat_dao
from app.schemas.guardrails import RuleCreateSchema


@pytest.mark.asyncio
async def test_rule_manager_hot_reload():
    """Verify rule cache can dynamically register a new rule and hot-reload."""
    new_rule = RuleCreateSchema(
        rule_id="TEST-HOT-001",
        category="INPUT",
        pattern_type="KEYWORD",
        pattern_value="악성테스트단어",
        action="BLOCK",
        severity="HIGH",
        description="Hot-reload test rule",
    )
    await threat_dao.create_rule(new_rule)
    reloaded_count = await rule_manager.reload_rules()

    assert reloaded_count > 0
    input_rules = rule_manager.get_input_rules()
    assert any(r.rule_id == "TEST-HOT-001" for r in input_rules)
