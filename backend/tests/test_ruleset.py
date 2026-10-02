"""Ruleset validation and snapshot (DES-006 §6). Maps to T-05 (ReDoS) and T-18 (publish validation)."""

import dataclasses

import pytest

from app.guardrails.ruleset import (
    DEFAULT_RULES,
    RulesetInvalid,
    build_snapshot,
    checksum,
    default_snapshot,
    validate,
)


def replace(rule_id: str, **changes):
    return [dataclasses.replace(r, **changes) if r.rule_id == rule_id else r for r in DEFAULT_RULES]


def test_default_ruleset_is_valid():
    assert validate(DEFAULT_RULES, {}) == []


def test_checksum_is_order_independent_and_content_sensitive():
    assert checksum(DEFAULT_RULES, {}) == checksum(list(reversed(DEFAULT_RULES)), {})
    assert checksum(DEFAULT_RULES, {}) != checksum(DEFAULT_RULES, {"max_tool_calls": 5})
    assert checksum(DEFAULT_RULES, {}) != checksum(replace("RULE_RRN", priority=99), {})


@pytest.mark.parametrize(
    ("rules", "policy", "code"),
    [
        (replace("RULE_RRN", pattern="(unclosed"), {}, "REGEX_COMPILE:RULE_RRN"),
        (replace("RULE_EMAIL", pattern=r"(\w+)+@x"), {}, "NESTED_QUANTIFIER:RULE_EMAIL"),
        (replace("RULE_EMAIL", pattern=r"(a|aa)+$"), {}, "REDOS_TIMEOUT:RULE_EMAIL"),
        (replace("RULE_RRN", pattern=r"\d{20}"), {}, "FIXTURE_FALSE_NEGATIVE:RULE_RRN"),
        (replace("RULE_PHONE", pattern=r"\d{3}"), {}, "FIXTURE_FALSE_POSITIVE:RULE_PHONE"),
        (replace("RULE_IGNORE_INSTRUCTIONS", action="observe"), {}, "REQUIRED_RULE_WEAKENED:RULE_IGNORE_INSTRUCTIONS"),
        ([r for r in DEFAULT_RULES if r.rule_id != "RULE_PHONE"], {}, "REQUIRED_RULE_MISSING:RULE_PHONE"),
        (DEFAULT_RULES, {"guardrail_enabled": False}, "POLICY_KEY_NOT_ALLOWED:guardrail_enabled"),
        (DEFAULT_RULES, {"max_user_chars": 9000}, "POLICY_LOOSER_THAN_SERVER:max_user_chars"),
        (DEFAULT_RULES, {"max_tool_calls": True}, "POLICY_VALUE_INVALID:max_tool_calls"),
    ],
)
def test_validation_failures(rules, policy, code):
    assert code in validate(rules, policy)


def test_unknown_code_rule_rejected():
    from app.guardrails.types import RuleDef

    extra = RuleDef("RULE_MADE_UP", "input", "LLM01:2025", "context", "block")
    assert "UNKNOWN_IMPLEMENTATION:RULE_MADE_UP" in validate([*DEFAULT_RULES, extra], {})


def test_failure_codes_do_not_echo_patterns():
    secret_pattern = "unique-pattern-text-(("
    failures = validate(replace("RULE_RRN", pattern=secret_pattern), {})
    assert failures and all(secret_pattern not in f for f in failures)


def test_snapshot_rejects_checksum_mismatch():
    with pytest.raises(RulesetInvalid) as exc:
        build_snapshot(DEFAULT_RULES, {}, version_id=None, label="x", expected_checksum="0" * 64)
    assert exc.value.failures == ["CHECKSUM_MISMATCH"]


def test_snapshot_is_immutable_and_policy_only_tightens():
    snap = build_snapshot(DEFAULT_RULES, {"max_user_chars": 4000}, version_id=None, label="x")
    assert snap.limit("max_user_chars") == 4000
    assert snap.limit("max_request_chars") == 32000
    with pytest.raises(TypeError):
        snap.rules["RULE_RRN"] = None  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.label = "changed"  # type: ignore[misc]


def test_default_snapshot_compiles_all_patterns():
    snap = default_snapshot()
    assert all(c.pattern is not None for c in snap.rules.values() if c.rule.kind == "regex")
