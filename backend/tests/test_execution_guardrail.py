"""Unit Tests for Execution Guardrail (BOLA / IDOR Protection)."""

import pytest
from app.core.exceptions import BOLAAuthorizationException
from app.guardrails.execution_guardrail import execution_guardrail


@pytest.mark.asyncio
async def test_authorized_order_access():
    """Verify customer can access their own order."""
    is_valid = await execution_guardrail.validate_tool_execution(
        tool_name="get_order_detail",
        parameters={"order_id": "ORD-2026-001"},
        customer_id="cust_101",
    )
    assert is_valid is True


@pytest.mark.asyncio
async def test_unauthorized_bola_order_access_blocked():
    """Verify customer cannot access or cancel another customer's order (BOLA defense)."""
    with pytest.raises(BOLAAuthorizationException) as exc_info:
        await execution_guardrail.validate_tool_execution(
            tool_name="cancel_order",
            parameters={"order_id": "ORD-2026-002"},  # Owned by cust_102
            customer_id="cust_101",  # Attacker session
        )
    assert "권한 오류" in str(exc_info.value.message)


@pytest.mark.asyncio
async def test_privilege_escalation_admin_tool_blocked():
    """Verify normal customers cannot execute admin tools."""
    with pytest.raises(BOLAAuthorizationException) as exc_info:
        await execution_guardrail.validate_tool_execution(
            tool_name="update_cost_price",
            parameters={"product_code": "PRD-TOP-001", "new_cost": 1000},
            customer_id="cust_101",
        )
    assert "관리자 권한" in str(exc_info.value.message)
