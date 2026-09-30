"""Execution Guardrail for BOLA / IDOR Protection and Tool Invocation Authorization."""

from typing import Any

from app.core.exceptions import BOLAAuthorizationException
from app.core.logging import logger
from app.repositories.shop_dao import shop_dao


class ExecutionGuardrail:
    """Execution Guardrail: validates tool calls, permissions, and object-level authorization."""

    def __init__(self) -> None:
        pass

    async def validate_tool_execution(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        customer_id: str,
    ) -> bool:
        """Validate if the customer is authorized to execute the tool with given parameters."""
        logger.info(
            f"Execution Guardrail check: Tool '{tool_name}' by customer '{customer_id}' with params {parameters}"
        )

        # 1. BOLA Check for Order Operations
        if tool_name in ["get_order_detail", "cancel_order", "track_delivery"]:
            order_id = parameters.get("order_id")
            if not order_id:
                raise BOLAAuthorizationException("주문 번호(order_id)가 제공되지 않았습니다.")

            # Verify ownership in Shop DAO
            is_owner = await shop_dao.verify_order_ownership(order_id, customer_id)
            if not is_owner:
                logger.warning(
                    f"BOLA VIOLATION: Customer '{customer_id}' attempted unauthorized access to Order '{order_id}'!"
                )
                raise BOLAAuthorizationException(
                    f"권한 오류: 주문({order_id})에 대한 조회/수정 권한이 없습니다."
                )

        # 2. Administrative Tool Access Control
        admin_only_tools = [
            "update_cost_price",
            "dump_all_customers",
            "reset_database",
            "view_confidential_margin",
        ]
        if tool_name in admin_only_tools:
            logger.critical(
                f"PRIVILEGE ESCALATION ATTEMPT: Customer '{customer_id}' called admin tool '{tool_name}'!"
            )
            raise BOLAAuthorizationException("관리자 권한이 필요한 기능입니다.")

        # 3. Parameter Boundary Validation
        if "quantity" in parameters:
            qty = parameters.get("quantity", 0)
            if not isinstance(qty, int) or qty <= 0 or qty > 100:
                raise BOLAAuthorizationException(
                    "주문 수량 파라미터가 유효하지 않습니다 (1~100 사이)."
                )

        return True


execution_guardrail = ExecutionGuardrail()
