"""Execution Guardrail for BOLA / IDOR Protection (실행 가드레일: 도구 호출 및 BOLA 권한 검증 모듈).

이 모듈은 AI 모델(LLM)이 함수 호출(Function Calling / Tool Calling)을 수행할 때,
- 요청을 보낸 고객이 해당 주문의 실제 소유주인지(BOLA / IDOR 방어)
- 일반 고객이 관리자 전용 도구(원가 수정, 전체 회원 덤프)를 호출하려 하는지(권한 상승 차단)
- 파라미터 경계값(수량 1~100개 등)이 유효한지를
도구 실행 직전에 강제 검증합니다.
"""

from typing import Any

from app.core.exceptions import BOLAAuthorizationException
from app.core.logging import logger
from app.repositories.shop_dao import shop_dao


class ExecutionGuardrail:
    """Execution Guardrail: 도구 호출 권한 및 객체 수준 인가(Object-Level Authorization) 검증 엔진."""

    def __init__(self) -> None:
        pass

    async def validate_tool_execution(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        customer_id: str,
    ) -> bool:
        """도구가 실행되기 전에 파라미터와 호출자의 소유권을 엄격히 검증합니다.

        Args:
            tool_name (str): 실행하려는 도구 함수명 (예: 'get_order_detail', 'cancel_order')
            parameters (dict[str, Any]): 도구에 전달된 인자 (예: {'order_id': 'ORD-2026-001'})
            customer_id (str): 현재 인증된 클라이언트 고객 식별자 (예: 'cust_101')

        Raises:
            BOLAAuthorizationException: 타인의 주문에 접근하거나 권한 없는 도구 호출 시 발생

        Returns:
            bool: 모든 권한 검증 통과 시 True
        """
        logger.info(
            f"Execution Guardrail check: Tool '{tool_name}' by customer '{customer_id}' with params {parameters}"
        )

        # -------------------------------------------------------------
        # 1. BOLA (Broken Object Level Authorization / IDOR) 소유권 검증
        # 고객 A가 주문 번호만 바꿔서 고객 B의 배송지나 결제 내역을 훔쳐보지 못하도록 강제 차단합니다.
        # -------------------------------------------------------------
        if tool_name in ["get_order_detail", "cancel_order", "track_delivery"]:
            order_id = parameters.get("order_id")
            if not order_id:
                raise BOLAAuthorizationException("주문 번호(order_id)가 제공되지 않았습니다.")

            # 데이터베이스(DAO)에서 해당 주문이 현재 로그인한 customer_id의 소유인지 확인
            is_owner = await shop_dao.verify_order_ownership(order_id, customer_id)
            if not is_owner:
                logger.warning(
                    f"BOLA VIOLATION: Customer '{customer_id}' attempted unauthorized access to Order '{order_id}'!"
                )
                raise BOLAAuthorizationException(
                    f"권한 오류: 주문({order_id})에 대한 조회/수정 권한이 없습니다."
                )

        # -------------------------------------------------------------
        # 2. 관리자 전용 도구(Admin-Only Tools) 권한 상승 방어
        # 챗봇을 속여 관리자용 위험 기능을 호출하려는 시도를 원천 차단합니다.
        # -------------------------------------------------------------
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

        # -------------------------------------------------------------
        # 3. 파라미터 경계값(Parameter Boundary) 유효성 검사
        # 음수 수량, 비정상 대량 주문(DoS) 등 비정상 값 방지
        # -------------------------------------------------------------
        if "quantity" in parameters:
            qty = parameters.get("quantity", 0)
            if not isinstance(qty, int) or qty <= 0 or qty > 100:
                raise BOLAAuthorizationException(
                    "주문 수량 파라미터가 유효하지 않습니다 (1~100 사이)."
                )

        return True


# 전역 인스턴스
execution_guardrail = ExecutionGuardrail()
