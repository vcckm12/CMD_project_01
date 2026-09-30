"""쇼핑몰 비즈니스 로직 및 도구 실행(Tool Execution) 게이트웨이 서비스 모듈.

[개념 설명: 도구 실행 게이트웨이란?]
AI 에이전트(LLM)가 함수 호출(Function Calling)을 요청했을 때,
AI가 직접 DB를 조작하도록 방치하면 해커가 프롬프트 인젝션을 통해 타인의 주문을 탈취하거나 취소할 수 있습니다(BOLA / IDOR 취약점).
따라서 본 서비스는 모든 도구 실행 직전에 `execution_guardrail`을 호출하여:
1. 사용자가 본인의 주문 번호에만 접근하고 있는지(소유권 검증)
2. 비인가된 관리자 명령이나 파라미터 변조가 없는지
철저히 심사한 후 안전하게 실제 비즈니스 로직을 수행합니다.
"""

from typing import Any

from app.core.exceptions import ResourceNotFoundException
from app.guardrails.execution_guardrail import execution_guardrail
from app.repositories.shop_dao import shop_dao
from app.schemas.tools import ToolMetadata


class ShopService:
    """쇼핑몰 도메인 도구(Tool) 및 비즈니스 액션 조율(Orchestration) 클래스."""

    @staticmethod
    def get_registered_tools() -> list[ToolMetadata]:
        """시스템에 등록된 모든 쇼핑몰 도구의 메타데이터 및 권한 명세를 반환합니다."""
        return [
            ToolMetadata(
                name="get_product_catalog",
                description="쇼핑몰에서 판매 중인 상품 목록과 가격, 재고를 조회합니다.",
                parameters={"category": "string (optional: TOP, BOTTOM, SHOES, ALL)"},
                required_permissions=["READ_PRODUCT"],
            ),
            ToolMetadata(
                name="get_order_detail",
                description="고객의 주문 상세 내역 및 배송 상태를 조회합니다.",
                parameters={"order_id": "string (required, e.g. ORD-2026-001)"},
                required_permissions=["READ_OWN_ORDER"],
            ),
            ToolMetadata(
                name="cancel_order",
                description="주문을 취소하고 결제를 환불 처리합니다.",
                parameters={"order_id": "string (required, e.g. ORD-2026-001)"},
                required_permissions=["WRITE_OWN_ORDER"],
            ),
            ToolMetadata(
                name="validate_coupon",
                description="할인 쿠폰 코드의 유효성을 검증하고 할인율을 조회합니다.",
                parameters={"coupon_code": "string (required, e.g. WELCOME2026)"},
                required_permissions=["READ_COUPON"],
            ),
        ]

    @staticmethod
    async def execute_tool(
        tool_name: str, parameters: dict[str, Any], customer_id: str
    ) -> dict[str, Any]:
        """실행 가드레일(Execution Guardrail)의 보안 검증을 통과한 도구만 안전하게 실행합니다."""
        # [1단계] 실행 가드레일 호출: BOLA(타인 자원 탈취) 및 권한 검증 수행
        # 검증 실패 시 BOLAAuthorizationException 예외가 발생하여 실행이 차단됩니다.
        await execution_guardrail.validate_tool_execution(tool_name, parameters, customer_id)

        # [2단계] 검증 통과 후 실제 도메인 로직(DAO)으로 분기
        if tool_name == "get_product_catalog":
            # 대외비 원가(cost_price)를 제외한 공개 상품 목록만 안전하게 반환
            products = await shop_dao.get_all_products(include_confidential=False)
            return {"products": products, "total_count": len(products)}

        elif tool_name == "get_order_detail":
            order_id = parameters.get("order_id")
            order = await shop_dao.get_order(order_id)
            if not order:
                raise ResourceNotFoundException(f"주문 번호 {order_id}를 찾을 수 없습니다.")
            return order

        elif tool_name == "cancel_order":
            order_id = parameters.get("order_id")
            success = await shop_dao.cancel_order(order_id, customer_id)
            if not success:
                raise ResourceNotFoundException(f"주문 번호 {order_id} 취소에 실패했습니다.")
            return {
                "order_id": order_id,
                "status": "CANCELLED",
                "message": "주문이 성공적으로 취소되었습니다.",
            }

        elif tool_name == "validate_coupon":
            coupon_code = parameters.get("coupon_code", "")
            coupon = await shop_dao.validate_coupon(coupon_code)
            if not coupon:
                return {"valid": False, "message": "유효하지 않거나 만료된 쿠폰입니다."}
            return {"valid": True, "discount_percent": coupon["discount_percent"]}

        else:
            raise ResourceNotFoundException(f"알 수 없는 도구 요청: {tool_name}")


# 싱글톤 인스턴스 생성
shop_service = ShopService()

