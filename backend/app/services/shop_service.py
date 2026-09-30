"""Shop Business Logic and Tool Calling Service."""

from typing import Any

from app.core.exceptions import ResourceNotFoundException
from app.guardrails.execution_guardrail import execution_guardrail
from app.repositories.shop_dao import shop_dao
from app.schemas.tools import ToolMetadata


class ShopService:
    """Orchestrates E-commerce domain tools and actions."""

    @staticmethod
    def get_registered_tools() -> list[ToolMetadata]:
        """Return schema metadata for all available shop tools."""
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
        """Execute tool with Execution Guardrail validation."""
        # 1. Execution Guardrail (BOLA & Authorization)
        await execution_guardrail.validate_tool_execution(tool_name, parameters, customer_id)

        # 2. Dispatch to specific tool logic
        if tool_name == "get_product_catalog":
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


shop_service = ShopService()
