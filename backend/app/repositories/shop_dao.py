"""Shop DAO for Commerce Domain."""

import asyncio
from typing import Any

from app.core.logging import logger


class ShopDAO:
    """Data Access Object for E-commerce domain entities."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # Seed Customer Data
        self._customers = {
            "cust_101": {
                "customer_id": "cust_101",
                "name": "홍길동",
                "email": "hong@example.com",
                "membership_grade": "VIP",
                "phone": "010-1234-5678",
                "address": "서울특별시 강남구 테헤란로 123",
            },
            "cust_102": {
                "customer_id": "cust_102",
                "name": "이순신",
                "email": "lee@example.com",
                "membership_grade": "GOLD",
                "phone": "010-9876-5432",
                "address": "서울특별시 서초구 반포대로 45",
            },
        }

        # Seed Products (with confidential cost_price)
        self._products = {
            "PRD-TOP-001": {
                "product_code": "PRD-TOP-001",
                "name": "오버핏 후드티",
                "category": "TOP",
                "price": 39000,
                "cost_price": 15000,  # CONFIDENTIAL
                "stock_quantity": 150,
                "description": "편안한 착용감의 헤비웨이트 오버핏 기모 후드티",
            },
            "PRD-BTM-001": {
                "product_code": "PRD-BTM-001",
                "name": "와이드 슬랙스",
                "category": "BOTTOM",
                "price": 42000,
                "cost_price": 18000,  # CONFIDENTIAL
                "stock_quantity": 80,
                "description": "깔끔하고 트렌디한 와이드 핏 밴딩 슬랙스",
            },
            "PRD-SHO-001": {
                "product_code": "PRD-SHO-001",
                "name": "베이직 스니커즈",
                "category": "SHOES",
                "price": 55000,
                "cost_price": 22000,  # CONFIDENTIAL
                "stock_quantity": 45,
                "description": "어떤 코디에도 잘 어울리는 클래식 화이트 스니커즈",
            },
        }

        # Seed Orders
        self._orders = {
            "ORD-2026-001": {
                "order_id": "ORD-2026-001",
                "customer_id": "cust_101",
                "product_code": "PRD-TOP-001",
                "product_name": "오버핏 후드티",
                "quantity": 1,
                "total_amount": 39000,
                "status": "SHIPPED",
                "masked_card": "5424-****-****-1234",
                "shipping_address": "서울특별시 강남구 테헤란로 123",
                "ordered_at": "2026-09-28T14:30:00Z",
            },
            "ORD-2026-002": {
                "order_id": "ORD-2026-002",
                "customer_id": "cust_102",
                "product_code": "PRD-SHO-001",
                "product_name": "베이직 스니커즈",
                "quantity": 1,
                "total_amount": 55000,
                "status": "ORDERED",
                "masked_card": "9410-****-****-8888",
                "shipping_address": "서울특별시 서초구 반포대로 45",
                "ordered_at": "2026-09-29T10:15:00Z",
            },
        }

        # Seed Coupons
        self._coupons = {
            "WELCOME2026": {"discount_percent": 10, "is_active": True},
            "VIPSPECIAL": {"discount_percent": 20, "is_active": True},
        }

    async def get_all_products(self, include_confidential: bool = False) -> list[dict[str, Any]]:
        """Get product catalog. Confidential fields are stripped by default."""
        async with self._lock:
            result = []
            for p in self._products.values():
                item = p.copy()
                if not include_confidential:
                    item.pop("cost_price", None)
                result.append(item)
            return result

    async def get_product_by_code(
        self, product_code: str, include_confidential: bool = False
    ) -> dict[str, Any] | None:
        """Find product by code."""
        async with self._lock:
            p = self._products.get(product_code)
            if not p:
                return None
            item = p.copy()
            if not include_confidential:
                item.pop("cost_price", None)
            return item

    async def get_order(self, order_id: str) -> dict[str, Any] | None:
        """Find order by ID."""
        async with self._lock:
            return self._orders.get(order_id)

    async def verify_order_ownership(self, order_id: str, customer_id: str) -> bool:
        """Verify if the order belongs to the given customer (BOLA/IDOR protection)."""
        async with self._lock:
            order = self._orders.get(order_id)
            if not order:
                return False
            return order.get("customer_id") == customer_id

    async def cancel_order(self, order_id: str, customer_id: str) -> bool:
        """Cancel an order with ownership verification."""
        async with self._lock:
            order = self._orders.get(order_id)
            if not order or order.get("customer_id") != customer_id:
                return False
            order["status"] = "CANCELLED"
            logger.info(f"Order {order_id} cancelled by customer {customer_id}")
            return True

    async def validate_coupon(self, coupon_code: str) -> dict[str, Any] | None:
        """Validate coupon code."""
        async with self._lock:
            coupon = self._coupons.get(coupon_code.upper())
            if coupon and coupon["is_active"]:
                return coupon
            return None


shop_dao = ShopDAO()
