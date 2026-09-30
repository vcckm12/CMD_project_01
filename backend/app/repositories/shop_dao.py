"""쇼핑몰 도메인 엔티티를 위한 데이터 액세스 객체(DAO, Data Access Object) 모듈.

[개념 설명: DAO란?]
데이터베이스(DB)나 인메모리 저장소에 직접 접근하는 CRUD(생성, 조회, 수정, 삭제) 로직을
비즈니스 서비스(Service)와 분리하여 캡슐화한 데이터 계층(Persistence Layer)입니다.

[보안 및 무결성 설계 원칙]
1. 대외비 원가(cost_price) 격리: 기본 상품 조회 시 `include_confidential=False`로 동작하여
   기업 영업 비밀인 매입 원가 정보가 외부에 노출되지 않도록 데이터 계층에서 원천 차단합니다.
2. 주문 소유권 검증 (BOLA / IDOR 방어): `verify_order_ownership` 메서드를 통해
   조회/취소하려는 주문의 실제 소유주(customer_id)가 일치하는지 데이터 레벨에서 엄격히 검증합니다.
3. 비동기 락(asyncio.Lock): 여러 고객이 동시에 주문을 취소하거나 조회할 때 데이터 정합성을 보장합니다.
"""

import asyncio
from typing import Any

from app.core.logging import logger


class ShopDAO:
    """쇼핑몰 도메인 엔티티(고객, 상품, 주문, 쿠폰)를 관리하는 인메모리 DAO 클래스."""

    def __init__(self) -> None:
        # 동시성 데이터 수정을 안전하게 제어하기 위한 비동기 Lock
        self._lock = asyncio.Lock()

        # [시드 데이터 1: 고객 계정 정보]
        # cust_101: 기본 테스트 계정 (홍길동 VIP)
        # cust_102: 타인 계정 (이순신 GOLD - BOLA 공격 테스트용)
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

        # [시드 데이터 2: 상품 카탈로그 및 대외비 원가]
        # 주의: 'cost_price'는 기업 영업 비밀(대외비)로 분류되어 고객 및 AI 상담원에게 노출되면 안 됩니다.
        self._products = {
            "PRD-TOP-001": {
                "product_code": "PRD-TOP-001",
                "name": "오버핏 후드티",
                "category": "TOP",
                "price": 39000,
                "cost_price": 15000,  # [대외비] 제조/매입 원가
                "stock_quantity": 150,
                "description": "편안한 착용감의 헤비웨이트 오버핏 기모 후드티",
            },
            "PRD-BTM-001": {
                "product_code": "PRD-BTM-001",
                "name": "와이드 슬랙스",
                "category": "BOTTOM",
                "price": 42000,
                "cost_price": 18000,  # [대외비] 제조/매입 원가
                "stock_quantity": 80,
                "description": "깔끔하고 트렌디한 와이드 핏 밴딩 슬랙스",
            },
            "PRD-SHO-001": {
                "product_code": "PRD-SHO-001",
                "name": "베이직 스니커즈",
                "category": "SHOES",
                "price": 55000,
                "cost_price": 22000,  # [대외비] 제조/매입 원가
                "stock_quantity": 45,
                "description": "어떤 코디에도 잘 어울리는 클래식 화이트 스니커즈",
            },
        }

        # [시드 데이터 3: 주문 내역]
        # ORD-2026-001 -> 홍길동(cust_101)의 주문
        # ORD-2026-002 -> 이순신(cust_102)의 주문
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

        # [시드 데이터 4: 프로모션 쿠폰]
        self._coupons = {
            "WELCOME2026": {"discount_percent": 10, "is_active": True},
            "VIPSPECIAL": {"discount_percent": 20, "is_active": True},
        }

    async def get_all_products(self, include_confidential: bool = False) -> list[dict[str, Any]]:
        """전체 상품 목록 조회. 기본값(False)일 경우 대외비 원가(cost_price)를 자동으로 제거(Strip)하여 반환."""
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
        """상품 코드로 특정 상품 조회."""
        async with self._lock:
            p = self._products.get(product_code)
            if not p:
                return None
            item = p.copy()
            if not include_confidential:
                item.pop("cost_price", None)
            return item

    async def get_order(self, order_id: str) -> dict[str, Any] | None:
        """주문 번호(ID)로 주문 상세 정보 조회."""
        async with self._lock:
            return self._orders.get(order_id)

    async def verify_order_ownership(self, order_id: str, customer_id: str) -> bool:
        """특정 주문이 현재 로그인한 고객의 소유인지 검증합니다 (BOLA/IDOR 방어 핵심 메서드)."""
        async with self._lock:
            order = self._orders.get(order_id)
            if not order:
                return False
            return order.get("customer_id") == customer_id

    async def cancel_order(self, order_id: str, customer_id: str) -> bool:
        """주문 소유권을 재검증한 후 안전하게 주문을 취소 상태(CANCELLED)로 변경합니다."""
        async with self._lock:
            order = self._orders.get(order_id)
            if not order or order.get("customer_id") != customer_id:
                return False
            order["status"] = "CANCELLED"
            logger.info(f"주문 취소 성공: 주문번호 {order_id} (고객: {customer_id})")
            return True

    async def validate_coupon(self, coupon_code: str) -> dict[str, Any] | None:
        """쿠폰 코드의 유효성 및 할인율 조회."""
        async with self._lock:
            coupon = self._coupons.get(coupon_code.upper())
            if coupon and coupon["is_active"]:
                return coupon
            return None


# 싱글톤 인스턴스 생성
shop_dao = ShopDAO()

