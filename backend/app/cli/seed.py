"""Synthetic catalog, coupons and order history for development (DES-002 §8 초기 적재).

Runs as the migration owner (no app role may write products/orders/coupons):
    docker compose run --rm migrate python -m app.cli.seed --customer-email customer@example.invalid
Idempotent for the catalog (SKU upsert). Orders and coupons are added only for the given existing
customer account. All data is synthetic; never load real customer data with this command.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid

import psycopg

PRODUCTS = [
    ("GF-TOP-001", "오버핏 후드티", "넉넉한 오버핏 기모 후드티", 39000, 30),
    ("GF-TOP-002", "베이직 맨투맨", "데일리 코튼 맨투맨", 29000, 25),
    ("GF-TOP-003", "스트라이프 셔츠", "봄가을용 스트라이프 셔츠", 35000, 12),
    ("GF-BTM-001", "와이드 슬랙스", "와이드 실루엣의 밴딩 슬랙스", 42000, 18),
    ("GF-BTM-002", "스트레이트 데님", "중청 스트레이트 데님 팬츠", 49000, 9),
    ("GF-OUT-001", "덕다운 패딩", "덕다운 80% 충전 숏패딩", 129000, 6),
    ("GF-OUT-002", "울 블렌드 코트", "울 50% 싱글 코트", 159000, 4),
    ("GF-SHO-001", "베이직 스니커즈", "편안한 착화감의 화이트 스니커즈", 55000, 20),
    ("GF-ACC-001", "미니멀 볼캡", "사이즈 조절 가능한 코튼 볼캡", 19000, 40),
    ("GF-ACC-002", "캔버스 토트백", "A4 수납 가능한 캔버스 토트백", 25000, 15),
    ("GF-ELC-001", "무선 마우스", "2.4GHz 무선 저소음 마우스", 25000, 50),
    ("GF-ELC-002", "블루투스 이어폰", "노이즈 캔슬링 무선 이어폰", 89000, 0),
]
COUPONS = [
    ("WELCOME5000", 5000, 30000, "60 days"),
    ("AUTUMN10000", 10000, 80000, "30 days"),
    ("EXPIRED3000", 3000, 0, "-1 days"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--customer-email", help="existing customer to receive synthetic orders and coupons")
    args = parser.parse_args()
    with psycopg.connect(os.environ["MIGRATION_DATABASE_URL"]) as conn, conn.transaction():
        for sku, name, desc, price, stock in PRODUCTS:
            conn.execute(
                "INSERT INTO commerce.products (sku, name, description, price_krw, stock_count)"
                " VALUES (%s, %s, %s, %s, %s)"
                " ON CONFLICT (sku) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,"
                " price_krw = EXCLUDED.price_krw, stock_count = EXCLUDED.stock_count",
                (sku, name, desc, price, stock),
            )
        for code, discount, minimum, ttl in COUPONS:
            conn.execute(
                "INSERT INTO commerce.coupons (code, discount_krw, min_subtotal_krw, expires_at)"
                " VALUES (%s, %s, %s, now() + %s::interval) ON CONFLICT (code) DO NOTHING",
                (code, discount, minimum, ttl),
            )
        print(f"catalog: {len(PRODUCTS)} products, {len(COUPONS)} coupons")
        if not args.customer_email:
            return 0
        user = conn.execute(
            "SELECT id FROM commerce.users WHERE login_email = %s AND role = 'customer'",
            (args.customer_email.strip().lower(),),
        ).fetchone()
        if user is None:
            print("customer not found (register it first)", file=sys.stderr)
            return 1
        user_id = user[0]
        conn.execute(
            "INSERT INTO commerce.user_coupons (user_id, coupon_id) SELECT %s, id FROM commerce.coupons"
            " ON CONFLICT (user_id, coupon_id) DO NOTHING",
            (user_id,),
        )
        history = [
            ("delivered", "40 days", [("GF-TOP-001", 1), ("GF-ACC-001", 2)]),
            ("shipped", "2 days", [("GF-SHO-001", 1)]),
            ("confirmed", "3 hours", [("GF-BTM-001", 1), ("GF-ELC-001", 1)]),
        ]
        for status, ago, lines in history:
            order_id = uuid.uuid4()
            items = [
                (
                    conn.execute("SELECT id, name, price_krw FROM commerce.products WHERE sku = %s", (sku,)).fetchone(),
                    qty,
                )
                for sku, qty in lines
            ]
            total = sum(p[2] * q for p, q in items)
            conn.execute(
                "INSERT INTO commerce.orders (id, user_id, external_ref, status, total_krw, placed_at)"
                " VALUES (%s, %s, %s, %s, %s, now() - %s::interval)",
                (order_id, user_id, f"ORD-SYN-{uuid.uuid4().hex[:8].upper()}", status, total, ago),
            )
            for (pid, pname, price), qty in items:
                conn.execute(
                    "INSERT INTO commerce.order_items (order_id, product_id, product_name, unit_price_krw, quantity)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (order_id, pid, pname, price, qty),
                )
        print(f"customer {args.customer_email}: {len(history)} synthetic orders, coupons granted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
