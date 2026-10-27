"""Synthetic catalog, coupons and order history for development (DES-002 §8 초기 적재).

Runs as the migration owner (no app role may write products/orders/coupons):
    docker compose run --rm migrate python -m app.cli.seed --customer-email customer@example.invalid
Idempotent for the catalog (SKU upsert). Orders and coupons are added only for the given existing
customer account. All data is synthetic; never load real customer data with this command.
"""

# ruff: noqa: E501 - catalog rows are data; one product per entry reads better than wrapped strings
from __future__ import annotations

import argparse
import os
import sys
import uuid

import psycopg

# Synthetic catalog. Brands are fictional. Columns:
# sku, name, description, price, stock, brand, color, sizes, material, list price (None = no sale), rating, reviews, tags
PRODUCTS = [
    ("GF-TOP-001", "오버핏 후드티", "넉넉한 오버핏에 안쪽 기모를 더한 후드티. 캥거루 포켓과 두툼한 립 소매로 쌀쌀한 날에 단독으로 입기 좋습니다.",
     39000, 30, "GF STUDIO", "멜란지 그레이", "S,M,L,XL", "면 80% · 폴리에스터 20% (기모)", 49000, 4.6, 412, "best,sale"),
    ("GF-TOP-002", "베이직 맨투맨", "탄탄한 코튼 원단의 데일리 맨투맨. 어깨선이 살짝 내려간 세미 오버핏입니다.",
     29000, 25, "MORNING COTTON", "네이비", "S,M,L,XL", "면 100%", None, 4.4, 238, "best"),
    ("GF-TOP-003", "스트라이프 셔츠", "가는 블루 스트라이프의 봄가을용 셔츠. 단독으로도, 니트 안에 레이어드해도 좋습니다.",
     35000, 12, "URBAN TAILOR", "블루 스트라이프", "S,M,L", "면 100%", None, 4.3, 97, ""),
    ("GF-TOP-004", "케이블 니트 스웨터", "굵은 케이블 짜임의 라운드넥 스웨터. 포근한 두께감으로 한겨울까지 입을 수 있습니다.",
     59000, 14, "NORDLINE", "아이보리", "M,L,XL", "울 30% · 아크릴 70%", 79000, 4.7, 183, "new,sale"),
    ("GF-TOP-005", "옥스퍼드 버튼다운 셔츠", "도톰한 옥스퍼드 원단의 버튼다운 셔츠. 세탁할수록 자연스럽게 길이 듭니다.",
     45000, 20, "URBAN TAILOR", "화이트", "S,M,L,XL", "면 100% (옥스퍼드)", None, 4.5, 156, "best"),
    ("GF-TOP-006", "터틀넥 골지 티셔츠", "몸에 적당히 붙는 골지 터틀넥. 재킷이나 코트 안에 받쳐 입기 좋은 기본 아이템입니다.",
     25000, 35, "MORNING COTTON", "블랙", "S,M,L", "면 95% · 스판덱스 5%", None, 4.2, 74, "new"),
    ("GF-TOP-007", "린넨 블렌드 셔츠", "린넨과 면을 섞어 구김이 덜한 셔츠. 가볍고 통기성이 좋아 간절기에 편합니다.",
     49000, 8, "ATELIER 9", "베이지", "M,L", "린넨 55% · 면 45%", 65000, 4.1, 42, "sale"),
    ("GF-BTM-001", "와이드 슬랙스", "허리 밴딩으로 편한 와이드 실루엣 슬랙스. 앞주름이 있어 단정하게 떨어집니다.",
     42000, 18, "URBAN TAILOR", "차콜", "26,28,30,32,34", "폴리에스터 70% · 레이온 30%", None, 4.5, 301, "best"),
    ("GF-BTM-002", "스트레이트 데님", "적당히 워싱된 중청 스트레이트 데님. 살짝 늘어나는 원단이라 오래 앉아 있어도 편합니다.",
     49000, 9, "NORDLINE", "중청", "26,28,30,32,34", "면 98% · 스판덱스 2%", 59000, 4.4, 265, "sale"),
    ("GF-BTM-003", "코듀로이 팬츠", "골이 굵지 않은 코듀로이 팬츠. 가을·겨울 내내 따뜻하게 입을 수 있습니다.",
     45000, 16, "ATELIER 9", "브라운", "28,30,32,34", "면 100% (코듀로이)", None, 4.3, 61, "new"),
    ("GF-BTM-004", "카고 조거 팬츠", "포켓이 넉넉한 카고 조거 팬츠. 밑단 스트링으로 길이를 조절할 수 있습니다.",
     39000, 22, "GF STUDIO", "카키", "S,M,L,XL", "면 60% · 나일론 40%", None, 4.2, 88, ""),
    ("GF-BTM-005", "플리츠 미디 스커트", "움직일 때 자연스럽게 퍼지는 플리츠 미디 스커트. 허리 뒤쪽은 밴딩입니다.",
     52000, 10, "ATELIER 9", "블랙", "S,M", "폴리에스터 100%", 69000, 4.6, 129, "sale"),
    ("GF-OUT-001", "덕다운 패딩", "덕다운 80%를 충전한 숏패딩. 가볍지만 따뜻하고, 후드는 탈부착할 수 있습니다.",
     129000, 6, "NORDLINE", "블랙", "S,M,L,XL", "겉감 나일론 100% · 충전재 덕다운 80%", 169000, 4.8, 522, "best,sale"),
    ("GF-OUT-002", "울 블렌드 코트", "울 50% 원단의 싱글 코트. 무릎 위 길이로 어떤 하의와도 잘 어울립니다.",
     159000, 4, "ATELIER 9", "카멜", "S,M,L", "울 50% · 폴리에스터 50%", None, 4.7, 211, "best"),
    ("GF-OUT-003", "트렌치 코트", "클래식한 더블 브레스트 트렌치 코트. 허리 벨트로 실루엣을 조절할 수 있습니다.",
     139000, 7, "URBAN TAILOR", "베이지", "S,M,L", "면 65% · 폴리에스터 35%", 179000, 4.6, 147, "sale"),
    ("GF-OUT-004", "데님 트러커 재킷", "연청 워싱의 트러커 재킷. 후드티 위에 걸치기 좋은 넉넉한 품입니다.",
     69000, 12, "NORDLINE", "연청", "S,M,L,XL", "면 100%", None, 4.4, 93, "new"),
    ("GF-OUT-005", "플리스 집업", "부드러운 양털 느낌의 플리스 집업. 가볍고 보온성이 좋아 실내외 모두 입기 좋습니다.",
     49000, 25, "GF STUDIO", "아이보리", "S,M,L,XL", "폴리에스터 100% (플리스)", None, 4.5, 176, "new,best"),
    ("GF-OUT-006", "레더 라이더 재킷", "부드러운 양가죽 라이더 재킷. 비대칭 지퍼와 벨트 디테일이 들어갔습니다.",
     199000, 3, "ATELIER 9", "블랙", "M,L", "양가죽 100%", 249000, 4.8, 58, "sale"),
    ("GF-SHO-001", "베이직 스니커즈", "어디에나 어울리는 화이트 스니커즈. 쿠션 깔창으로 오래 걸어도 편합니다.",
     55000, 20, "STEP LAB", "화이트", "230,240,250,260,270,280", "인조가죽 · 고무 밑창", None, 4.5, 389, "best"),
    ("GF-SHO-002", "첼시 부츠", "옆면 밴딩으로 신고 벗기 쉬운 첼시 부츠. 미끄럼 방지 고무 밑창입니다.",
     89000, 9, "STEP LAB", "블랙", "230,240,250,260,270,280", "소가죽 · 고무 밑창", 109000, 4.6, 102, "new,sale"),
    ("GF-SHO-003", "러닝화", "통기성 좋은 메시 갑피의 데일리 러닝화. 가벼운 EVA 밑창을 썼습니다.",
     79000, 15, "STEP LAB", "그레이", "230,240,250,260,270,280,290", "메시 · EVA 밑창", None, 4.4, 134, ""),
    ("GF-SHO-004", "페니 로퍼", "은은한 광택의 브라운 페니 로퍼. 슬랙스와 데님 모두에 잘 어울립니다.",
     69000, 11, "ATELIER 9", "브라운", "230,240,250,260,270", "소가죽", None, 4.3, 49, "new"),
    ("GF-ACC-001", "미니멀 볼캡", "로고 없이 깔끔한 코튼 볼캡. 뒤쪽 버클로 사이즈를 조절합니다.",
     19000, 40, "GF STUDIO", "베이지", "FREE", "면 100%", None, 4.3, 211, ""),
    ("GF-ACC-002", "캔버스 토트백", "A4 서류와 노트북이 들어가는 캔버스 토트백. 안쪽에 작은 포켓이 있습니다.",
     25000, 15, "MORNING COTTON", "내추럴", "FREE", "면 캔버스", None, 4.4, 167, "best"),
    ("GF-ACC-003", "레더 벨트", "소가죽 한 장으로 만든 클래식 벨트. 길이 조절 구멍이 5개 있습니다.",
     25000, 50, "URBAN TAILOR", "브라운", "95,105,115", "소가죽", 32000, 4.5, 143, "sale"),
    ("GF-ACC-004", "캐시미어 머플러", "캐시미어를 섞어 부드럽고 따뜻한 머플러. 어느 코트에나 잘 어울리는 그레이입니다.",
     89000, 0, "NORDLINE", "그레이", "FREE", "캐시미어 30% · 울 70%", None, 4.8, 76, ""),
    ("GF-ACC-005", "가죽 카드지갑", "카드 6장과 지폐가 들어가는 얇은 소가죽 카드지갑입니다.",
     35000, 30, "URBAN TAILOR", "블랙", "FREE", "소가죽", None, 4.6, 95, "new"),
    ("GF-ACC-006", "울 비니", "도톰한 골지 짜임의 울 비니. 접어서 길이를 조절할 수 있습니다.",
     22000, 28, "NORDLINE", "차콜", "FREE", "울 50% · 아크릴 50%", 29000, 4.4, 64, "new,sale"),
    ("GF-ACC-007", "미니 크로스백", "휴대폰과 지갑이 들어가는 작은 나일론 크로스백. 끈 길이를 조절할 수 있습니다.",
     59000, 13, "ATELIER 9", "블랙", "FREE", "나일론 · 가죽 트림", None, 4.5, 81, ""),
    ("GF-ACC-008", "실버 체인 목걸이", "얇고 반짝이는 925 실버 체인 목걸이. 길이 45cm입니다.",
     39000, 18, "GF STUDIO", "실버", "FREE", "925 실버", None, 4.2, 37, "new"),
]
RETIRED = ("GF-ELC-001", "GF-ELC-002")  # earlier non-fashion items: hidden, kept for existing orders
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
        for sku, name, desc, price, stock, brand, color, sizes, material, list_price, rating, reviews, tags in PRODUCTS:
            conn.execute(
                "INSERT INTO commerce.products (sku, name, description, price_krw, stock_count, brand, color, sizes,"
                " material, list_price_krw, rating, review_count, tags)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (sku) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,"
                " price_krw = EXCLUDED.price_krw, stock_count = EXCLUDED.stock_count, brand = EXCLUDED.brand,"
                " color = EXCLUDED.color, sizes = EXCLUDED.sizes, material = EXCLUDED.material,"
                " list_price_krw = EXCLUDED.list_price_krw, rating = EXCLUDED.rating,"
                " review_count = EXCLUDED.review_count, tags = EXCLUDED.tags",
                (sku, name, desc, price, stock, brand, color, sizes, material, list_price, rating, reviews, tags),
            )
        conn.execute("UPDATE commerce.products SET is_active = false WHERE sku = ANY(%s)", (list(RETIRED),))
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
            ("confirmed", "3 hours", [("GF-BTM-001", 1), ("GF-ACC-003", 1)]),
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
