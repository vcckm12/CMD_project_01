"""Customer web catalog (SHOP-01/02): display fields, detail page, order items carry the SKU for pictures."""

import uuid

from tests.conftest import bearer, register_and_login, superuser


def shopper(client) -> dict:
    _, data = register_and_login(client)
    return {"token": data["access_token"], "user_id": data["user"]["id"]}


def add_product(**fields) -> tuple[str, str]:
    sku = f"T-{uuid.uuid4().hex[:10]}"
    values = {"sku": sku, "name": "테스트 코트", "price_krw": 90000, "stock_count": 3, **fields}
    cols = ", ".join(values)
    marks = ", ".join(["%s"] * len(values))
    with superuser() as conn:
        pid = conn.execute(
            f"INSERT INTO commerce.products ({cols}) VALUES ({marks}) RETURNING id",  # noqa: S608 - test helper
            tuple(values.values()),
        ).fetchone()[0]
    return str(pid), sku


def test_catalog_lists_display_fields(client):
    s = shopper(client)
    pid, sku = add_product(brand="NORDLINE", color="카멜", sizes="S,M,L", material="울 50%", list_price_krw=120000,
                           rating=4.5, review_count=12, tags="new,sale")  # fmt: skip
    items = client.get(f"/api/v1/products?q={sku}", headers=bearer(s["token"])).json()["data"]["items"]
    assert items == [{
        "id": pid, "sku": sku, "name": "테스트 코트", "description": "", "price_krw": 90000, "list_price_krw": 120000,
        "stock_count": 3, "brand": "NORDLINE", "color": "카멜", "sizes": ["S", "M", "L"], "material": "울 50%",
        "rating": 4.5, "review_count": 12, "tags": ["new", "sale"],
    }]  # fmt: skip


def test_catalog_searches_brand_and_detail_hides_inactive(client):
    s = shopper(client)
    brand = f"BRAND{uuid.uuid4().hex[:6].upper()}"
    pid, _ = add_product(brand=brand)
    found = client.get(f"/api/v1/products?q={brand}", headers=bearer(s["token"])).json()["data"]["items"]
    assert [i["id"] for i in found] == [pid]
    detail = client.get(f"/api/v1/products/{pid}", headers=bearer(s["token"]))
    assert detail.status_code == 200 and detail.json()["data"]["brand"] == brand
    assert detail.json()["data"]["list_price_krw"] is None and detail.json()["data"]["rating"] is None
    with superuser() as conn:
        conn.execute("UPDATE commerce.products SET is_active = false WHERE id = %s", (pid,))
    assert client.get(f"/api/v1/products/{pid}", headers=bearer(s["token"])).status_code == 404


def test_order_detail_items_carry_sku(client):
    s = shopper(client)
    pid, sku = add_product()
    with superuser() as conn:
        oid = conn.execute(
            "INSERT INTO commerce.orders (user_id, external_ref, status, total_krw, placed_at)"
            " VALUES (%s, %s, 'shipped', 90000, now()) RETURNING id",
            (s["user_id"], f"ORD-T-{uuid.uuid4().hex[:8]}"),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO commerce.order_items (order_id, product_id, product_name, unit_price_krw, quantity)"
            " VALUES (%s, %s, '테스트 코트', 90000, 1)",
            (oid, pid),
        )
    order = client.get(f"/api/v1/orders/{oid}", headers=bearer(s["token"])).json()["data"]
    assert order["items"][0]["sku"] == sku


def test_assistant_tool_output_is_unchanged(client):
    """The search tool still returns only id, sku, name, price and stock (display fields stay out of the model)."""
    import asyncio
    import os

    import psycopg

    from app.shop import dao
    from tests.conftest import _dsn

    _, sku = add_product(brand="HIDDEN", description="긴 설명")

    async def run():
        dsn = _dsn("postgres", os.environ["TEST_SUPERUSER_PASSWORD"])
        async with await psycopg.AsyncConnection.connect(dsn) as conn:
            return await dao.search_products(conn, sku, 5)

    rows = asyncio.run(run())
    assert set(rows[0]) == {"id", "sku", "name", "price_krw", "stock_count"}
