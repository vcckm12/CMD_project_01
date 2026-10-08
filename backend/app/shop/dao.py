"""Shop DAO: fixed, parameterized SQL only (DES-002 §7, DES-006 §5).

`user_id` always comes from the authenticated context and is part of every WHERE clause for owned
data. A missing row and another user's row look the same to callers (None), so existence is never
revealed. Results carry only the fields the assistant needs; no addresses, phones or e-mails.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from psycopg import AsyncConnection
from psycopg.rows import dict_row


def _like_escape(q: str) -> str:
    return q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def search_products(conn: AsyncConnection, q: str, limit: int) -> list[dict]:
    pattern = f"%{_like_escape(q)}%"
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT id, sku, name, price_krw, stock_count FROM commerce.products"
            " WHERE is_active AND (name ILIKE %s ESCAPE '\\' OR sku ILIKE %s ESCAPE '\\')"
            " ORDER BY name, id LIMIT %s",
            (pattern, pattern, limit),
        )
        return [
            {"id": str(r["id"]), "sku": r["sku"], "name": r["name"], "price_krw": r["price_krw"],
             "stock_count": r["stock_count"]}
            for r in await cur.fetchall()
        ]  # fmt: skip


async def get_order(conn: AsyncConnection, user_id: uuid.UUID, order_id: uuid.UUID) -> dict | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT id, external_ref, status, total_krw, placed_at FROM commerce.orders WHERE user_id = %s AND id = %s",
            (user_id, order_id),
        )
        order = await cur.fetchone()
        if order is None:
            return None
        await cur.execute(
            "SELECT product_id, product_name, quantity, unit_price_krw FROM commerce.order_items"
            " WHERE order_id = %s ORDER BY product_name",
            (order_id,),
        )
        items = await cur.fetchall()
    return {
        "id": str(order["id"]),
        "external_ref": order["external_ref"],
        "status": order["status"],
        "total_krw": order["total_krw"],
        "placed_at": order["placed_at"].isoformat(),
        "items": [
            {
                "product_id": str(i["product_id"]),
                "name": i["product_name"],
                "quantity": i["quantity"],
                "unit_price_krw": i["unit_price_krw"],
            }
            for i in items
        ],  # fmt: skip
    }


async def list_orders(conn: AsyncConnection, user_id: uuid.UUID, limit: int = 10) -> list[dict]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT id, external_ref, status, total_krw, placed_at FROM commerce.orders"
            " WHERE user_id = %s ORDER BY placed_at DESC, id LIMIT %s",
            (user_id, limit),
        )
        return [
            {"id": str(r["id"]), "external_ref": r["external_ref"], "status": r["status"],
             "total_krw": r["total_krw"], "placed_at": r["placed_at"].isoformat()}
            for r in await cur.fetchall()
        ]  # fmt: skip


def _coupon_effect(coupon: dict | None, subtotal: int, now: datetime) -> tuple[int, str | None]:
    """Discount actually applicable now, and the fixed reason when it is not (DES-002 §6 쿠폰)."""
    if coupon is None:
        return 0, None
    if not coupon["is_active"] or coupon["state"] != "available" or coupon["expires_at"] <= now:
        return 0, "COUPON_NOT_AVAILABLE"
    if subtotal < coupon["min_subtotal_krw"]:
        return 0, "MIN_SUBTOTAL_NOT_MET"
    return min(coupon["discount_krw"], subtotal), None


async def get_cart(conn: AsyncConnection, user_id: uuid.UUID) -> dict | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT c.id, c.version, c.applied_coupon_id, now() AS db_now FROM commerce.carts c WHERE c.user_id = %s",
            (user_id,),
        )
        cart = await cur.fetchone()
        if cart is None:
            return None
        await cur.execute(
            "SELECT p.id, p.sku, p.name, p.price_krw, p.stock_count, p.is_active, ci.quantity"
            " FROM commerce.cart_items ci JOIN commerce.products p ON p.id = ci.product_id"
            " WHERE ci.cart_id = %s ORDER BY p.name",
            (cart["id"],),
        )
        items = await cur.fetchall()
        coupon = None
        if cart["applied_coupon_id"] is not None:
            await cur.execute(
                "SELECT uc.id, uc.state, c.code, c.discount_krw, c.min_subtotal_krw, c.expires_at, c.is_active"
                " FROM commerce.user_coupons uc JOIN commerce.coupons c ON c.id = uc.coupon_id"
                " WHERE uc.id = %s AND uc.user_id = %s",
                (cart["applied_coupon_id"], user_id),
            )
            coupon = await cur.fetchone()
    subtotal = sum(i["price_krw"] * i["quantity"] for i in items if i["is_active"])
    discount, reason = _coupon_effect(coupon, subtotal, cart["db_now"])
    return {
        "cart_id": str(cart["id"]),
        "version": cart["version"],
        "items": [
            {
                "product_id": str(i["id"]),
                "sku": i["sku"],
                "name": i["name"],
                "price_krw": i["price_krw"],
                "quantity": i["quantity"],
                "available": bool(i["is_active"] and i["stock_count"] >= i["quantity"]),
            }
            for i in items
        ],  # fmt: skip
        "coupon": None if coupon is None else {"id": str(coupon["id"]), "code": coupon["code"], "reason": reason},
        "subtotal_krw": subtotal,
        "discount_krw": discount,
        "total_krw": subtotal - discount,
    }


async def list_coupons(conn: AsyncConnection, user_id: uuid.UUID) -> list[dict]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT now() AS db_now", ())
        now = (await cur.fetchone())["db_now"]
        cart = await get_cart(conn, user_id)
        subtotal = cart["subtotal_krw"] if cart else 0
        await cur.execute(
            "SELECT uc.id, uc.state, c.code, c.discount_krw, c.min_subtotal_krw, c.expires_at, c.is_active"
            " FROM commerce.user_coupons uc JOIN commerce.coupons c ON c.id = uc.coupon_id"
            " WHERE uc.user_id = %s ORDER BY c.expires_at, uc.id",
            (user_id,),
        )
        rows = await cur.fetchall()
    out = []
    for r in rows:
        _, reason = _coupon_effect(r, subtotal, now)
        out.append(
            {"id": str(r["id"]), "code": r["code"], "state": r["state"], "discount_krw": r["discount_krw"],
             "min_subtotal_krw": r["min_subtotal_krw"], "expires_at": r["expires_at"].isoformat(),
             "eligible": reason is None, "reason": reason}
        )  # fmt: skip
    return out
