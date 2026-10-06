"""SHOP-01~06 (DES-005 §2.3): catalog, own orders, own cart and coupons. Same fixed DAO as the tools.

Lists use limit only for now (`next_cursor` is always null); signed cursors arrive with the web UI.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from app.api.auth import ok
from app.errors import ApiError
from app.security.auth import AuthContext, authenticate, require_scope
from app.shop import dao

router = APIRouter(prefix="/api/v1", tags=["shop"])


async def shop_reader(request: Request) -> AuthContext:
    ctx = await authenticate(request)
    if ctx.role != "customer":
        raise ApiError(403, "FORBIDDEN")
    if ctx.kind == "client_token":
        require_scope(ctx, "shop:read")
    return ctx


Reader = Annotated[AuthContext, Depends(shop_reader)]


@router.get("/products")
async def products(
    request: Request,
    ctx: Reader,
    q: Annotated[str, Query(max_length=100)] = "",
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> JSONResponse:
    async with request.app.state.pools.chat.connection() as conn:
        items = await dao.search_products(conn, q.strip(), limit)
    return ok(request, {"items": items, "next_cursor": None})


@router.get("/products/{product_id}")
async def product(request: Request, product_id: uuid.UUID, ctx: Reader) -> JSONResponse:
    async with request.app.state.pools.chat.connection() as conn:
        row = await (
            await conn.execute(
                "SELECT id, sku, name, description, price_krw, stock_count FROM commerce.products"
                " WHERE id = %s AND is_active",
                (product_id,),
            )
        ).fetchone()
    if row is None:
        raise ApiError(404, "NOT_FOUND")
    return ok(request, {**row, "id": str(row["id"])})


@router.get("/orders")
async def orders(request: Request, ctx: Reader, limit: Annotated[int, Query(ge=1, le=100)] = 20) -> JSONResponse:
    async with request.app.state.pools.chat.connection() as conn:
        items = await dao.list_orders(conn, ctx.user_id, limit)
    return ok(request, {"items": items, "next_cursor": None})


@router.get("/orders/{order_id}")
async def order(request: Request, order_id: uuid.UUID, ctx: Reader) -> JSONResponse:
    async with request.app.state.pools.chat.connection() as conn:
        found = await dao.get_order(conn, ctx.user_id, order_id)
    if found is None:
        raise ApiError(404, "NOT_FOUND")  # missing and not-owned look the same
    return ok(request, found)


@router.get("/cart")
async def cart(request: Request, ctx: Reader) -> JSONResponse:
    async with request.app.state.pools.chat.connection() as conn:
        found = await dao.get_cart(conn, ctx.user_id)
    if found is None:
        raise ApiError(404, "NOT_FOUND")
    return ok(request, found)


@router.get("/coupons")
async def coupons(request: Request, ctx: Reader) -> JSONResponse:
    async with request.app.state.pools.chat.connection() as conn:
        items = await dao.list_coupons(conn, ctx.user_id)
    return ok(request, {"items": items, "next_cursor": None})
