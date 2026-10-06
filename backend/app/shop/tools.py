"""ToolRegistry (DES-006 §5.1): the only functions the model can ask for.

Schemas are strict (no extra fields, no bool-as-int, no user_id/sql/url/price arguments). Results are
minimal JSON. Change tools (cart/coupon) are added with the confirmation flow in the next stage; until
then a proposal for them is simply an unknown tool.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Any

from psycopg import AsyncConnection
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StringConstraints, ValidationError

from app.shop import dao


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SearchProductsArgs(_Args):
    q: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
    limit: Annotated[StrictInt, Field(ge=1, le=20)] = 10


class GetOrderArgs(_Args):
    order_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F-]{36}$")]


class NoArgs(_Args):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args_model: type[_Args]
    scope: str  # client-token scope that must be present
    run: Callable[[AsyncConnection, uuid.UUID, Any], Awaitable[Any]]
    requires_confirmation: bool = False

    def schema(self) -> dict:
        params = self.args_model.model_json_schema()
        params.pop("title", None)
        for prop in params.get("properties", {}).values():
            prop.pop("title", None)
        params["additionalProperties"] = False
        return {
            "type": "function",
            "function": {"name": self.name, "description": self.description, "parameters": params},
        }


class ObjectNotFound(Exception):
    """Missing or not owned by the caller; never distinguished (DES-006 §5.2)."""


async def _search(conn, user_id, args: SearchProductsArgs):
    return {"products": await dao.search_products(conn, args.q, args.limit)}


async def _get_order(conn, user_id, args: GetOrderArgs):
    try:
        order_id = uuid.UUID(args.order_id)
    except ValueError as exc:
        raise ObjectNotFound from exc
    order = await dao.get_order(conn, user_id, order_id)
    if order is None:
        raise ObjectNotFound
    return {"order": order}


async def _list_orders(conn, user_id, args: NoArgs):
    return {"orders": await dao.list_orders(conn, user_id)}


async def _get_cart(conn, user_id, args: NoArgs):
    cart = await dao.get_cart(conn, user_id)
    if cart is None:
        raise ObjectNotFound
    return {"cart": cart}


async def _list_coupons(conn, user_id, args: NoArgs):
    return {"coupons": await dao.list_coupons(conn, user_id)}


READ_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("search_products", "Search active products by name or SKU. Returns id, name, price_krw, stock_count.",
             SearchProductsArgs, "shop:read", _search),
    ToolSpec("list_orders", "List the current customer's recent orders (status, total, date).",
             NoArgs, "shop:read", _list_orders),
    ToolSpec("get_order", "Get one of the current customer's orders with its items, by order id (UUID).",
             GetOrderArgs, "shop:read", _get_order),
    ToolSpec("get_cart", "Get the current customer's cart: items, applied coupon and amounts in KRW.",
             NoArgs, "shop:read", _get_cart),
    ToolSpec("list_coupons", "List the current customer's coupons with eligibility for the current cart.",
             NoArgs, "shop:read", _list_coupons),
)  # fmt: skip

REGISTRY: dict[str, ToolSpec] = {t.name: t for t in READ_TOOLS}


def parse_args(spec: ToolSpec, raw: Any) -> _Args:
    """Raises ValueError for anything that is not exactly the declared schema."""
    if not isinstance(raw, dict):
        raise ValueError("arguments must be an object")
    try:
        return spec.args_model.model_validate(raw)
    except ValidationError as exc:
        raise ValueError("invalid arguments") from exc
