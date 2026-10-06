"""Cart/coupon change proposals and confirmation (DES-002 §6, DES-006 §5.3, ACTION-01~04).

A proposal stores a frozen intent (tool, arguments, target cart, base cart version, argument hash)
and a server-computed preview. Nothing in the cart changes until the owner confirms with an
Idempotency-Key. Confirmation locks action then cart (always in that order) in a REPEATABLE READ
transaction, re-checks ownership, expiry, hash, cart version and the preview prices, applies the fixed
SQL change and commits it together with the audit outbox event. A retried confirm of an executed action
returns the stored result without changing the cart again.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from psycopg import AsyncConnection
from psycopg.errors import SerializationFailure
from psycopg.rows import dict_row, tuple_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from app.audit.outbox import AuditEnvelope, Source, ToolExecution, persist_event
from app.shop import dao
from app.shop.tools import CHANGE_TOOLS, parse_args

PREVIEW_COMPARE_KEYS = ("product", "quantity_before", "coupon", "subtotal_after", "discount_after", "total_after")


class ActionInvalid(Exception):
    """The change cannot apply (fixed reason code), e.g. PRODUCT_UNAVAILABLE, MIN_SUBTOTAL_NOT_MET."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ActionNotFound(Exception):
    pass


class ActionStale(Exception):
    pass


class ActionTerminal(Exception):
    pass


class ActionExpired(Exception):
    pass


class IdempotencyConflict(Exception):
    pass


@dataclass(frozen=True)
class Proposal:
    tool_name: str
    arguments: dict[str, Any]
    cart_id: uuid.UUID
    base_version: int
    preview: dict[str, Any]


def arguments_hash(tool_name: str, target_id: uuid.UUID, user_id: uuid.UUID, base_version: int, arguments: dict) -> str:
    canonical = json.dumps(
        {"tool_name": tool_name, "target_id": str(target_id), "user_id": str(user_id), "base_version": base_version,
         "arguments": arguments},
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )  # fmt: skip
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _args_dict(args: BaseModel) -> dict[str, Any]:
    return args.model_dump(mode="json")


async def _coupon_row(conn: AsyncConnection, user_id: uuid.UUID, user_coupon_id: str | uuid.UUID) -> dict | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT uc.id, uc.state, c.code, c.discount_krw, c.min_subtotal_krw, c.expires_at, c.is_active"
            " FROM commerce.user_coupons uc JOIN commerce.coupons c ON c.id = uc.coupon_id"
            " WHERE uc.id = %s AND uc.user_id = %s",
            (user_coupon_id, user_id),
        )
        return await cur.fetchone()


async def _product_row(conn: AsyncConnection, product_id: str | uuid.UUID) -> dict | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT id, name, price_krw, stock_count, is_active FROM commerce.products WHERE id = %s", (product_id,)
        )
        return await cur.fetchone()


async def _now(conn: AsyncConnection):
    async with conn.cursor(row_factory=tuple_row) as cur:  # independent of the pool's dict row factory
        await cur.execute("SELECT now()")
        return (await cur.fetchone())[0]


async def build_proposal(conn: AsyncConnection, user_id: uuid.UUID, tool_name: str, raw_arguments: Any) -> Proposal:
    """Validate arguments and compute the server preview from current DB values (no writes)."""
    spec = CHANGE_TOOLS.get(tool_name)
    if spec is None:
        raise ActionInvalid("UNKNOWN_TOOL")
    try:
        args = parse_args(spec, raw_arguments)
    except ValueError as exc:
        raise ActionInvalid("INVALID_ARGUMENTS") from exc
    arguments = _args_dict(args)
    cart = await dao.get_cart(conn, user_id)
    if cart is None:
        raise ActionInvalid("CART_NOT_FOUND")
    items = {i["product_id"]: dict(i) for i in cart["items"]}
    now = await _now(conn)
    applied = await _coupon_row(conn, user_id, cart["coupon"]["id"]) if cart["coupon"] else None
    preview: dict[str, Any] = {"tool": tool_name, "product": None, "quantity_before": None, "quantity_after": None,
                               "coupon": None, "notes": []}  # fmt: skip

    if tool_name in ("set_cart_item", "remove_cart_item"):
        product = await _product_row(conn, arguments["product_id"])
        if product is None or not product["is_active"]:
            raise ActionInvalid("PRODUCT_UNAVAILABLE")
        key = str(product["id"])
        before = items[key]["quantity"] if key in items else 0
        if tool_name == "set_cart_item":
            after = arguments["quantity"]
            if product["stock_count"] < after:
                raise ActionInvalid("OUT_OF_STOCK")
        else:
            if before == 0:
                raise ActionInvalid("NOT_IN_CART")
            after = 0
        preview.update(
            product={"id": key, "name": product["name"], "price_krw": product["price_krw"]},
            quantity_before=before,
            quantity_after=after,
        )
        if after:
            items[key] = {"product_id": key, "price_krw": product["price_krw"], "quantity": after, "available": True}
        else:
            items.pop(key, None)
    elif tool_name == "apply_coupon":
        applied = await _coupon_row(conn, user_id, arguments["user_coupon_id"])
        if applied is None:
            raise ActionInvalid("COUPON_NOT_AVAILABLE")  # missing and not-owned look the same
    elif tool_name == "remove_coupon":
        if cart["coupon"] is None:
            raise ActionInvalid("NO_COUPON_APPLIED")
        applied = None

    subtotal = sum(i["price_krw"] * i["quantity"] for i in items.values())
    discount, reason = dao._coupon_effect(applied, subtotal, now)
    if tool_name == "apply_coupon" and reason is not None:
        raise ActionInvalid(reason)
    if applied is not None and reason is not None:
        preview["notes"].append("COUPON_WILL_BE_REMOVED:" + reason)  # e.g. quantity change drops below minimum
        applied, discount = None, 0
    preview.update(
        coupon=None
        if applied is None
        else {"id": str(applied["id"]), "code": applied["code"], "discount_krw": discount},
        subtotal_before=cart["subtotal_krw"],
        discount_before=cart["discount_krw"],
        total_before=cart["total_krw"],
        subtotal_after=subtotal,
        discount_after=discount,
        total_after=subtotal - discount,
    )
    return Proposal(tool_name, arguments, uuid.UUID(cart["cart_id"]), cart["version"], preview)


def _envelope(
    *, request_id: str, actor: uuid.UUID, session_id: uuid.UUID | None, source: Source, api_path: str, status: str,
    stage: str | None, summary: str, tool: ToolExecution | None, ruleset_version: uuid.UUID | None = None,
) -> AuditEnvelope:  # fmt: skip
    return AuditEnvelope(
        request_id=uuid.UUID(request_id), actor_id=actor, session_id=session_id, source=source, api_path=api_path,
        status=status, stage=stage, ruleset_version=ruleset_version, summary_redacted=summary,
        tool_executions=(tool,) if tool else (),
    )  # fmt: skip


async def insert_proposal(
    conn: AsyncConnection, *, proposal: Proposal, user_id: uuid.UUID, session_id: uuid.UUID | None, request_id: str,
    ruleset_version: uuid.UUID, ttl_seconds: int,
) -> dict:  # fmt: skip
    """Insert the pending action inside the caller's transaction (the caller adds the outbox event)."""
    digest = arguments_hash(proposal.tool_name, proposal.cart_id, user_id, proposal.base_version, proposal.arguments)
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "INSERT INTO commerce.actions (request_id, user_id, session_id, tool_name, target_id, arguments,"
            " arguments_hash, base_version, ruleset_version, expires_at, result)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now() + make_interval(secs => %s), %s)"
            " RETURNING id, expires_at",
            (request_id, user_id, session_id, proposal.tool_name, proposal.cart_id, Jsonb(proposal.arguments), digest,
             proposal.base_version, ruleset_version, ttl_seconds, Jsonb({"preview": proposal.preview})),
        )  # fmt: skip
        return await cur.fetchone()


async def propose(
    conn: AsyncConnection, *, user_id: uuid.UUID, tool_name: str, raw_arguments: Any, base_version: int,
    session_id: uuid.UUID | None, request_id: str, source: Source, ruleset_version: uuid.UUID, ttl_seconds: int,
) -> tuple[dict, Proposal]:  # fmt: skip
    """ACTION-01: one transaction with the pending action and its confirmation_required outbox event."""
    async with conn.transaction():
        proposal = await build_proposal(conn, user_id, tool_name, raw_arguments)
        if proposal.base_version != base_version:
            raise ActionStale
        row = await insert_proposal(
            conn, proposal=proposal, user_id=user_id, session_id=session_id, request_id=request_id,
            ruleset_version=ruleset_version, ttl_seconds=ttl_seconds,
        )  # fmt: skip
        await persist_event(conn, _envelope(
            request_id=request_id, actor=user_id, session_id=session_id, source=source, api_path="/api/v1/actions",
            status="confirmation_required", stage=None, summary=f"변경 제안 대기: {tool_name}",
            tool=ToolExecution(action_id=row["id"], tool_name=tool_name, outcome="proposed", target_id=proposal.cart_id,
                               duration_ms=0),
            ruleset_version=ruleset_version,
        ))  # fmt: skip
    return row, proposal


def view(row: dict, now) -> dict:
    state = row["state"]
    if state == "pending" and row["expires_at"] <= now:
        state = "expired"  # the expiry batch may not have run yet; the server clock decides
    result = row["result"] or {}
    return {
        "action_id": str(row["id"]),
        "state": state,
        "tool_name": row["tool_name"],
        "expires_at": row["expires_at"].isoformat(),
        "preview": result.get("preview"),
        "result": result.get("executed") if row["state"] == "executed" else None,
    }


async def get(conn: AsyncConnection, user_id: uuid.UUID, action_id: uuid.UUID) -> dict:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT id, state, tool_name, expires_at, result, now() AS db_now FROM commerce.actions"
            " WHERE id = %s AND user_id = %s",
            (action_id, user_id),
        )
        row = await cur.fetchone()
    if row is None:
        raise ActionNotFound
    return view(row, row["db_now"])


async def _terminal_update(conn, action_id: uuid.UUID, state: str) -> None:
    await conn.execute("UPDATE commerce.actions SET state = %s, resolved_at = now() WHERE id = %s", (state, action_id))


async def confirm(
    conn: AsyncConnection, *, user_id: uuid.UUID, action_id: uuid.UUID, idempotency_key: str, request_id: str,
    ruleset_version: uuid.UUID | None,
) -> dict:  # fmt: skip
    """ACTION-03. Raises ActionNotFound/Expired/Terminal/Stale/IdempotencyConflict. A failure that changes
    the action state (expired/failed) is committed with its outbox event first, then raised."""
    try:
        result, failure = await _confirm_tx(conn, user_id, action_id, idempotency_key, request_id, ruleset_version)
    except SerializationFailure as exc:
        raise ActionStale from exc
    if failure is not None:
        raise failure
    return result


async def _confirm_tx(conn, user_id, action_id, idempotency_key, request_id, ruleset_version):
    api_path = f"/api/v1/actions/{action_id}/confirm"
    async with conn.transaction():
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT *, now() AS db_now FROM commerce.actions WHERE id = %s AND user_id = %s FOR UPDATE",
                (action_id, user_id),
            )
            action = await cur.fetchone()
            if action is None:
                raise ActionNotFound
            if action["state"] == "executed":
                return view(action, action["db_now"]), None  # replay: stored result, no second change
            await cur.execute(
                "SELECT 1 FROM commerce.actions WHERE user_id = %s AND idempotency_key = %s AND id <> %s",
                (user_id, idempotency_key, action_id),
            )
            if await cur.fetchone():
                raise IdempotencyConflict
            if action["state"] != "pending":
                raise ActionExpired if action["state"] == "expired" else ActionTerminal

            def event(status: str, summary: str, outcome: str) -> AuditEnvelope:
                return _envelope(
                    request_id=request_id, actor=user_id, session_id=action["session_id"], source="web",
                    api_path=api_path, status=status, stage=None, summary=summary,
                    tool=ToolExecution(action_id=action_id, tool_name=action["tool_name"], outcome=outcome,
                                       target_id=action["target_id"], duration_ms=0),
                    ruleset_version=ruleset_version,
                )  # fmt: skip

            if action["expires_at"] <= action["db_now"]:
                await _terminal_update(conn, action_id, "expired")
                await persist_event(conn, event("error", "변경 확인 만료", "denied"))
                return None, ActionExpired
            digest = arguments_hash(
                action["tool_name"], action["target_id"], user_id, action["base_version"], action["arguments"]
            )
            await cur.execute(
                "SELECT version FROM commerce.carts WHERE id = %s AND user_id = %s FOR UPDATE",
                (action["target_id"], user_id),
            )
            cart = await cur.fetchone()
            current = None
            if digest == action["arguments_hash"] and cart is not None and cart["version"] == action["base_version"]:
                try:
                    current = await build_proposal(conn, user_id, action["tool_name"], action["arguments"])
                except ActionInvalid:
                    current = None
                stored = action["result"]["preview"]
                if current is not None and any(current.preview.get(k) != stored.get(k) for k in PREVIEW_COMPARE_KEYS):
                    current = None  # price, stock-driven validity or coupon terms changed since the preview
            if current is None:
                await _terminal_update(conn, action_id, "failed")
                await persist_event(conn, event("error", "변경 확인 실패: 장바구니·가격 변경", "denied"))
                return None, ActionStale

            executed = await _apply(conn, user_id, action, current.preview)
            await cur.execute(
                "UPDATE commerce.actions SET state = 'executed', resolved_at = now(), idempotency_key = %s,"
                " result = %s WHERE id = %s RETURNING *, now() AS db_now",
                (idempotency_key, Jsonb({"preview": action["result"]["preview"], "executed": executed}), action_id),
            )
            done = await cur.fetchone()
            await persist_event(conn, event("success", f"변경 실행: {action['tool_name']}", "executed"))
            return view(done, done["db_now"]), None


async def _apply(conn: AsyncConnection, user_id: uuid.UUID, action: dict, preview: dict) -> dict:
    """Fixed SQL for the four change tools; the cart version always increases by exactly one."""
    cart_id, args, tool = action["target_id"], action["arguments"], action["tool_name"]
    if tool == "set_cart_item":
        await conn.execute(
            "INSERT INTO commerce.cart_items (cart_id, product_id, quantity) VALUES (%s, %s, %s)"
            " ON CONFLICT (cart_id, product_id) DO UPDATE SET quantity = EXCLUDED.quantity",
            (cart_id, args["product_id"], args["quantity"]),
        )
    elif tool == "remove_cart_item":
        await conn.execute(
            "DELETE FROM commerce.cart_items WHERE cart_id = %s AND product_id = %s", (cart_id, args["product_id"])
        )
    coupon_id = preview["coupon"]["id"] if preview["coupon"] else None
    await conn.execute(
        "UPDATE commerce.carts SET applied_coupon_id = %s, version = version + 1, updated_at = now()"
        " WHERE id = %s AND user_id = %s",
        (coupon_id, cart_id, user_id),
    )
    cart = await dao.get_cart(conn, user_id)
    return {"cart_version": cart["version"], "subtotal_krw": cart["subtotal_krw"], "discount_krw": cart["discount_krw"],
            "total_krw": cart["total_krw"], "notes": preview.get("notes", [])}  # fmt: skip


async def cancel(conn: AsyncConnection, *, user_id: uuid.UUID, action_id: uuid.UUID, request_id: str) -> dict:
    """ACTION-04: only the owner's pending action; repeating a cancel returns the same state."""
    async with conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT *, now() AS db_now FROM commerce.actions WHERE id = %s AND user_id = %s FOR UPDATE",
            (action_id, user_id),
        )
        action = await cur.fetchone()
        if action is None:
            raise ActionNotFound
        if action["state"] == "cancelled":
            return view(action, action["db_now"])
        if action["state"] != "pending":
            raise ActionTerminal
        await cur.execute(
            "UPDATE commerce.actions SET state = 'cancelled', resolved_at = now() WHERE id = %s RETURNING *,"
            " now() AS db_now",
            (action_id,),
        )
        done = await cur.fetchone()
        await persist_event(conn, _envelope(
            request_id=request_id, actor=user_id, session_id=action["session_id"], source="web",
            api_path=f"/api/v1/actions/{action_id}/cancel", status="success", stage=None,
            summary=f"변경 제안 취소: {action['tool_name']}",
            tool=ToolExecution(action_id=action_id, tool_name=action["tool_name"], outcome="denied",
                               target_id=action["target_id"], duration_ms=0),
        ))  # fmt: skip
        return view(done, done["db_now"])
