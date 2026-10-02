"""Request authentication and authorization (DES-005 §1.1, D-17).

Identity, role and scopes always come from the verified token and the database row,
never from the body, client system messages, or X-* headers other than the edge channel.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Literal

from fastapi import Request

from app.audit.outbox import Source
from app.errors import ApiError
from app.security.tokens import CLIENT_TOKEN_PREFIX, TokenExpired, TokenInvalid, token_hash

Role = Literal["customer", "operator", "admin"]
DEFAULT_CLIENT_SCOPES: tuple[str, ...] = ("chat:write", "models:read", "tools:read", "shop:read", "actions:propose")


@dataclass(frozen=True)
class AuthContext:
    user_id: uuid.UUID
    role: Role
    kind: Literal["jwt", "client_token"]
    scopes: frozenset[str]
    channel: Literal["shop", "ops"]

    @property
    def source(self) -> Source:
        if self.kind == "client_token":
            return "anythingllm"
        return "web" if self.role == "customer" else "streamlit"


def channel_allows(role: str, kind: str, channel: str | None) -> bool:
    """Customers and client tokens only on shop; operator/admin only on ops."""
    if channel is None:
        return False
    if kind == "client_token" or role == "customer":
        return channel == "shop"
    return channel == "ops"


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 4096:
        raise ApiError(401, "AUTH_REQUIRED", {"WWW-Authenticate": "Bearer"})
    return token.strip()


async def authenticate(request: Request) -> AuthContext:
    token = _bearer(request)
    channel = request.state.channel
    if token.startswith(CLIENT_TOKEN_PREFIX):
        ctx = await _authenticate_client_token(request, token)
    else:
        ctx = await _authenticate_jwt(request, token)
    if not channel_allows(ctx.role, ctx.kind, channel):
        raise ApiError(403, "FORBIDDEN")
    request.state.auth = ctx
    return ctx


async def _authenticate_jwt(request: Request, token: str) -> AuthContext:
    signer = request.app.state.jwt_signer
    try:
        claims = signer.verify(token)
    except TokenExpired as exc:
        raise ApiError(401, "TOKEN_EXPIRED") from exc
    except TokenInvalid as exc:
        raise ApiError(401, "AUTH_REQUIRED") from exc
    async with request.app.state.pools.auth.connection() as conn:
        row = await (
            await conn.execute(
                "SELECT role, token_version, is_active FROM commerce.users WHERE id = %s", (claims.user_id,)
            )
        ).fetchone()
    if row is None or not row["is_active"]:
        raise ApiError(401, "TOKEN_REVOKED")
    if row["role"] != claims.role or row["token_version"] != claims.token_version:
        raise ApiError(401, "TOKEN_REVOKED")
    return AuthContext(
        user_id=claims.user_id,
        role=row["role"],
        kind="jwt",
        scopes=frozenset(DEFAULT_CLIENT_SCOPES) if row["role"] == "customer" else frozenset(),
        channel=request.state.channel,
    )


async def _authenticate_client_token(request: Request, token: str) -> AuthContext:
    async with request.app.state.pools.auth.connection() as conn:
        row = await (
            await conn.execute(
                "SELECT t.user_id, t.scopes, t.token_version AS issued_version, t.expires_at, t.revoked_at,"
                " u.role, u.token_version, u.is_active, now() AS db_now"
                " FROM commerce.client_tokens t JOIN commerce.users u ON u.id = t.user_id"
                " WHERE t.token_hash = %s",
                (token_hash(token),),
            )
        ).fetchone()
    if row is None:
        raise ApiError(401, "AUTH_REQUIRED")
    if row["revoked_at"] is not None or not row["is_active"] or row["issued_version"] != row["token_version"]:
        raise ApiError(401, "TOKEN_REVOKED")
    if row["expires_at"] <= row["db_now"]:
        raise ApiError(401, "TOKEN_EXPIRED")
    if row["role"] != "customer":
        raise ApiError(403, "FORBIDDEN")
    return AuthContext(
        user_id=row["user_id"],
        role="customer",
        kind="client_token",
        scopes=frozenset(row["scopes"]),
        channel=request.state.channel,
    )


async def require_customer_jwt(request: Request) -> AuthContext:
    """Account, token management, confirm: customer access JWT only, never a client token."""
    ctx = await authenticate(request)
    if ctx.kind != "jwt" or ctx.role != "customer":
        raise ApiError(403, "FORBIDDEN")
    return ctx


async def require_staff(request: Request) -> AuthContext:
    ctx = await authenticate(request)
    if ctx.kind != "jwt" or ctx.role not in ("operator", "admin"):
        raise ApiError(403, "FORBIDDEN")
    return ctx


async def require_admin(request: Request) -> AuthContext:
    ctx = await require_staff(request)
    if ctx.role != "admin":
        raise ApiError(403, "FORBIDDEN")
    return ctx


def require_scope(ctx: AuthContext, scope: str) -> None:
    if ctx.role != "customer" or scope not in ctx.scopes:
        raise ApiError(403, "FORBIDDEN")


class LoginRateLimiter:
    """In-memory failure counter; valid because FastAPI runs a single worker (DES-001 §2)."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._failures[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if not q:
            self._failures.pop(key, None)
        return q

    def check(self, *keys: str) -> None:
        now = time.monotonic()
        for key in keys:
            if len(self._prune(key, now)) >= self.limit:
                raise ApiError(429, "RATE_LIMITED", {"Retry-After": str(self.window)})

    def record_failure(self, *keys: str) -> None:
        now = time.monotonic()
        for key in keys:
            self._failures[key].append(now)

    def reset(self, *keys: str) -> None:
        for key in keys:
            self._failures.pop(key, None)
