"""AUTH-01~07 (DES-005 §2.1). Every account/token change commits with its outbox event."""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from psycopg import AsyncConnection
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.audit.outbox import AuditEnvelope, Source, elapsed_ms, persist_event
from app.errors import ApiError
from app.security import passwords
from app.security.auth import (
    DEFAULT_CLIENT_SCOPES,
    AuthContext,
    authenticate,
    channel_allows,
    require_customer_jwt,
)
from app.security.tokens import CLIENT_TOKEN_PREFIX, new_opaque_token, token_hash

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

REFRESH_COOKIE = "guardrail_refresh"
CSRF_COOKIE = "guardrail_csrf"
CSRF_HEADER = "x-csrf-token"
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


def normalize_email(value: str) -> str:
    value = value.strip().lower()
    if len(value) > 254 or not EMAIL_RE.match(value):
        raise ValueError("invalid email")
    return value


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    password: str = Field(min_length=1, max_length=passwords.MAX_LENGTH)

    _normalize = field_validator("email")(normalize_email)


class Registration(Credentials):
    password: str = Field(min_length=passwords.MIN_LENGTH, max_length=passwords.MAX_LENGTH)


class ClientTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]
    scopes: list[str] = Field(default_factory=lambda: list(DEFAULT_CLIENT_SCOPES), min_length=1, max_length=5)

    @field_validator("scopes")
    @classmethod
    def _allowed_scopes(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or not set(value) <= set(DEFAULT_CLIENT_SCOPES):
            raise ValueError("unsupported scope")
        return value


def ok(request: Request, data: object, status: int = 200) -> JSONResponse:
    return JSONResponse({"request_id": request.state.request_id, "data": data}, status_code=status)


async def record(
    conn: AsyncConnection, request: Request, actor_id: uuid.UUID | None, source: Source, summary: str
) -> None:
    await persist_event(
        conn,
        AuditEnvelope(
            request_id=uuid.UUID(request.state.request_id),
            actor_id=actor_id,
            source=source,
            api_path=request.url.path,
            status="success",
            total_ms=elapsed_ms(request.state.started),
            summary_redacted=summary,
        ),
    )


def staff_or_web(role: str) -> Source:
    return "web" if role == "customer" else "streamlit"


def client_ip(request: Request) -> str:
    # Nginx sets X-Real-IP on the shop/ops edge; direct internal callers fall back to the socket peer.
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")


def set_session_cookies(response: Response, request: Request, refresh_token: str, csrf_token: str) -> None:
    settings = request.app.state.settings
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        max_age=settings.refresh_token_ttl_seconds,
        path="/api/v1/auth",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    # Readable by the page so it can send X-CSRF-Token after a reload (double-submit).
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=settings.refresh_token_ttl_seconds,
        path="/",
        secure=True,
        httponly=False,
        samesite="strict",
    )


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth", secure=True, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=True, samesite="strict")


def check_cookie_request(request: Request) -> None:
    """Cookie-authenticated calls need the channel's exact Origin and a matching CSRF pair."""
    settings = request.app.state.settings
    expected_origin = {"shop": settings.shop_origin, "ops": settings.ops_origin}.get(request.state.channel)
    if expected_origin is None or request.headers.get("origin") != expected_origin:
        raise ApiError(403, "FORBIDDEN")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get(CSRF_HEADER, "")
    if not cookie or not secrets.compare_digest(cookie, header):
        raise ApiError(403, "FORBIDDEN")


def user_view(user_id: uuid.UUID, email: str, role: str) -> dict[str, str]:
    return {"id": str(user_id), "email": email, "role": role}


async def issue_session(
    conn: AsyncConnection, request: Request, user_id: uuid.UUID, role: str, token_version: int, family_id: uuid.UUID
) -> tuple[str, str, str]:
    settings = request.app.state.settings
    refresh = new_opaque_token()
    await conn.execute(
        "INSERT INTO commerce.refresh_tokens (user_id, token_hash, family_id, expires_at)"
        " VALUES (%s, %s, %s, now() + make_interval(secs => %s))",
        (user_id, token_hash(refresh), family_id, settings.refresh_token_ttl_seconds),
    )
    access = request.app.state.jwt_signer.issue(user_id, role, token_version)
    return access, refresh, new_opaque_token()


@router.post("/register", status_code=201)
async def register(request: Request, body: Registration) -> JSONResponse:
    if request.state.channel != "shop":
        raise ApiError(404, "NOT_FOUND")
    password_hash = await passwords.hash_password(body.password)
    async with request.app.state.pools.auth.connection() as conn, conn.transaction():
        try:
            async with conn.transaction():
                row = await (
                    await conn.execute(
                        "INSERT INTO commerce.users (login_email, password_hash, role) VALUES (%s, %s, 'customer')"
                        " RETURNING id",
                        (body.email, password_hash),
                    )
                ).fetchone()
        except UniqueViolation as exc:
            raise ApiError(409, "EMAIL_UNAVAILABLE") from exc
        await conn.execute("INSERT INTO commerce.carts (user_id) VALUES (%s)", (row["id"],))
        await record(conn, request, row["id"], "web", "고객 계정 생성")
    return ok(request, {"user": user_view(row["id"], body.email, "customer")}, 201)


@router.post("/login")
async def login(request: Request, body: Credentials) -> JSONResponse:
    limiter = request.app.state.login_limiter
    keys = (f"ip:{client_ip(request)}", f"email:{body.email}")
    limiter.check(*keys)
    async with request.app.state.pools.auth.connection() as conn:
        user = await (
            await conn.execute(
                "SELECT id, password_hash, role, token_version, is_active FROM commerce.users WHERE login_email = %s",
                (body.email,),
            )
        ).fetchone()
        valid = await passwords.verify_password(user["password_hash"] if user else None, body.password)
        if not valid or not user["is_active"] or not channel_allows(user["role"], "jwt", request.state.channel):
            # Same response whether the account is missing, inactive, wrong password, or wrong channel.
            limiter.record_failure(*keys)
            raise ApiError(401, "INVALID_CREDENTIALS")
        limiter.reset(f"email:{body.email}")
        async with conn.transaction():
            access, refresh, csrf = await issue_session(
                conn, request, user["id"], user["role"], user["token_version"], uuid.uuid4()
            )
            await record(conn, request, user["id"], staff_or_web(user["role"]), "로그인, refresh 토큰 발급")
    response = ok(
        request,
        {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": request.app.state.settings.access_token_ttl_seconds,
            "user": user_view(user["id"], body.email, user["role"]),
            "csrf_token": csrf,
        },
    )
    set_session_cookies(response, request, refresh, csrf)
    return response


@router.post("/refresh")
async def refresh(request: Request) -> JSONResponse:
    check_cookie_request(request)
    presented = request.cookies.get(REFRESH_COOKIE)
    if not presented:
        raise ApiError(401, "AUTH_REQUIRED")
    # One transaction holds the row lock from check to rotation, so a token can rotate only once.
    async with request.app.state.pools.auth.connection() as conn, conn.transaction():
        row = await (
            await conn.execute(
                "SELECT t.id, t.user_id, t.family_id, t.expires_at <= now() AS expired, t.revoked_at,"
                " u.login_email, u.role, u.token_version, u.is_active"
                " FROM commerce.refresh_tokens t JOIN commerce.users u ON u.id = t.user_id"
                " WHERE t.token_hash = %s FOR UPDATE OF t",
                (token_hash(presented),),
            )
        ).fetchone()
        if row is None:
            outcome = "AUTH_REQUIRED"
        elif row["revoked_at"] is not None:
            # Reuse of a rotated token: assume theft and revoke the whole family (DES-005 §1.1).
            await conn.execute(
                "UPDATE commerce.refresh_tokens SET revoked_at = now()"
                " WHERE user_id = %s AND family_id = %s AND revoked_at IS NULL",
                (row["user_id"], row["family_id"]),
            )
            await record(
                conn, request, row["user_id"], staff_or_web(row["role"]), "refresh 재사용 감지, 토큰 계열 폐기"
            )
            outcome = "TOKEN_REVOKED"
        elif row["expired"]:
            outcome = "TOKEN_EXPIRED"
        elif not row["is_active"] or not channel_allows(row["role"], "jwt", request.state.channel):
            outcome = "TOKEN_REVOKED"
        else:
            await conn.execute("UPDATE commerce.refresh_tokens SET revoked_at = now() WHERE id = %s", (row["id"],))
            access, new_refresh, csrf = await issue_session(
                conn, request, row["user_id"], row["role"], row["token_version"], row["family_id"]
            )
            await record(conn, request, row["user_id"], staff_or_web(row["role"]), "refresh 토큰 회전")
            outcome = None
    if outcome is not None:
        # Raised after commit so a detected reuse still persists the family revocation.
        raise ApiError(401, outcome)
    response = ok(
        request,
        {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": request.app.state.settings.access_token_ttl_seconds,
            "user": user_view(row["user_id"], row["login_email"], row["role"]),
            "csrf_token": csrf,
        },
    )
    set_session_cookies(response, request, new_refresh, csrf)
    return response


@router.post("/logout", status_code=204)
async def logout(request: Request, ctx: Annotated[AuthContext, Depends(authenticate)]) -> Response:
    if ctx.kind != "jwt":
        raise ApiError(403, "FORBIDDEN")
    if REFRESH_COOKIE in request.cookies:
        check_cookie_request(request)
    async with request.app.state.pools.auth.connection() as conn, conn.transaction():
        # Bumping token_version invalidates every access JWT and every client token (all devices).
        await conn.execute("UPDATE commerce.users SET token_version = token_version + 1 WHERE id = %s", (ctx.user_id,))
        await conn.execute(
            "UPDATE commerce.refresh_tokens SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL",
            (ctx.user_id,),
        )
        await record(conn, request, ctx.user_id, ctx.source, "모든 기기 로그아웃, 토큰 무효화")
    response = Response(status_code=204)
    clear_session_cookies(response)
    return response


def client_token_view(row: dict, now: datetime) -> dict:
    if row["revoked_at"] is not None or row["token_version"] != row["user_token_version"]:
        status = "revoked"
    elif row["expires_at"] <= now:
        status = "expired"
    else:
        status = "active"
    return {
        "id": str(row["id"]),
        "name": row["name"],
        "scopes": list(row["scopes"]),
        "expires_at": row["expires_at"].isoformat(),
        "created_at": row["created_at"].isoformat(),
        "status": status,
    }


@router.post("/client-tokens", status_code=201)
async def create_client_token(
    request: Request, body: ClientTokenRequest, ctx: Annotated[AuthContext, Depends(require_customer_jwt)]
) -> JSONResponse:
    token = new_opaque_token(CLIENT_TOKEN_PREFIX)
    async with request.app.state.pools.auth.connection() as conn, conn.transaction():
        row = await (
            await conn.execute(
                "INSERT INTO commerce.client_tokens (user_id, name, token_hash, scopes, token_version, expires_at)"
                " SELECT id, %s, %s, %s, token_version, now() + make_interval(secs => %s)"
                " FROM commerce.users WHERE id = %s"
                " RETURNING id, name, scopes, expires_at",
                (
                    body.name,
                    token_hash(token),
                    body.scopes,
                    request.app.state.settings.client_token_ttl_seconds,
                    ctx.user_id,
                ),
            )
        ).fetchone()
        await record(conn, request, ctx.user_id, ctx.source, "클라이언트 토큰 발급")
    # The plaintext token is returned exactly once; only its SHA-256 is stored.
    return ok(
        request,
        {
            "id": str(row["id"]),
            "name": row["name"],
            "token": token,
            "scopes": list(row["scopes"]),
            "expires_at": row["expires_at"].isoformat(),
        },
        201,
    )


@router.get("/client-tokens")
async def list_client_tokens(
    request: Request, ctx: Annotated[AuthContext, Depends(require_customer_jwt)]
) -> JSONResponse:
    async with request.app.state.pools.auth.connection() as conn:
        rows = await (
            await conn.execute(
                "SELECT t.id, t.name, t.scopes, t.token_version, t.expires_at, t.revoked_at, t.created_at,"
                " u.token_version AS user_token_version, now() AS db_now"
                " FROM commerce.client_tokens t JOIN commerce.users u ON u.id = t.user_id"
                " WHERE t.user_id = %s ORDER BY t.created_at DESC LIMIT 100",
                (ctx.user_id,),
            )
        ).fetchall()
    items = [client_token_view(r, r["db_now"]) for r in rows]
    return ok(request, {"items": items, "next_cursor": None})


@router.delete("/client-tokens/{token_id}", status_code=204)
async def revoke_client_token(
    request: Request, token_id: uuid.UUID, ctx: Annotated[AuthContext, Depends(require_customer_jwt)]
) -> Response:
    async with request.app.state.pools.auth.connection() as conn, conn.transaction():
        row = await (
            await conn.execute(
                "SELECT revoked_at FROM commerce.client_tokens WHERE id = %s AND user_id = %s FOR UPDATE",
                (token_id, ctx.user_id),
            )
        ).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND")
        if row["revoked_at"] is None:
            await conn.execute("UPDATE commerce.client_tokens SET revoked_at = now() WHERE id = %s", (token_id,))
            await record(conn, request, ctx.user_id, ctx.source, "클라이언트 토큰 폐기")
    return Response(status_code=204)
