"""AUTH-01~07 and access control (DES-005 §1.1·§2.1, D-17·D-19). Maps to T-11·T-12·T-13·T-27."""

import base64
import hashlib
import hmac
import json
import os
import uuid

import jwt
import psycopg
import pytest

from tests.conftest import OPS, PASSWORD, SHOP, _dsn, bearer, new_email, register_and_login

WHOAMI = "/api/v1/_test/whoami"
TOKENS = "/api/v1/auth/client-tokens"


def superuser():
    return psycopg.connect(_dsn("postgres", os.environ["TEST_SUPERUSER_PASSWORD"]), autocommit=True)


def outbox_payloads(request_id: str) -> list[dict]:
    with superuser() as conn:
        rows = conn.execute("SELECT payload FROM audit.outbox WHERE payload->>'request_id' = %s", (request_id,))
        return [r[0] for r in rows.fetchall()]


# ------------------------------------------------------------------ register


def test_register_creates_customer_cart_and_audit_event(client):
    email = new_email()
    r = client.post("/api/v1/auth/register", json={"email": f"  {email.upper()} ", "password": PASSWORD}, headers=SHOP)
    assert r.status_code == 201
    user = r.json()["data"]["user"]
    assert user["email"] == email and user["role"] == "customer"
    with superuser() as conn:
        assert conn.execute("SELECT count(*) FROM commerce.carts WHERE user_id=%s", (user["id"],)).fetchone()[0] == 1
        stored = conn.execute("SELECT password_hash FROM commerce.users WHERE id=%s", (user["id"],)).fetchone()[0]
    assert stored.startswith("$argon2id$")
    events = outbox_payloads(r.headers["x-request-id"])
    assert len(events) == 1 and events[0]["status"] == "success"
    assert PASSWORD not in json.dumps(events[0]) and email not in json.dumps(events[0])


@pytest.mark.parametrize(
    "body",
    [
        {"email": "a@example.invalid", "password": "short"},
        {"email": "not-an-email", "password": PASSWORD},
        {"email": "a@example.invalid", "password": PASSWORD, "role": "admin"},
        {"email": "a@example.invalid", "password": "x" * 129},
    ],
)
def test_register_rejects_invalid_input_without_echo(client, body):
    r = client.post("/api/v1/auth/register", json=body, headers=SHOP)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"
    assert body["password"] not in r.text


def test_register_only_on_shop_channel(client):
    r = client.post("/api/v1/auth/register", json={"email": new_email(), "password": PASSWORD}, headers=OPS)
    assert r.status_code == 404


def test_register_duplicate_email(client):
    email = new_email()
    client.post("/api/v1/auth/register", json={"email": email, "password": PASSWORD}, headers=SHOP)
    r = client.post("/api/v1/auth/register", json={"email": email, "password": PASSWORD}, headers=SHOP)
    assert r.status_code == 409 and r.json()["error"]["code"] == "EMAIL_UNAVAILABLE"


# --------------------------------------------------------------------- login


def test_login_sets_secure_cookies(client):
    _, data = register_and_login(client)
    assert data["expires_in"] == 900 and data["token_type"] == "Bearer"
    cookies = client.cookies
    assert cookies.get("guardrail_refresh") and cookies.get("guardrail_csrf") == data["csrf_token"]


def test_login_set_cookie_attributes(client):
    email = new_email()
    client.post("/api/v1/auth/register", json={"email": email, "password": PASSWORD}, headers=SHOP)
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}, headers=SHOP)
    raw = [v for k, v in r.headers.multi_items() if k == "set-cookie"]
    refresh = next(c for c in raw if c.startswith("guardrail_refresh="))
    assert "HttpOnly" in refresh and "Secure" in refresh and "SameSite=strict" in refresh
    assert "Path=/api/v1/auth" in refresh


def test_login_failures_are_indistinguishable(client):
    email, _ = register_and_login(client)
    wrong = client.post("/api/v1/auth/login", json={"email": email, "password": "wrong password 123"}, headers=SHOP)
    missing = client.post(
        "/api/v1/auth/login", json={"email": new_email(), "password": "wrong password 123"}, headers=SHOP
    )
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json()["error"] == missing.json()["error"]


def test_customer_cannot_login_on_ops_channel(client):
    email = new_email()
    client.post("/api/v1/auth/register", json={"email": email, "password": PASSWORD}, headers=SHOP)
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}, headers=OPS)
    assert r.status_code == 401 and r.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_staff_login_only_on_ops_channel(client):
    from argon2 import PasswordHasher

    email = new_email()
    with superuser() as conn:
        conn.execute(
            "INSERT INTO commerce.users (login_email, password_hash, role) VALUES (%s, %s, 'admin')",
            (email, PasswordHasher().hash(PASSWORD)),
        )
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}, headers=SHOP).status_code == 401
    )
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}, headers=OPS)
    assert r.status_code == 200 and r.json()["data"]["user"]["role"] == "admin"
    token = r.json()["data"]["access_token"]
    assert client.get(WHOAMI, headers=bearer(token, OPS)).json()["source"] == "streamlit"
    # Staff token replayed through the shop edge is refused.
    assert client.get(WHOAMI, headers=bearer(token, SHOP)).status_code == 403


def test_login_rate_limit(client):
    email, _ = register_and_login(client)
    for _ in range(10):
        client.post("/api/v1/auth/login", json={"email": email, "password": "wrong password 123"}, headers=SHOP)
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}, headers=SHOP)
    assert r.status_code == 429 and r.headers["retry-after"]


# ------------------------------------------------------------- access tokens


def test_channel_is_required(client):
    _, data = register_and_login(client)
    token = data["access_token"]
    assert client.get(WHOAMI, headers=bearer(token, SHOP)).status_code == 200
    assert client.get(WHOAMI, headers={"Authorization": f"Bearer {token}"}).status_code == 403
    assert client.get(WHOAMI, headers=bearer(token, {"X-Edge-Channel": "admin"})).status_code == 403
    assert client.get(WHOAMI, headers=bearer(token, OPS)).status_code == 403


def test_missing_and_malformed_bearer(client):
    assert client.get(WHOAMI, headers=SHOP).status_code == 401
    assert client.get(WHOAMI, headers={**SHOP, "Authorization": "Basic abc"}).status_code == 401
    assert client.get(WHOAMI, headers=bearer("not.a.jwt")).status_code == 401


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_forged_tokens_rejected(client, settings):
    _, data = register_and_login(client)
    header, payload, signature = data["access_token"].split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    elevated = {**claims, "role": "admin"}
    # 1) payload tampering with the original signature
    tampered = f"{header}.{_b64(elevated)}.{signature}"
    # 2) alg=none
    none_alg = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(elevated)}."
    # 3) HS256 signed with the public key (algorithm confusion)
    signer = client.app.state.jwt_signer
    from cryptography.hazmat.primitives import serialization

    pub = signer._public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    hs_header = _b64({"alg": "HS256", "typ": "JWT", "kid": signer.kid})
    hs_body = _b64(elevated)
    hs_sig = base64.urlsafe_b64encode(hmac.new(pub, f"{hs_header}.{hs_body}".encode(), hashlib.sha256).digest())
    hs = f"{hs_header}.{hs_body}.{hs_sig.rstrip(b'=').decode()}"
    for forged in (tampered, none_alg, hs):
        r = client.get(WHOAMI, headers=bearer(forged))
        assert r.status_code == 401, forged


def test_wrong_audience_and_issuer_rejected(client):
    _, data = register_and_login(client)
    signer = client.app.state.jwt_signer
    claims = jwt.decode(data["access_token"], options={"verify_signature": False})
    for override in ({"aud": "other-api"}, {"iss": "someone-else"}):
        token = jwt.encode({**claims, **override}, signer._private_key, algorithm="RS256", headers={"kid": signer.kid})
        assert client.get(WHOAMI, headers=bearer(token)).status_code == 401


def test_expired_token(client):
    _, data = register_and_login(client)
    signer = client.app.state.jwt_signer
    claims = jwt.decode(data["access_token"], options={"verify_signature": False})
    expired = jwt.encode(
        {**claims, "iat": claims["iat"] - 3600, "exp": claims["iat"] - 60},
        signer._private_key,
        algorithm="RS256",
        headers={"kid": signer.kid},
    )
    r = client.get(WHOAMI, headers=bearer(expired))
    assert r.status_code == 401 and r.json()["error"]["code"] == "TOKEN_EXPIRED"


def test_role_change_in_db_invalidates_token(client):
    email, data = register_and_login(client)
    with superuser() as conn:
        conn.execute("UPDATE commerce.users SET is_active=false WHERE login_email=%s", (email,))
    r = client.get(WHOAMI, headers=bearer(data["access_token"]))
    assert r.status_code == 401 and r.json()["error"]["code"] == "TOKEN_REVOKED"


# ------------------------------------------------------------------- refresh


def csrf_headers(client, base=SHOP):
    return {**base, "X-CSRF-Token": client.cookies.get("guardrail_csrf")}


def test_refresh_requires_origin_and_csrf(client):
    register_and_login(client)
    assert client.post("/api/v1/auth/refresh", headers=SHOP).status_code == 403
    bad_origin = {**csrf_headers(client), "Origin": "https://evil.example.invalid"}
    assert client.post("/api/v1/auth/refresh", headers=bad_origin).status_code == 403
    wrong_csrf = {**SHOP, "X-CSRF-Token": "nope"}
    assert client.post("/api/v1/auth/refresh", headers=wrong_csrf).status_code == 403


def test_refresh_rotates_and_detects_reuse(client):
    _, first = register_and_login(client)
    old_refresh = client.cookies.get("guardrail_refresh")
    r = client.post("/api/v1/auth/refresh", headers=csrf_headers(client))
    assert r.status_code == 200
    new_refresh = client.cookies.get("guardrail_refresh")
    assert new_refresh != old_refresh
    assert client.get(WHOAMI, headers=bearer(r.json()["data"]["access_token"])).status_code == 200

    # Replaying the rotated token revokes the whole family, including the newest token.
    csrf = client.cookies.get("guardrail_csrf")

    def send_with(refresh_token):
        client.cookies.clear()
        client.cookies.set("guardrail_refresh", refresh_token)
        client.cookies.set("guardrail_csrf", csrf)
        return client.post("/api/v1/auth/refresh", headers={**SHOP, "X-CSRF-Token": csrf})

    replay = send_with(old_refresh)
    assert replay.status_code == 401 and replay.json()["error"]["code"] == "TOKEN_REVOKED"
    after = send_with(new_refresh)
    assert after.status_code == 401
    assert outbox_payloads(replay.headers["x-request-id"])[0]["summary_redacted"].startswith("refresh 재사용")


# -------------------------------------------------------------------- logout


def test_logout_invalidates_all_tokens_including_client_tokens(client):
    _, data = register_and_login(client)
    access = data["access_token"]
    created = client.post(TOKENS, json={"name": "desktop"}, headers=bearer(access))
    client_token = created.json()["data"]["token"]
    assert client.get(WHOAMI, headers=bearer(client_token)).json()["source"] == "anythingllm"

    r = client.post(
        "/api/v1/auth/logout", headers={**bearer(access), "X-CSRF-Token": client.cookies.get("guardrail_csrf")}
    )
    assert r.status_code == 204
    assert client.get(WHOAMI, headers=bearer(access)).json()["error"]["code"] == "TOKEN_REVOKED"
    assert client.get(WHOAMI, headers=bearer(client_token)).json()["error"]["code"] == "TOKEN_REVOKED"


# ------------------------------------------------------------- client tokens


def test_client_token_issued_once_and_hashed(client):
    _, data = register_and_login(client)
    r = client.post(
        TOKENS,
        json={"name": "내 데스크톱", "scopes": ["chat:write", "models:read"]},
        headers=bearer(data["access_token"]),
    )
    assert r.status_code == 201
    token = r.json()["data"]["token"]
    assert token.startswith("gct_") and len(token) >= 40
    with superuser() as conn:
        rows = conn.execute(
            "SELECT token_hash FROM commerce.client_tokens WHERE id=%s", (r.json()["data"]["id"],)
        ).fetchall()
    assert rows and token not in rows[0][0]
    listing = client.get(TOKENS, headers=bearer(data["access_token"]))
    assert token not in listing.text and "token_hash" not in listing.text
    assert listing.json()["data"]["items"][0]["status"] == "active"


def test_client_token_cannot_manage_tokens_or_use_ops(client):
    _, data = register_and_login(client)
    token = client.post(TOKENS, json={"name": "d"}, headers=bearer(data["access_token"])).json()["data"]["token"]
    assert client.get(TOKENS, headers=bearer(token)).status_code == 403
    assert client.post(TOKENS, json={"name": "x"}, headers=bearer(token)).status_code == 403
    assert client.get(WHOAMI, headers=bearer(token, OPS)).status_code == 403


@pytest.mark.parametrize("scopes", [["actions:confirm"], ["admin"], [], ["chat:write", "chat:write"]])
def test_client_token_scope_allowlist(client, scopes):
    _, data = register_and_login(client)
    assert (
        client.post(TOKENS, json={"name": "d", "scopes": scopes}, headers=bearer(data["access_token"])).status_code
        == 422
    )


def test_revoke_client_token_and_idor(client):
    _, owner = register_and_login(client)
    _, other = register_and_login(client)
    created = client.post(TOKENS, json={"name": "d"}, headers=bearer(owner["access_token"])).json()["data"]
    # Another customer cannot revoke (or learn about) it.
    assert client.delete(f"{TOKENS}/{created['id']}", headers=bearer(other["access_token"])).status_code == 404
    assert client.delete(f"{TOKENS}/{uuid.uuid4()}", headers=bearer(owner["access_token"])).status_code == 404
    assert client.delete(f"{TOKENS}/{created['id']}", headers=bearer(owner["access_token"])).status_code == 204
    assert client.delete(f"{TOKENS}/{created['id']}", headers=bearer(owner["access_token"])).status_code == 204
    r = client.get(WHOAMI, headers=bearer(created["token"]))
    assert r.status_code == 401 and r.json()["error"]["code"] == "TOKEN_REVOKED"


# ------------------------------------------------------------ cross-cutting


def test_request_id_is_server_generated(client):
    r = client.get("/api/v1/health/live", headers={"X-Request-Id": "attacker-chosen"})
    assert r.headers["x-request-id"] != "attacker-chosen"
    uuid.UUID(r.headers["x-request-id"])
    assert r.headers["cache-control"] == "no-store"


def test_body_too_large(client):
    r = client.post("/api/v1/auth/login", content=b"x" * 262_145, headers={**SHOP, "Content-Type": "application/json"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "BODY_TOO_LARGE"


def test_failed_login_is_not_audited(client):
    # D-19: rejections before authentication go to logs/metrics, not the audit outbox.
    r = client.post("/api/v1/auth/login", json={"email": new_email(), "password": "wrong password 123"}, headers=SHOP)
    assert r.status_code == 401
    assert outbox_payloads(r.headers["x-request-id"]) == []


def test_readiness_internal_and_through_edge(client):
    assert client.get("/api/v1/health/ready").status_code == 200
    _, data = register_and_login(client)
    assert client.get("/api/v1/health/ready", headers=bearer(data["access_token"])).status_code == 403


def test_production_refuses_guardrail_off(jwt_key_file):
    from app.config import Settings

    with pytest.raises(ValueError, match="GUARDRAIL_ENFORCED"):
        Settings(auth_database_url="postgresql://x", jwt_private_key_file=jwt_key_file, guardrail_enforced=False)
    lab = Settings(
        auth_database_url="postgresql://x", jwt_private_key_file=jwt_key_file, guardrail_enforced=False, app_env="lab"
    )
    assert lab.guardrail_enforced is False
