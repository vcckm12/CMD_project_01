import json
import os
import uuid

import psycopg
import pytest


def _dsn(user: str, password: str) -> str:
    host = os.environ.get("TEST_DB_HOST", "localhost")
    dbname = os.environ.get("TEST_DB_NAME", "ai_guardrail")
    return f"postgresql://{user}:{password}@{host}:5432/{dbname}"


@pytest.fixture
def db():
    """Superuser connection inside a transaction that is always rolled back.

    Tests switch privileges with `SET LOCAL ROLE <group role>` so grants are checked
    exactly as the application pools would see them.
    """
    conn = psycopg.connect(_dsn("postgres", os.environ["TEST_SUPERUSER_PASSWORD"]))
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def owner_conn():
    conn = psycopg.connect(_dsn("ag_owner", os.environ["TEST_OWNER_PASSWORD"]), autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


def as_role(conn: psycopg.Connection, role: str) -> None:
    conn.execute(f'SET LOCAL ROLE "{role}"')


def reset_role(conn: psycopg.Connection) -> None:
    conn.execute("RESET ROLE")


@pytest.fixture
def seed(db):
    """Minimal synthetic graph: one customer with a cart, one admin, one draft ruleset."""
    ids = {k: uuid.uuid4() for k in ("customer", "other", "admin", "cart", "other_cart", "ruleset", "product")}
    db.execute(
        "INSERT INTO commerce.users (id, login_email, password_hash, role) VALUES "
        "(%s, 'c@example.invalid', 'x', 'customer'), (%s, 'o@example.invalid', 'x', 'customer'),"
        " (%s, 'a@example.invalid', 'x', 'admin')",
        (ids["customer"], ids["other"], ids["admin"]),
    )
    db.execute(
        "INSERT INTO commerce.carts (id, user_id) VALUES (%s, %s), (%s, %s)",
        (ids["cart"], ids["customer"], ids["other_cart"], ids["other"]),
    )
    db.execute(
        "INSERT INTO commerce.products (id, sku, name, price_krw, stock_count) "
        "VALUES (%s, 'SKU-1', '무선 마우스', 25000, 10)",
        (ids["product"],),
    )
    db.execute(
        "INSERT INTO threat_intel.rulesets (id, version_label, created_by) VALUES (%s, 'test-draft', %s)",
        (ids["ruleset"], ids["admin"]),
    )
    return ids


def insert_action(db, seed, **overrides):
    values = {
        "id": uuid.uuid4(),
        "request_id": uuid.uuid4(),
        "user_id": seed["customer"],
        "tool_name": "set_cart_item",
        "target_id": seed["cart"],
        "arguments": json.dumps({"product_id": str(seed["product"]), "quantity": 2}),
        "arguments_hash": "0" * 64,
        "base_version": 0,
        "ruleset_version": seed["ruleset"],
    }
    values.update(overrides)
    cols = ", ".join(values)
    marks = ", ".join(["%s"] * len(values))
    db.execute(
        f"INSERT INTO commerce.actions ({cols}, expires_at) VALUES ({marks}, now() + interval '5 minutes')",
        tuple(values.values()),
    )
    return values["id"]


# ---------------------------------------------------------------- API fixtures

SHOP = {"X-Edge-Channel": "shop", "Origin": "https://shop.example.internal"}
OPS = {"X-Edge-Channel": "ops", "Origin": "https://ops.example.internal"}


@pytest.fixture(scope="session")
def jwt_key_file(tmp_path_factory):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path_factory.mktemp("keys") / "jwt.pem"
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return path


@pytest.fixture(scope="session")
def active_ruleset():
    """Make sure some validated ruleset is active so readiness can pass (bootstrap if the DB is fresh)."""
    import asyncio

    from app.guardrails import rule_store
    from app.guardrails.ruleset import RulesetInvalid

    async def ensure():
        rules_url = _dsn("ag_rules", os.environ["TEST_RULES_PASSWORD"])
        async with await psycopg.AsyncConnection.connect(rules_url) as conn:
            current = await rule_store.active_id(conn)
            if current is not None:
                try:
                    await rule_store.load_active(conn)
                    return
                except RulesetInvalid:
                    pass  # e.g. published before the current engine added required rules: publish defaults over it
            with psycopg.connect(_dsn("postgres", os.environ["TEST_SUPERUSER_PASSWORD"]), autocommit=True) as su:
                actor = su.execute(
                    "INSERT INTO commerce.users (login_email, password_hash, role)"
                    " VALUES (%s, 'x', 'admin') RETURNING id",
                    (f"bootstrap-{uuid.uuid4().hex[:8]}@example.invalid",),
                ).fetchone()[0]
            draft = await rule_store.create_draft(conn, label=f"test-boot-{uuid.uuid4().hex[:8]}", actor_id=actor)
            assert await rule_store.validate_draft(conn, draft) == []
            await rule_store.publish(
                conn, ruleset_id=draft, expected_active_id=current, actor_id=actor, request_id=uuid.uuid4()
            )

    asyncio.run(ensure())


@pytest.fixture
def settings(jwt_key_file, active_ruleset):
    from app.config import Settings

    return Settings(
        auth_database_url=_dsn("ag_auth", os.environ["TEST_AUTH_PASSWORD"]),
        chat_database_url=_dsn("ag_chat", os.environ["TEST_CHAT_PASSWORD"]),
        audit_reader_database_url=_dsn("ag_audit_reader", os.environ["TEST_AUDIT_READER_PASSWORD"]),
        rules_database_url=_dsn("ag_rules", os.environ["TEST_RULES_PASSWORD"]),
        jwt_private_key_file=jwt_key_file,
        input_fingerprint_key="test-fingerprint-key-" + "x" * 16,
    )


class FakeModel:
    """Scripted Ollama: judge calls (format=json) get `judge` labels by target, chat calls pop `replies`.

    A reply is a dict message ({"content": ...} or {"tool_calls": [...]}), an int HTTP status, or
    an Exception class to raise. `chat_calls` records every non-judge request body.
    """

    def __init__(self):
        self.replies: list = []
        self.judge = {"input": "SAFE", "tool": "SAFE", "output": "SAFE"}
        self.chat_calls: list[dict] = []
        self.judge_calls: list[dict] = []
        self.prompt_eval_count = 100

    def handler(self, request):
        import json as _json

        import httpx

        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "qwen3:8b", "digest": "d" * 64}]})
        body = _json.loads(request.content)
        if body.get("format") == "json":
            self.judge_calls.append(body)
            system = body["messages"][0]["content"]
            target = "output" if "ASSISTANT ANSWER" in system else "tool" if "TOOL RESULT" in system else "input"
            label = self.judge[target]
            if isinstance(label, int):
                return httpx.Response(label)
            return httpx.Response(200, json={"message": {"content": _json.dumps({"label": label})}})
        self.chat_calls.append(body)
        reply = self.replies.pop(0) if self.replies else {"content": "안내해 드릴게요."}
        if isinstance(reply, type) and issubclass(reply, Exception):
            raise reply("scripted")
        if isinstance(reply, int):
            return httpx.Response(reply)
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", **reply},
                "prompt_eval_count": self.prompt_eval_count,
                "eval_count": 20,
            },
        )


@pytest.fixture
def fake_model():
    return FakeModel()


@pytest.fixture
def client(settings, fake_model):
    import httpx
    from fastapi import Depends
    from fastapi.testclient import TestClient

    from app.main import create_app
    from app.security.auth import AuthContext, authenticate

    app = create_app(settings, ollama_transport=httpx.MockTransport(fake_model.handler))

    # Test-only probe so client-token authentication can be exercised before chat routes exist.
    @app.get("/api/v1/_test/whoami")
    async def whoami(ctx: AuthContext = Depends(authenticate)):  # noqa: B008
        return {"user_id": str(ctx.user_id), "kind": ctx.kind, "source": ctx.source}

    with TestClient(app, base_url="https://testserver") as c:
        yield c


def new_email() -> str:
    return f"u-{uuid.uuid4().hex[:12]}@example.invalid"


PASSWORD = "correct horse battery 42"


def register_and_login(client, headers=SHOP):
    email = new_email()
    r = client.post("/api/v1/auth/register", json={"email": email, "password": PASSWORD}, headers=SHOP)
    assert r.status_code == 201, r.text
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}, headers=headers)
    assert r.status_code == 200, r.text
    return email, r.json()["data"]


def bearer(token: str, base=SHOP) -> dict[str, str]:
    return {**base, "Authorization": f"Bearer {token}"}
