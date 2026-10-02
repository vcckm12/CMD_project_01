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
