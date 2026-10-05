"""Integration tests for the initial schema (DES-002 §4~§6) on real PostgreSQL 17."""

import uuid

import psycopg
import pytest

from tests.conftest import as_role, insert_action, reset_role

EXPECTED_TABLES = {
    "commerce": {
        "users",
        "refresh_tokens",
        "client_tokens",
        "chat_sessions",
        "products",
        "orders",
        "order_items",
        "coupons",
        "user_coupons",
        "carts",
        "cart_items",
        "actions",
    },
    "threat_intel": {"rulesets", "rules", "policy_publications"},
    "audit": {"outbox", "events", "rule_hits", "tool_executions", "alerts"},
}


def test_server_is_postgres_17(db):
    assert db.execute("SHOW server_version_num").fetchone()[0].startswith("17")


def test_all_tables_exist(db):
    rows = db.execute(
        "SELECT table_schema, table_name FROM information_schema.tables "
        "WHERE table_schema IN ('commerce','threat_intel','audit')"
    ).fetchall()
    found: dict[str, set[str]] = {}
    for schema, name in rows:
        found.setdefault(schema, set()).add(name)
    assert found == EXPECTED_TABLES


def test_owner_is_not_superuser(owner_conn):
    assert owner_conn.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()[0] is False


@pytest.mark.parametrize(
    ("login", "group"),
    [
        ("ag_chat", "shop_writer"),
        ("ag_chat", "audit_ingest"),
        ("ag_auth", "auth_service"),
        ("ag_rules", "rule_publisher"),
        ("ag_audit_worker", "audit_worker"),
        ("ag_maintenance", "maintenance_worker"),
        ("ag_retention", "retention_worker"),
    ],
)
def test_login_role_membership(db, login, group):
    assert db.execute("SELECT pg_has_role(%s, %s, 'MEMBER')", (login, group)).fetchone()[0]


@pytest.mark.parametrize(
    ("role", "table", "privilege", "expected"),
    [
        # D-18: expiry needs UPDATE + outbox INSERT; retention only deletes.
        ("maintenance_worker", "commerce.actions", "UPDATE", True),
        ("maintenance_worker", "commerce.user_coupons", "UPDATE", True),
        ("maintenance_worker", "audit.outbox", "INSERT", True),
        ("maintenance_worker", "commerce.actions", "DELETE", False),
        ("retention_worker", "commerce.actions", "UPDATE", False),
        ("retention_worker", "audit.outbox", "INSERT", False),
        ("retention_worker", "audit.events", "DELETE", True),
        # Least privilege for the request path.
        ("shop_writer", "commerce.products", "UPDATE", False),
        ("shop_writer", "commerce.coupons", "UPDATE", False),
        ("shop_reader", "commerce.cart_items", "INSERT", False),
        ("audit_ingest", "audit.outbox", "SELECT", False),
        ("audit_ingest", "audit.events", "INSERT", False),
        ("audit_reader", "commerce.users", "SELECT", False),
        ("audit_worker", "commerce.carts", "SELECT", False),
        ("audit_reader", "audit.events", "UPDATE", False),
        ("rule_reader", "threat_intel.rules", "INSERT", False),
    ],
)
def test_table_privileges(db, role, table, privilege, expected):
    assert db.execute("SELECT has_table_privilege(%s, %s, %s)", (role, table, privilege)).fetchone()[0] is expected


def test_action_intent_is_immutable(db, seed):
    action_id = insert_action(db, seed)
    with pytest.raises(psycopg.errors.RaiseException, match="action intent is immutable"):
        db.execute("UPDATE commerce.actions SET arguments = '{\"quantity\": 99}' WHERE id = %s", (action_id,))


def test_pending_preview_is_immutable(db, seed):
    action_id = insert_action(db, seed, result='{"preview": 1}')
    with pytest.raises(psycopg.errors.RaiseException, match="pending preview is immutable"):
        db.execute("UPDATE commerce.actions SET result = '{\"preview\": 2}' WHERE id = %s", (action_id,))


def test_executed_action_is_terminal(db, seed):
    action_id = insert_action(db, seed)
    as_role(db, "shop_writer")  # trigger functions must still fire after REVOKE EXECUTE FROM PUBLIC
    db.execute(
        "UPDATE commerce.actions SET state='executed', result='{\"ok\": true}', resolved_at=now(), "
        "idempotency_key='k1' WHERE id=%s",
        (action_id,),
    )
    with pytest.raises(psycopg.errors.RaiseException, match="terminal action is immutable"):
        db.execute("UPDATE commerce.actions SET state='cancelled' WHERE id=%s", (action_id,))


def test_executed_requires_result(db, seed):
    action_id = insert_action(db, seed)
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute("UPDATE commerce.actions SET state='executed', resolved_at=now() WHERE id=%s", (action_id,))


def test_action_arguments_cannot_carry_user_id(db, seed):
    with pytest.raises(psycopg.errors.CheckViolation):
        insert_action(db, seed, arguments='{"user_id": "x"}')


def test_action_target_must_be_own_cart(db, seed):
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        insert_action(db, seed, target_id=seed["other_cart"])


def test_maintenance_worker_can_expire_and_write_outbox(db, seed):
    action_id = insert_action(db, seed)
    as_role(db, "maintenance_worker")
    db.execute("UPDATE commerce.actions SET state='expired', resolved_at=now() WHERE id=%s", (action_id,))
    db.execute("INSERT INTO audit.outbox (event_id, payload) VALUES (%s, '{}')", (uuid.uuid4(),))


def test_retention_worker_cannot_write_outbox(db):
    as_role(db, "retention_worker")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        db.execute("INSERT INTO audit.outbox (event_id, payload) VALUES (%s, '{}')", (uuid.uuid4(),))


def test_cart_cannot_apply_other_users_coupon(db, seed):
    coupon_id, other_uc = uuid.uuid4(), uuid.uuid4()
    db.execute(
        "INSERT INTO commerce.coupons (id, code, discount_krw, expires_at) "
        "VALUES (%s, 'C1', 1000, now() + interval '1 day')",
        (coupon_id,),
    )
    db.execute(
        "INSERT INTO commerce.user_coupons (id, user_id, coupon_id) VALUES (%s, %s, %s)",
        (other_uc, seed["other"], coupon_id),
    )
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        db.execute("UPDATE commerce.carts SET applied_coupon_id=%s WHERE id=%s", (other_uc, seed["cart"]))


def _add_rule(db, ruleset_id, rule_id="RULE_TEST"):
    db.execute(
        "INSERT INTO threat_intel.rules (ruleset_id, rule_id, stage, category, kind, pattern, action) "
        "VALUES (%s, %s, 'input', 'LLM01:2025', 'regex', 'ignore', 'block')",
        (ruleset_id, rule_id),
    )


def test_rules_frozen_after_validation(db, seed):
    _add_rule(db, seed["ruleset"])
    db.execute(
        "UPDATE threat_intel.rulesets SET state='validated', checksum=%s, validated_at=now() WHERE id=%s",
        ("a" * 64, seed["ruleset"]),
    )
    with pytest.raises(psycopg.errors.RaiseException, match="ruleset is immutable"), db.transaction():
        _add_rule(db, seed["ruleset"], "RULE_TEST_2")
    with pytest.raises(psycopg.errors.RaiseException, match="validated content is immutable"), db.transaction():
        db.execute("UPDATE threat_intel.rulesets SET policy='{\"x\":1}' WHERE id=%s", (seed["ruleset"],))
    with pytest.raises(psycopg.errors.RaiseException, match="clone a new draft"), db.transaction():
        db.execute("UPDATE threat_intel.rulesets SET state='draft' WHERE id=%s", (seed["ruleset"],))


def test_only_one_active_ruleset(db, seed):
    # A real ruleset may already be active in this database; retire it inside the rolled-back transaction.
    db.execute("UPDATE threat_intel.rulesets SET state='retired' WHERE state='active'")
    second = uuid.uuid4()
    db.execute(
        "INSERT INTO threat_intel.rulesets (id, version_label, created_by, state, checksum, validated_at) "
        "VALUES (%s, 'v-a', %s, 'active', %s, now()), (%s, 'v-b', %s, 'validated', %s, now())",
        (uuid.uuid4(), seed["admin"], "b" * 64, second, seed["admin"], "c" * 64),
    )
    with pytest.raises(psycopg.errors.UniqueViolation):
        db.execute("UPDATE threat_intel.rulesets SET state='active' WHERE id=%s", (second,))


def test_mask_rule_requires_output_stage_and_marker(db, seed):
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute(
            "INSERT INTO threat_intel.rules (ruleset_id, rule_id, stage, category, kind, pattern, action) "
            "VALUES (%s, 'RULE_X', 'input', 'LLM02:2025', 'regex', 'x', 'mask')",
            (seed["ruleset"],),
        )


@pytest.mark.parametrize(
    ("status", "stage", "ok"),
    [
        ("blocked", None, False),
        ("blocked", "input", True),
        ("success", "input", False),
        ("masked", None, True),
    ],
)
def test_event_status_stage_consistency(db, status, stage, ok):
    stmt = (
        "INSERT INTO audit.events "
        "(event_id, request_id, source, api_path, status, stage, summary_redacted, occurred_at) "
        "VALUES (%s, %s, 'web', '/api/v1/chat/completions', %s, %s, 's', now())"
    )
    args = (uuid.uuid4(), uuid.uuid4(), status, stage)
    if ok:
        db.execute(stmt, args)
    else:
        with pytest.raises(psycopg.errors.CheckViolation):
            db.execute(stmt, args)


def test_email_must_be_lowercase(db):
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute("INSERT INTO commerce.users (login_email, password_hash) VALUES ('A@example.invalid', 'x')")


def test_client_token_scope_allowlist(db, seed):
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute(
            "INSERT INTO commerce.client_tokens (user_id, name, token_hash, scopes, token_version, expires_at) "
            "VALUES (%s, 'desk', %s, ARRAY['actions:confirm'], 0, now() + interval '30 days')",
            (seed["customer"], "d" * 64),
        )


def test_login_role_cannot_bypass_grants(db):
    reset_role(db)
    assert db.execute("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname='ag_chat'").fetchone()[0] is False
