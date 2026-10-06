"""Audit worker and scheduler on PostgreSQL (DES-002 §6·§8, DES-007 §5·§6). Maps to T-19 and T-22."""

import asyncio
import os
import uuid

import psycopg
import pytest
from psycopg.types.json import Jsonb

from app.audit.outbox import AuditEnvelope, RuleHit, ToolExecution
from app.workers import audit_worker, scheduler
from tests.conftest import _dsn


def run(coro):
    return asyncio.run(coro)


def superuser():
    return psycopg.connect(_dsn("postgres", os.environ["TEST_SUPERUSER_PASSWORD"]), autocommit=True)


def login(role: str, env: str) -> str:
    return _dsn(role, os.environ[env])


WORKER = ("ag_audit_worker", "TEST_AUDIT_WORKER_PASSWORD")
MAINTENANCE = ("ag_maintenance", "TEST_MAINTENANCE_PASSWORD")
RETENTION = ("ag_retention", "TEST_RETENTION_PASSWORD")


def put_outbox(payload: dict, event_id: uuid.UUID | None = None) -> uuid.UUID:
    event_id = event_id or uuid.UUID(payload["event_id"])
    with superuser() as conn:
        conn.execute("INSERT INTO audit.outbox (event_id, payload) VALUES (%s, %s)", (event_id, Jsonb(payload)))
    return event_id


def envelope(**overrides) -> dict:
    env = AuditEnvelope(
        request_id=uuid.uuid4(),
        actor_id=None,
        source="web",
        api_path="/api/v1/chat/completions",
        status="blocked",
        stage="input",
        summary_redacted="차단(input): RULE_IGNORE_INSTRUCTIONS",
        rule_hits=(RuleHit(rule_id="RULE_IGNORE_INSTRUCTIONS", category="LLM01:2025", stage="input", action="block",
                           match_count=1),),
        tool_executions=(ToolExecution(tool_name="get_cart", outcome="read", duration_ms=1.5),),
    )  # fmt: skip
    data = env.model_dump(mode="json")
    data.update(overrides)
    return data


def drain_until(predicate, rounds: int = 50):
    async def go():
        async with await psycopg.AsyncConnection.connect(login(*WORKER)) as conn:
            for _ in range(rounds):
                await audit_worker.drain_once(conn)
                if predicate():
                    return True
        return False

    return run(go())


def outbox_row(event_id):
    with superuser() as conn:
        return conn.execute(
            "SELECT delivery_state, attempts, last_error_code, available_at > now() FROM audit.outbox WHERE event_id = %s",
            (event_id,),
        ).fetchone()


def counts(event_id):
    with superuser() as conn:
        return tuple(
            conn.execute(f"SELECT count(*) FROM audit.{table} WHERE event_id = %s", (event_id,)).fetchone()[0]
            for table in ("events", "rule_hits", "tool_executions")
        )


# ------------------------------------------------------------------------------ worker


def test_event_and_children_are_loaded():
    event_id = put_outbox(envelope())
    assert drain_until(lambda: outbox_row(event_id)[0] == "delivered")
    assert counts(event_id) == (1, 1, 1)


def test_replay_adds_no_duplicates():
    event_id = put_outbox(envelope())
    assert drain_until(lambda: outbox_row(event_id)[0] == "delivered")
    with superuser() as conn:  # e.g. a crash after insert but before the delivered mark was committed elsewhere
        conn.execute(
            "UPDATE audit.outbox SET delivery_state = 'pending', delivered_at = NULL WHERE event_id = %s", (event_id,)
        )
    assert drain_until(lambda: outbox_row(event_id)[0] == "delivered")
    assert counts(event_id) == (1, 1, 1)


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 2},
        {"stage": None},  # blocked without stage violates the envelope rule
        {"summary_redacted": "x" * 2001},
        {"unexpected_field": "raw prompt text"},
    ],
)
def test_invalid_envelope_goes_dead_and_alerts(payload):
    with superuser() as conn:
        conn.execute("DELETE FROM audit.alerts WHERE kind = 'outbox_dead'")
    event_id = put_outbox(envelope(**payload))
    assert drain_until(lambda: outbox_row(event_id)[0] == "dead")
    assert outbox_row(event_id)[2] == "INVALID_ENVELOPE" and counts(event_id)[0] == 0
    with superuser() as conn:
        alert = conn.execute(
            "SELECT severity FROM audit.alerts WHERE kind = 'outbox_dead' AND state = 'open'"
        ).fetchone()
    assert alert == ("critical",)


def test_fk_failure_backs_off_then_dies():
    event_id = put_outbox(envelope(ruleset_version=str(uuid.uuid4())))  # no such ruleset → FK violation
    assert drain_until(lambda: outbox_row(event_id)[1] >= 1)
    state, attempts, code, delayed = outbox_row(event_id)
    assert state == "pending" and attempts == 1 and code == "23503" and delayed
    with superuser() as conn:
        conn.execute("UPDATE audit.outbox SET attempts = 9, available_at = now() WHERE event_id = %s", (event_id,))
    assert drain_until(lambda: outbox_row(event_id)[0] == "dead")
    assert outbox_row(event_id)[1] == 10


def test_parallel_workers_never_double_load():
    ids = [put_outbox(envelope()) for _ in range(120)]

    async def worker():
        async with await psycopg.AsyncConnection.connect(login(*WORKER)) as conn:
            for _ in range(10):
                await audit_worker.drain_once(conn)

    async def both():
        await asyncio.gather(worker(), worker())

    run(both())
    with superuser() as conn:
        loaded = conn.execute("SELECT count(*) FROM audit.events WHERE event_id = ANY(%s)", (ids,)).fetchone()[0]
        hits = conn.execute("SELECT count(*) FROM audit.rule_hits WHERE event_id = ANY(%s)", (ids,)).fetchone()[0]
    assert loaded == 120 and hits == 120


def test_backoff_grows_and_caps():
    assert 1 <= audit_worker.backoff_seconds(1) <= 1.25
    assert 8 <= audit_worker.backoff_seconds(4) <= 10
    assert audit_worker.backoff_seconds(30) <= 75


# --------------------------------------------------------------------------- scheduler


@pytest.fixture
def user_with_cart():
    with superuser() as conn:
        user = conn.execute(
            "INSERT INTO commerce.users (login_email, password_hash) VALUES (%s, 'x') RETURNING id",
            (f"sched-{uuid.uuid4().hex[:8]}@example.invalid",),
        ).fetchone()[0]
        cart = conn.execute("INSERT INTO commerce.carts (user_id) VALUES (%s) RETURNING id", (user,)).fetchone()[0]
        ruleset = conn.execute("SELECT id FROM threat_intel.rulesets WHERE state = 'active'").fetchone()[0]
    return {"user": user, "cart": cart, "ruleset": ruleset}


def make_action(ctx, *, state="pending", age="10 minutes", ttl="5 minutes", resolved_age=None, session=None):
    with superuser() as conn:
        return conn.execute(
            "INSERT INTO commerce.actions (request_id, user_id, session_id, tool_name, target_id, arguments,"
            " arguments_hash, base_version, ruleset_version, state, created_at, expires_at, resolved_at, result)"
            " VALUES (%s, %s, %s, 'remove_coupon', %s, '{}', %s, 0, %s, %s, now() - %s::interval,"
            " now() - %s::interval + %s::interval, %s, %s) RETURNING id",
            (uuid.uuid4(), ctx["user"], session, ctx["cart"], "0" * 64, ctx["ruleset"], state, age, age, ttl,
             None if resolved_age is None else _ago(resolved_age), Jsonb({"ok": True}) if state == "executed" else None),
        ).fetchone()[0]  # fmt: skip


def _ago(interval: str):
    with superuser() as conn:
        return conn.execute("SELECT now() - %s::interval", (interval,)).fetchone()[0]


def test_expired_pending_actions_get_system_event(user_with_cart):
    stale = make_action(user_with_cart, age="10 minutes", ttl="5 minutes")
    fresh = make_action(user_with_cart, age="1 minute", ttl="5 minutes")

    async def go():
        async with await psycopg.AsyncConnection.connect(login(*MAINTENANCE)) as conn:
            return await scheduler.expire_actions(conn)

    assert run(go()) >= 1
    with superuser() as conn:
        states = dict(
            conn.execute("SELECT id, state FROM commerce.actions WHERE id = ANY(%s)", ([stale, fresh],)).fetchall()
        )
        event = conn.execute(
            "SELECT payload->>'source' FROM audit.outbox WHERE payload->'tool_executions'->0->>'action_id' = %s",
            (str(stale),),
        ).fetchone()
    assert states == {stale: "expired", fresh: "pending"} and event == ("system",)


def test_expired_coupons(user_with_cart):
    with superuser() as conn:
        coupon = conn.execute(
            "INSERT INTO commerce.coupons (code, discount_krw, expires_at) VALUES (%s, 1000, now() - interval '1 day')"
            " RETURNING id",
            (f"OLD{uuid.uuid4().hex[:8]}",),
        ).fetchone()[0]
        held = conn.execute(
            "INSERT INTO commerce.user_coupons (user_id, coupon_id) VALUES (%s, %s) RETURNING id",
            (user_with_cart["user"], coupon),
        ).fetchone()[0]

    async def go():
        async with await psycopg.AsyncConnection.connect(login(*MAINTENANCE)) as conn:
            return await scheduler.expire_coupons(conn)

    assert run(go()) >= 1
    with superuser() as conn:
        assert conn.execute("SELECT state FROM commerce.user_coupons WHERE id = %s", (held,)).fetchone()[0] == "expired"


def test_retention_deletes_only_what_policy_allows(user_with_cart):
    ctx = user_with_cart
    with superuser() as conn:

        def session(age):
            return conn.execute(
                "INSERT INTO commerce.chat_sessions (user_id, source, last_activity_at) VALUES (%s, 'web', now() - %s::interval)"
                " RETURNING id",
                (ctx["user"], age),
            ).fetchone()[0]

        old_session, referenced_session, recent_session = session("40 days"), session("40 days"), session("1 day")
        outbox = {}
        for label, state, age in (
            ("delivered_old", "delivered", "2 days"),
            ("delivered_new", "delivered", "1 hour"),
            ("pending_old", "pending", "2 days"),
            ("dead_old", "dead", "30 days"),
        ):
            eid = uuid.uuid4()
            conn.execute(
                "INSERT INTO audit.outbox (event_id, payload, delivery_state, created_at, delivered_at)"
                " VALUES (%s, '{}', %s, now() - %s::interval, CASE WHEN %s = 'delivered' THEN now() - %s::interval END)",
                (eid, state, age, state, age),
            )
            outbox[label] = eid
        old_event, new_event = uuid.uuid4(), uuid.uuid4()
        for eid, age in ((old_event, "100 days"), (new_event, "10 days")):
            conn.execute(
                "INSERT INTO audit.events (event_id, request_id, source, api_path, status, summary_redacted, occurred_at)"
                " VALUES (%s, %s, 'web', '/x', 'success', 's', now() - %s::interval)",
                (eid, uuid.uuid4(), age),
            )
            conn.execute(
                "INSERT INTO audit.rule_hits (event_id, rule_id, category, stage, action, match_count)"
                " VALUES (%s, 'RULE_PHONE', 'LLM02:2025', 'output', 'mask', 1)",
                (eid,),
            )
        tokens = {}
        for label, revoked in (("revoked_old", "10 days"), ("revoked_new", "1 day")):
            tokens[label] = conn.execute(
                "INSERT INTO commerce.refresh_tokens (user_id, token_hash, family_id, created_at, expires_at, revoked_at)"
                " VALUES (%s, %s, %s, now() - interval '20 days', now() + interval '1 day', now() - %s::interval)"
                " RETURNING id",
                (ctx["user"], uuid.uuid4().hex + uuid.uuid4().hex, uuid.uuid4(), revoked),
            ).fetchone()[0]
    old_terminal = make_action(ctx, state="executed", age="45 days", resolved_age="40 days")
    recent_terminal = make_action(
        ctx, state="executed", age="3 days", resolved_age="2 days", session=referenced_session
    )
    old_pending = make_action(ctx, state="pending", age="45 days", ttl="5 minutes")

    async def go():
        async with await psycopg.AsyncConnection.connect(login(*RETENTION)) as conn:
            return await scheduler.purge(conn)

    run(go())
    with superuser() as conn:

        def exists(table, key, value):
            return conn.execute(f"SELECT count(*) FROM {table} WHERE {key} = %s", (value,)).fetchone()[0] == 1

        assert not exists("audit.outbox", "event_id", outbox["delivered_old"])
        assert exists("audit.outbox", "event_id", outbox["delivered_new"])
        assert exists("audit.outbox", "event_id", outbox["pending_old"])  # never delete undelivered events
        assert exists("audit.outbox", "event_id", outbox["dead_old"])
        assert not exists("audit.events", "event_id", old_event) and exists("audit.events", "event_id", new_event)
        assert conn.execute("SELECT count(*) FROM audit.rule_hits WHERE event_id = %s", (old_event,)).fetchone()[0] == 0
        assert not exists("commerce.actions", "id", old_terminal)
        assert exists("commerce.actions", "id", recent_terminal) and exists("commerce.actions", "id", old_pending)
        assert not exists("commerce.chat_sessions", "id", old_session)
        assert exists("commerce.chat_sessions", "id", referenced_session)  # still referenced by an action
        assert exists("commerce.chat_sessions", "id", recent_session)
        assert not exists("commerce.refresh_tokens", "id", tokens["revoked_old"])
        assert exists("commerce.refresh_tokens", "id", tokens["revoked_new"])
        # The deliberately old pending row would otherwise trip the readiness backlog check later.
        conn.execute(
            "DELETE FROM audit.outbox WHERE event_id = ANY(%s)", ([outbox["pending_old"], outbox["dead_old"]],)
        )


def test_worker_roles_stay_in_their_lane():
    async def go():
        async with await psycopg.AsyncConnection.connect(login(*RETENTION)) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                await conn.execute("UPDATE commerce.actions SET state = 'expired'")
        async with await psycopg.AsyncConnection.connect(login(*MAINTENANCE)) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                await conn.execute("DELETE FROM audit.events")
        async with await psycopg.AsyncConnection.connect(login(*WORKER)) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                await conn.execute("SELECT * FROM commerce.carts")

    run(go())


# ---------------------------------------------------------------------- readiness backlog


def test_readiness_fails_on_old_backlog(client):
    event_id = uuid.uuid4()
    with superuser() as conn:
        conn.execute(
            "INSERT INTO audit.outbox (event_id, payload, created_at) VALUES (%s, '{}', now() - interval '20 minutes')",
            (event_id,),
        )
    try:
        r = client.get("/api/v1/health/ready")
        assert r.status_code == 503 and r.json()["data"]["checks"]["outbox_backlog"] is False
    finally:
        with superuser() as conn:
            conn.execute("DELETE FROM audit.outbox WHERE event_id = %s", (event_id,))
    assert client.get("/api/v1/health/ready").json()["data"]["checks"]["outbox_backlog"] is True
