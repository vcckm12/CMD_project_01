"""Ruleset publish lifecycle on PostgreSQL (DES-006 §6). Maps to T-18."""

import asyncio
import dataclasses
import os
import uuid

import psycopg
import pytest

from app.guardrails import rule_store
from app.guardrails.rule_cache import RuleCache
from app.guardrails.ruleset import DEFAULT_RULES, RulesetInvalid
from tests.conftest import _dsn


def run(coro):
    return asyncio.run(coro)


async def rules_conn() -> psycopg.AsyncConnection:
    return await psycopg.AsyncConnection.connect(_dsn("ag_rules", os.environ["TEST_RULES_PASSWORD"]))


def superuser():
    return psycopg.connect(_dsn("postgres", os.environ["TEST_SUPERUSER_PASSWORD"]), autocommit=True)


@pytest.fixture(scope="module")
def admin_id():
    with superuser() as conn:
        return conn.execute(
            "INSERT INTO commerce.users (login_email, password_hash, role) VALUES (%s, 'x', 'admin') RETURNING id",
            (f"rules-{uuid.uuid4().hex[:8]}@example.invalid",),
        ).fetchone()[0]


def label() -> str:
    return f"test-{uuid.uuid4().hex[:10]}"


async def _draft_and_validate(conn, actor, rules=DEFAULT_RULES):
    draft = await rule_store.create_draft(conn, label=label(), actor_id=actor, rules=rules)
    return draft, await rule_store.validate_draft(conn, draft)


def test_publish_and_rollback_lifecycle(admin_id):
    async def scenario():
        async with await rules_conn() as conn:
            previous = await rule_store.active_id(conn)
            draft, failures = await _draft_and_validate(conn, admin_id)
            assert failures == []
            request_id = uuid.uuid4()
            snapshot = await rule_store.publish(
                conn, ruleset_id=draft, expected_active_id=previous, actor_id=admin_id, request_id=request_id
            )
            assert snapshot.version_id == draft and await rule_store.active_id(conn) == draft
            if previous is not None:
                await rule_store.publish(
                    conn, ruleset_id=previous, expected_active_id=draft, actor_id=admin_id, request_id=uuid.uuid4()
                )
                assert await rule_store.active_id(conn) == previous
            return draft, previous, request_id

    draft, previous, request_id = run(scenario())
    with superuser() as conn:
        states = dict(conn.execute("SELECT id, state FROM threat_intel.rulesets WHERE id = ANY(%s)",
                                   ([draft] + ([previous] if previous else []),)).fetchall())  # fmt: skip
        outcomes = [r[0] for r in conn.execute(
            "SELECT outcome FROM threat_intel.policy_publications WHERE ruleset_id = ANY(%s) ORDER BY created_at",
            ([draft] + ([previous] if previous else []),)).fetchall()]  # fmt: skip
        events = conn.execute(
            "SELECT count(*) FROM audit.outbox WHERE payload->>'request_id' = %s", (str(request_id),)
        ).fetchone()[0]
    assert events == 1
    if previous is not None:
        assert states == {draft: "retired", previous: "active"} and "rolled_back" in outcomes


def test_publish_conflict_changes_nothing(admin_id):
    async def scenario():
        async with await rules_conn() as conn:
            before = await rule_store.active_id(conn)
            draft, _ = await _draft_and_validate(conn, admin_id)
            with pytest.raises(rule_store.PublishConflict):
                await rule_store.publish(
                    conn, ruleset_id=draft, expected_active_id=uuid.uuid4(), actor_id=admin_id,
                    request_id=uuid.uuid4(),
                )  # fmt: skip
            return before, await rule_store.active_id(conn)

    before, after = run(scenario())
    assert before == after


def test_invalid_draft_stays_draft(admin_id):
    broken = [dataclasses.replace(r, pattern="(unclosed") if r.rule_id == "RULE_RRN" else r for r in DEFAULT_RULES]

    async def scenario():
        async with await rules_conn() as conn:
            draft, failures = await _draft_and_validate(conn, admin_id, broken)
            row = await (await conn.execute("SELECT state FROM threat_intel.rulesets WHERE id=%s", (draft,))).fetchone()
            with pytest.raises(RulesetInvalid):
                await rule_store.publish(
                    conn, ruleset_id=draft, expected_active_id=await rule_store.active_id(conn), actor_id=admin_id,
                    request_id=uuid.uuid4(),
                )  # fmt: skip
            return failures, row[0]

    failures, state = run(scenario())
    assert "REGEX_COMPILE:RULE_RRN" in failures and state == "draft"


def test_validated_rules_cannot_change(admin_id):
    async def scenario():
        async with await rules_conn() as conn:
            draft, _ = await _draft_and_validate(conn, admin_id)
            with pytest.raises(psycopg.errors.RaiseException, match="ruleset is immutable"):
                await conn.execute(
                    "UPDATE threat_intel.rules SET pattern = 'x' WHERE ruleset_id = %s AND rule_id = 'RULE_RRN'",
                    (draft,),
                )

    run(scenario())


def test_chat_role_cannot_write_rules():
    async def scenario():
        async with await psycopg.AsyncConnection.connect(_dsn("ag_chat", os.environ["TEST_CHAT_PASSWORD"])) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                await conn.execute("UPDATE threat_intel.rulesets SET state = 'retired' WHERE state = 'active'")

    run(scenario())


def test_tampered_active_ruleset_is_rejected_on_load(admin_id):
    async def scenario():
        async with await psycopg.AsyncConnection.connect(
            _dsn("postgres", os.environ["TEST_SUPERUSER_PASSWORD"])
        ) as conn:
            active = await rule_store.active_id(conn)
            assert active is not None
            # Simulate an out-of-band edit that bypasses the immutability trigger; rolled back afterwards.
            await conn.execute("ALTER TABLE threat_intel.rules DISABLE TRIGGER rules_draft_only")
            await conn.execute(
                "UPDATE threat_intel.rules SET priority = priority + 1 WHERE ruleset_id = %s AND rule_id = 'RULE_RRN'",
                (active,),
            )
            with pytest.raises(RulesetInvalid) as exc:
                await rule_store.load_active(conn)
            await conn.rollback()
            return exc.value.failures

    assert "CHECKSUM_MISMATCH" in run(scenario())


def test_rule_cache_keeps_last_good_snapshot_on_failure(monkeypatch):
    from psycopg_pool import AsyncConnectionPool

    async def scenario():
        cache = RuleCache()
        url = _dsn("ag_chat", os.environ["TEST_CHAT_PASSWORD"])
        async with AsyncConnectionPool(url, min_size=1, max_size=1, open=False) as pool:
            await pool.open()
            await cache.refresh(pool)
            good = cache.current()
            assert good is not None and cache.consistent

            async def other_active(conn):
                return uuid.uuid4()

            async def broken_load(conn):
                raise RulesetInvalid(["CHECKSUM_MISMATCH"])

            monkeypatch.setattr(rule_store, "active_id", other_active)
            monkeypatch.setattr(rule_store, "load_active", broken_load)
            await cache.refresh(pool)
            return good, cache

    good, cache = run(scenario())
    assert cache.current() is good and cache.consistent is False and cache.reload_errors == 1
