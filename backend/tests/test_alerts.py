"""Ops alerts on PostgreSQL (D-26): outage vs repeated-input signals, dedupe, roles."""

import asyncio
import os
import uuid

import psycopg
import pytest
from psycopg_pool import AsyncConnectionPool

from app.guardrails.alerts import AlertMonitor
from tests.conftest import _dsn


def run(coro):
    return asyncio.run(coro)


def superuser():
    return psycopg.connect(_dsn("postgres", os.environ["TEST_SUPERUSER_PASSWORD"]), autocommit=True)


@pytest.fixture(autouse=True)
def clean_alerts():
    with superuser() as conn:
        conn.execute("DELETE FROM audit.alerts")
    yield


def open_alerts():
    with superuser() as conn:
        return conn.execute(
            "SELECT kind, severity, fingerprint, occurrences FROM audit.alerts WHERE state = 'open' ORDER BY kind"
        ).fetchall()


async def with_monitor(steps, **kw):
    url = _dsn("ag_chat", os.environ["TEST_CHAT_PASSWORD"])
    async with AsyncConnectionPool(url, min_size=1, max_size=1, open=False) as pool:
        await pool.open()
        monitor = AlertMonitor(pool, b"unit-test-key-" * 3, **kw)
        await steps(monitor)
        return monitor


def test_outage_alert_after_three_failures_across_inputs():
    async def steps(m):
        for i in range(2):
            await m.judge_failed(f"서로 다른 질문 {i}")
        assert open_alerts() == []
        await m.judge_failed("세 번째 질문")

    run(with_monitor(steps))
    kinds = [a[0] for a in open_alerts()]
    assert kinds == ["judge_unavailable"]


def test_repeated_same_input_raises_fingerprint_alert_and_dedupes():
    async def steps(m):
        for _ in range(4):
            await m.input_failed("같은 의심 입력")

    monitor = run(with_monitor(steps))
    ((kind, severity, fingerprint, occurrences),) = open_alerts()
    assert kind == "suspicious_input_repeat" and severity == "warning"
    assert fingerprint == monitor.fingerprint("같은 의심 입력") and occurrences == 3  # 2nd, 3rd, 4th


def test_fingerprint_is_keyed_and_normalized():
    a = AlertMonitor(None, b"key-a" * 8)
    b = AlertMonitor(None, b"key-b" * 8)
    assert a.fingerprint("ｔｅｓｔ") == a.fingerprint("test")  # NFKC: same input, same fingerprint
    assert a.fingerprint("test") != b.fingerprint("test")
    assert "test" not in a.fingerprint("test")


def test_failures_outside_window_do_not_alert():
    async def steps(m):
        for _ in range(3):
            await m.judge_failed("q")

    run(with_monitor(steps, window_s=0.0))
    assert open_alerts() == []


def test_alert_holds_no_user_text():
    secret_text = "유일한-원문-" + uuid.uuid4().hex

    async def steps(m):
        await m.input_failed(secret_text)
        await m.input_failed(secret_text)

    run(with_monitor(steps))
    with superuser() as conn:
        dump = str(conn.execute("SELECT * FROM audit.alerts").fetchall())
    assert secret_text not in dump


def test_chat_role_cannot_acknowledge_alerts():
    async def steps(m):
        await m.input_failed("x")
        await m.input_failed("x")

    run(with_monitor(steps))

    async def ack():
        async with await psycopg.AsyncConnection.connect(_dsn("ag_chat", os.environ["TEST_CHAT_PASSWORD"])) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                await conn.execute("UPDATE audit.alerts SET state = 'acknowledged'")

    run(ack())


def test_acknowledged_alert_allows_a_new_open_one(db):
    db.execute(
        "INSERT INTO audit.alerts (kind, severity, detail, state, acknowledged_by, acknowledged_at)"
        " SELECT 'judge_unavailable', 'critical', 'd', 'acknowledged', id, now() FROM commerce.users LIMIT 1"
    )
    db.execute("INSERT INTO audit.alerts (kind, severity, detail) VALUES ('judge_unavailable', 'critical', 'd')")
    with pytest.raises(psycopg.errors.UniqueViolation):
        db.execute("INSERT INTO audit.alerts (kind, severity, detail) VALUES ('judge_unavailable', 'critical', 'd')")
