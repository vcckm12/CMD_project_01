"""Scheduler: expiry every minute, retention once a day (D-18, DES-002 §8, DES-007 §6.2).

Two connections with different least-privilege logins:
- maintenance_worker: pending actions past expiry → expired (one system outbox event per action), and
  user coupons past their coupon's expiry → expired (one summary event).
- retention_worker: deletes only what the retention table allows, in bounded batches. Pending/dead
  outbox rows and pending actions are never deleted; sessions still referenced by actions are kept.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
import uuid
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.audit.outbox import AuditEnvelope, ToolExecution

log = logging.getLogger("app.scheduler")

BATCH = 500
HEARTBEAT = Path(os.environ.get("WORKER_HEARTBEAT_FILE", "/tmp/scheduler.heartbeat"))  # noqa: S108

# (label, SQL deleting at most %(batch)s rows). Periods follow DES-002 §8.
RETENTION: tuple[tuple[str, str], ...] = (
    ("outbox_delivered", "DELETE FROM audit.outbox WHERE event_id IN (SELECT event_id FROM audit.outbox"
     " WHERE delivery_state = 'delivered' AND delivered_at < now() - interval '24 hours' LIMIT %(batch)s)"),
    ("audit_events", "DELETE FROM audit.events WHERE event_id IN (SELECT event_id FROM audit.events"
     " WHERE occurred_at < now() - interval '90 days' LIMIT %(batch)s)"),
    ("alerts_acknowledged", "DELETE FROM audit.alerts WHERE id IN (SELECT id FROM audit.alerts"
     " WHERE state = 'acknowledged' AND acknowledged_at < now() - interval '90 days' LIMIT %(batch)s)"),
    ("actions_terminal", "DELETE FROM commerce.actions WHERE id IN (SELECT id FROM commerce.actions"
     " WHERE state <> 'pending' AND resolved_at < now() - interval '30 days' LIMIT %(batch)s)"),
    ("chat_sessions", "DELETE FROM commerce.chat_sessions WHERE id IN (SELECT s.id FROM commerce.chat_sessions s"
     " WHERE s.last_activity_at < now() - interval '30 days'"
     " AND NOT EXISTS (SELECT 1 FROM commerce.actions a WHERE a.session_id = s.id) LIMIT %(batch)s)"),
    ("refresh_tokens", "DELETE FROM commerce.refresh_tokens WHERE id IN (SELECT id FROM commerce.refresh_tokens"
     " WHERE coalesce(revoked_at, expires_at) < now() - interval '7 days' LIMIT %(batch)s)"),
    ("client_tokens", "DELETE FROM commerce.client_tokens WHERE id IN (SELECT id FROM commerce.client_tokens"
     " WHERE coalesce(revoked_at, expires_at) < now() - interval '7 days' LIMIT %(batch)s)"),
)  # fmt: skip


def _system_event(summary: str, *, session_id=None, tool: ToolExecution | None = None) -> AuditEnvelope:
    return AuditEnvelope(
        request_id=uuid.uuid4(),
        actor_id=None,
        session_id=session_id,
        source="system",
        api_path="scheduler",
        status="success",
        summary_redacted=summary,
        tool_executions=(tool,) if tool else (),
    )


async def _outbox(cur: psycopg.AsyncCursor, env: AuditEnvelope) -> None:
    await cur.execute(
        "INSERT INTO audit.outbox (event_id, payload) VALUES (%s, %s)",
        (env.event_id, Jsonb(env.model_dump(mode="json"))),
    )


async def expire_actions(conn: psycopg.AsyncConnection) -> int:
    async with conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "UPDATE commerce.actions SET state = 'expired', resolved_at = now()"
            " WHERE id IN (SELECT id FROM commerce.actions WHERE state = 'pending' AND expires_at <= now()"
            " ORDER BY expires_at LIMIT %s FOR UPDATE SKIP LOCKED)"
            " RETURNING id, session_id, tool_name, target_id",
            (BATCH,),
        )
        rows = await cur.fetchall()
        for r in rows:
            await _outbox(cur, _system_event(
                "변경 확인 만료(스케줄러)", session_id=r["session_id"],
                tool=ToolExecution(action_id=r["id"], tool_name=r["tool_name"], outcome="denied",
                                   target_id=r["target_id"], duration_ms=0),
            ))  # fmt: skip
    return len(rows)


async def expire_coupons(conn: psycopg.AsyncConnection) -> int:
    async with conn.transaction(), conn.cursor() as cur:
        await cur.execute(
            "UPDATE commerce.user_coupons uc SET state = 'expired' FROM commerce.coupons c"
            " WHERE c.id = uc.coupon_id AND uc.state = 'available' AND c.expires_at <= now()"
        )
        count = cur.rowcount
        if count:
            await _outbox(cur, _system_event(f"보유 쿠폰 만료 처리 {count}건(스케줄러)"))
    return count


async def purge(conn: psycopg.AsyncConnection, max_rounds: int = 1000) -> dict[str, int]:
    """Delete expired data in batches until nothing is left (bounded by max_rounds per table)."""
    removed: dict[str, int] = {}
    for label, statement in RETENTION:
        total = 0
        for _ in range(max_rounds):
            async with conn.transaction(), conn.cursor() as cur:
                await cur.execute(statement, {"batch": BATCH})
                total += cur.rowcount
                if cur.rowcount < BATCH:
                    break
        removed[label] = total
    return removed


async def run(maintenance_dsn: str, retention_dsn: str, *, expiry_interval_s: float = 60.0,
              retention_interval_s: float = 86400.0) -> None:  # fmt: skip
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    last_retention = 0.0
    while not stop.is_set():
        try:
            async with await psycopg.AsyncConnection.connect(maintenance_dsn) as conn:
                actions, coupons = await expire_actions(conn), await expire_coupons(conn)
            if actions or coupons:
                log.info("expired actions=%d coupons=%d", actions, coupons)
            if time.monotonic() - last_retention >= retention_interval_s or last_retention == 0.0:
                async with await psycopg.AsyncConnection.connect(retention_dsn) as conn:
                    log.info("retention %s", await purge(conn))
                last_retention = time.monotonic()
            HEARTBEAT.write_text(str(time.time()), encoding="utf-8")
        except psycopg.Error as exc:
            log.error("scheduler cycle failed class=%s", type(exc).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=expiry_interval_s)
        except TimeoutError:
            pass


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(run(os.environ["MAINTENANCE_DATABASE_URL"], os.environ["RETENTION_DATABASE_URL"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
