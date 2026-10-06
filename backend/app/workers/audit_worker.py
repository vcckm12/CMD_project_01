"""Audit worker: audit.outbox → audit.events / rule_hits / tool_executions (DES-002 §6, DES-007 §5).

- Claims up to 50 pending rows with FOR UPDATE SKIP LOCKED, so several workers never take the same row.
- Each envelope is validated against the strict AuditEnvelope schema; an unknown schema_version or an
  invalid payload goes straight to `dead` (retrying cannot fix it).
- The event and its children are inserted in a savepoint; an existing event_id counts as already
  loaded and adds no duplicate children (idempotent replays).
- Other failures (FK, transient DB errors) retry with exponential backoff 1,2,4,…,60 s + jitter and
  become `dead` after 10 attempts. Every dead event raises an `outbox_dead` alert.
Runs as the audit_worker login only: it can neither read nor change commerce data.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import signal
import sys
import time
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from pydantic import ValidationError

from app.audit.outbox import AuditEnvelope

log = logging.getLogger("app.audit_worker")

BATCH = 50
MAX_ATTEMPTS = 10
BACKOFF_CAP_S = 60
HEARTBEAT = Path(os.environ.get("WORKER_HEARTBEAT_FILE", "/tmp/audit-worker.heartbeat"))  # noqa: S108


def backoff_seconds(attempts: int) -> float:
    base = min(2 ** max(attempts - 1, 0), BACKOFF_CAP_S)
    return base + random.uniform(0, base / 4)  # noqa: S311 - jitter, not security


async def _insert_event(cur: psycopg.AsyncCursor, env: AuditEnvelope) -> bool:
    """Insert one event with its children. False when the event_id was already loaded."""
    await cur.execute(
        "INSERT INTO audit.events (event_id, request_id, actor_id, session_id, source, api_path, model, status,"
        " stage, ruleset_version, input_chars, output_chars, input_ms, output_ms, total_ms, summary_redacted,"
        " occurred_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        " ON CONFLICT (event_id) DO NOTHING",
        (env.event_id, env.request_id, env.actor_id, env.session_id, env.source, env.api_path, env.model, env.status,
         env.stage, env.ruleset_version, env.input_chars, env.output_chars, env.input_ms, env.output_ms, env.total_ms,
         env.summary_redacted, env.occurred_at),
    )  # fmt: skip
    if cur.rowcount == 0:
        return False
    for hit in env.rule_hits:
        await cur.execute(
            "INSERT INTO audit.rule_hits (event_id, rule_id, category, stage, action, match_count)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (env.event_id, hit.rule_id, hit.category, hit.stage, hit.action, hit.match_count),
        )
    for tool in env.tool_executions:
        await cur.execute(
            "INSERT INTO audit.tool_executions (event_id, action_id, tool_name, outcome, target_id, duration_ms)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (env.event_id, tool.action_id, tool.tool_name, tool.outcome, tool.target_id, tool.duration_ms),
        )
    return True


async def _alert_dead(cur: psycopg.AsyncCursor) -> None:
    await cur.execute(
        "INSERT INTO audit.alerts (kind, severity, detail) VALUES ('outbox_dead', 'critical',"
        " '감사 이벤트 적재가 반복 실패해 dead로 전환됨: schema·FK·payload 확인 후 승인된 재처리 필요')"
        " ON CONFLICT (kind, (coalesce(fingerprint, ''))) WHERE state = 'open'"
        " DO UPDATE SET occurrences = audit.alerts.occurrences + 1, last_seen_at = now()"
    )


async def drain_once(conn: psycopg.AsyncConnection) -> dict[str, int]:
    """Process one batch. Returns counters {delivered, duplicate, retried, dead}."""
    stats = {"delivered": 0, "duplicate": 0, "retried": 0, "dead": 0}
    async with conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT event_id, payload, attempts FROM audit.outbox"
            " WHERE delivery_state = 'pending' AND available_at <= now()"
            " ORDER BY available_at, created_at LIMIT %s FOR UPDATE SKIP LOCKED",
            (BATCH,),
        )
        rows = await cur.fetchall()
        for row in rows:
            try:
                env = AuditEnvelope.model_validate(row["payload"])
                if env.event_id != row["event_id"]:
                    raise ValueError("event_id mismatch")
            except (ValidationError, ValueError):
                await cur.execute(
                    "UPDATE audit.outbox SET delivery_state = 'dead', attempts = attempts + 1,"
                    " last_error_code = 'INVALID_ENVELOPE' WHERE event_id = %s",
                    (row["event_id"],),
                )
                await _alert_dead(cur)
                stats["dead"] += 1
                continue
            try:
                async with conn.transaction():  # savepoint per event
                    inserted = await _insert_event(cur, env)
            except psycopg.Error as exc:
                attempts = row["attempts"] + 1
                code = (exc.sqlstate or type(exc).__name__)[:64]
                if attempts >= MAX_ATTEMPTS:
                    await cur.execute(
                        "UPDATE audit.outbox SET delivery_state = 'dead', attempts = %s, last_error_code = %s"
                        " WHERE event_id = %s",
                        (attempts, code, row["event_id"]),
                    )
                    await _alert_dead(cur)
                    stats["dead"] += 1
                else:
                    await cur.execute(
                        "UPDATE audit.outbox SET attempts = %s, last_error_code = %s,"
                        " available_at = now() + make_interval(secs => %s) WHERE event_id = %s",
                        (attempts, code, backoff_seconds(attempts), row["event_id"]),
                    )
                    stats["retried"] += 1
                continue
            await cur.execute(
                "UPDATE audit.outbox SET delivery_state = 'delivered', delivered_at = now(), attempts = attempts + 1,"
                " last_error_code = NULL WHERE event_id = %s",
                (row["event_id"],),
            )
            stats["delivered" if inserted else "duplicate"] += 1
    return stats


async def run(dsn: str, interval_s: float = 1.0) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    while not stop.is_set():
        try:
            async with await psycopg.AsyncConnection.connect(dsn) as conn:
                while not stop.is_set():
                    stats = await drain_once(conn)
                    HEARTBEAT.write_text(str(time.time()), encoding="utf-8")
                    if any(stats.values()):
                        log.info("batch %s", stats)
                    if stats["delivered"] + stats["duplicate"] < BATCH:
                        try:
                            await asyncio.wait_for(stop.wait(), timeout=interval_s)
                        except TimeoutError:
                            pass
        except psycopg.OperationalError as exc:
            log.error("database unavailable class=%s; retrying", type(exc).__name__)
            try:
                await asyncio.wait_for(stop.wait(), timeout=5)
            except TimeoutError:
                pass


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(run(os.environ["AUDIT_WORKER_DATABASE_URL"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
