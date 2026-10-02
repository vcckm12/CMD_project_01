"""Immutable snapshot holder with atomic swap (DES-006 §6).

A request reads `current()` once and keeps that snapshot until it finishes. A background task polls
the DB active id; on change it loads and fully re-validates the new ruleset, then swaps the reference.
If loading fails the previous snapshot stays in use and `consistent` turns False, which fails
readiness until the DB and memory agree again (DES-001 §5, DES-007 §5).
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from psycopg_pool import AsyncConnectionPool

from app.guardrails import rule_store
from app.guardrails.ruleset import RulesetInvalid, RuleSnapshot

log = logging.getLogger("app.rules")


class RuleCache:
    def __init__(self) -> None:
        self._snapshot: RuleSnapshot | None = None
        self.consistent = False
        self.reload_errors = 0

    def current(self) -> RuleSnapshot | None:
        return self._snapshot

    def install(self, snapshot: RuleSnapshot) -> None:
        """Swap in a snapshot that was already validated (e.g. right after an in-process publish)."""
        self._snapshot = snapshot
        self.consistent = True

    async def refresh(self, pool: AsyncConnectionPool) -> None:
        try:
            async with pool.connection() as conn:
                db_active: uuid.UUID | None = await rule_store.active_id(conn)
                loaded = self._snapshot.version_id if self._snapshot else None
                if db_active is not None and db_active == loaded:
                    self.consistent = True
                    return
                snapshot = await rule_store.load_active(conn) if db_active else None
        except RulesetInvalid as exc:
            self.reload_errors += 1
            self.consistent = False
            log.error("ruleset reload rejected codes=%s", ",".join(exc.failures))
            return
        except Exception as exc:  # noqa: BLE001 - DB outages keep the last good snapshot
            self.reload_errors += 1
            self.consistent = False
            log.error("ruleset reload failed class=%s", type(exc).__name__)
            return
        if snapshot is None:
            self.consistent = False
            return
        self.install(snapshot)
        log.info("ruleset active label=%s checksum=%s", snapshot.label, snapshot.checksum[:12])

    async def run(self, pool: AsyncConnectionPool, interval_seconds: float = 5.0) -> None:
        while True:
            await self.refresh(pool)
            await asyncio.sleep(interval_seconds)
