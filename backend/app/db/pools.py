"""Async connection pools, one per least-privilege login role (DES-002 §5)."""

from __future__ import annotations

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool


def _pool(url: str, name: str, max_size: int) -> AsyncConnectionPool:
    # Small pools: FastAPI runs a single worker (DES-001 §2).
    return AsyncConnectionPool(
        url, min_size=1, max_size=max_size, open=False, kwargs={"row_factory": dict_row}, name=name
    )


class Pools:
    def __init__(
        self,
        auth_url: str,
        chat_url: str | None = None,
        audit_url: str | None = None,
        rules_url: str | None = None,
    ) -> None:
        self.auth = _pool(auth_url, "auth", 5)
        # chat: shop_reader + shop_writer + rule_reader + audit_ingest + alert_writer
        self.chat = _pool(chat_url, "chat", 5) if chat_url else None
        # audit: audit_reader + alert_manager (ops dashboard; no commerce data, no payloads)
        self.audit = _pool(audit_url, "audit", 3) if audit_url else None
        # rules: rule_publisher + rule_reader + audit_ingest (admin ruleset changes)
        self.rules = _pool(rules_url, "rules", 2) if rules_url else None

    def _all(self) -> list[AsyncConnectionPool]:
        return [p for p in (self.auth, self.chat, self.audit, self.rules) if p is not None]

    async def open(self) -> None:
        for pool in self._all():
            await pool.open(wait=True, timeout=30)

    async def close(self) -> None:
        for pool in reversed(self._all()):
            await pool.close()
