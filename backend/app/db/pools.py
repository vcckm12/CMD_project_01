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
    def __init__(self, auth_url: str, chat_url: str | None = None) -> None:
        self.auth = _pool(auth_url, "auth", 5)
        # chat: shop_reader + shop_writer + rule_reader + audit_ingest (also loads the active ruleset)
        self.chat = _pool(chat_url, "chat", 5) if chat_url else None

    async def open(self) -> None:
        await self.auth.open(wait=True, timeout=30)
        if self.chat:
            await self.chat.open(wait=True, timeout=30)

    async def close(self) -> None:
        if self.chat:
            await self.chat.close()
        await self.auth.close()
