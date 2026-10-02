"""Async connection pools, one per least-privilege login role (DES-002 §5)."""

from __future__ import annotations

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool


class Pools:
    def __init__(self, auth_url: str) -> None:
        # Small pool: FastAPI runs a single worker (DES-001 §2).
        self.auth = AsyncConnectionPool(
            auth_url, min_size=1, max_size=5, open=False, kwargs={"row_factory": dict_row}, name="auth"
        )

    async def open(self) -> None:
        await self.auth.open(wait=True, timeout=30)

    async def close(self) -> None:
        await self.auth.close()
