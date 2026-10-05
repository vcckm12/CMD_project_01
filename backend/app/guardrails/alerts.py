"""Judge/guardrail failure monitor (D-26).

Two signals, kept apart because they need different admin actions:
- judge_unavailable: failures across all requests within a window → model server problem.
- suspicious_input_repeat: the same input (keyed fingerprint) failing again → likely an input built to
  stall the guardrails (DoS) rather than an outage.
Counters live in memory (single worker); crossing a threshold upserts one open alert row per
kind/fingerprint. Alert writes never fail the user request.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from collections import defaultdict, deque

from psycopg_pool import AsyncConnectionPool

from app.guardrails.normalize import canonical

log = logging.getLogger("app.alerts")

DETAILS = {
    "judge_unavailable": "AI 판별 모델 응답 실패가 반복됨: 모델 서버 상태 확인 필요",
    "suspicious_input_repeat": "같은 입력에서 가드레일 시간 초과·판별 실패가 반복됨: 의도적 지연 공격 의심",
}


class AlertMonitor:
    def __init__(
        self,
        pool: AsyncConnectionPool | None,
        fingerprint_key: bytes,
        *,
        window_s: float = 300.0,
        outage_threshold: int = 3,
        input_threshold: int = 2,
    ) -> None:
        self.pool = pool
        self.key = fingerprint_key
        self.window_s = window_s
        self.outage_threshold = outage_threshold
        self.input_threshold = input_threshold
        self._failures: deque[float] = deque()
        self._by_input: dict[str, deque[float]] = defaultdict(deque)

    def fingerprint(self, text: str) -> str:
        """Keyed so a stored fingerprint cannot be reversed by hashing guessed short inputs."""
        return hmac.new(self.key, canonical(text).encode("utf-8"), hashlib.sha256).hexdigest()

    def _recent(self, q: deque[float], now: float) -> int:
        while q and now - q[0] > self.window_s:
            q.popleft()
        return len(q)

    async def judge_failed(self, text: str) -> None:
        now = time.monotonic()
        self._failures.append(now)
        if self._recent(self._failures, now) >= self.outage_threshold:
            await self._raise("judge_unavailable", "critical", None)
        await self.input_failed(text)

    async def input_failed(self, text: str) -> None:
        """Also called for rule-engine timeouts, which are input-specific by nature."""
        now = time.monotonic()
        fp = self.fingerprint(text)
        q = self._by_input[fp]
        q.append(now)
        if self._recent(q, now) >= self.input_threshold:
            await self._raise("suspicious_input_repeat", "warning", fp)
        if len(self._by_input) > 10_000:  # bound memory under attack: drop idle fingerprints
            for key in [k for k, v in self._by_input.items() if self._recent(v, now) == 0]:
                del self._by_input[key]

    async def _raise(self, kind: str, severity: str, fingerprint: str | None) -> None:
        log.warning("alert kind=%s fingerprint=%s", kind, fingerprint[:12] if fingerprint else "-")
        if self.pool is None:
            return
        try:
            async with self.pool.connection() as conn:
                await conn.execute(
                    "INSERT INTO audit.alerts (kind, severity, fingerprint, detail) VALUES (%s, %s, %s, %s)"
                    " ON CONFLICT (kind, (coalesce(fingerprint, ''))) WHERE state = 'open'"
                    " DO UPDATE SET occurrences = audit.alerts.occurrences + 1, last_seen_at = now()",
                    (kind, severity, fingerprint, DETAILS[kind]),
                )
        except Exception as exc:  # noqa: BLE001 - the alert path must not break the response path
            log.error("alert write failed class=%s", type(exc).__name__)
