"""Time budget for one inspection.

The stage budget is counted in CPU time of the inspecting thread (time.thread_time), so waiting for the
GIL or for other requests does not count as inspection time; a 5 ms thread switch interval made
wall-clock budgets fail long benign inputs at random. Each regex call additionally has a wall-clock
timeout (default 20 ms) as the ReDoS safety net: catastrophic backtracking burns CPU and is cut off by
either limit.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import regex

from app.guardrails.types import GuardrailTimeout

# Long texts are scanned in overlapping windows so a single regex call stays well under its timeout.
# The overlap must exceed the longest match any rule can produce (bounded repeats keep it < 512).
WINDOW = 2000
OVERLAP = 512
# The stage budget (D-16) covers 8,000 characters; longer inputs (full compat histories, long answers)
# get proportionally more so legitimate long text is not refused.
BUDGET_UNIT_CHARS = 8000


def scaled_budget_ms(base_ms: float, chars: int) -> float:
    return base_ms * max(1.0, chars / BUDGET_UNIT_CHARS)


class Budget:
    def __init__(self, total_ms: float, per_call_ms: float = 20.0) -> None:
        self.started = time.perf_counter()
        self.cpu_started = time.thread_time()
        self.cpu_budget = total_ms / 1000
        self.per_call = per_call_ms / 1000

    def _timeout(self) -> float:
        if time.thread_time() - self.cpu_started >= self.cpu_budget:
            raise GuardrailTimeout
        return self.per_call

    def elapsed_ms(self) -> float:
        return round((time.perf_counter() - self.started) * 1000, 3)

    def finditer(self, pattern: regex.Pattern, text: str) -> Iterator[regex.Match]:
        """Matches over windows, de-duplicated by absolute span. Raises GuardrailTimeout."""
        seen: set[tuple[int, int]] = set()
        for offset in _window_offsets(len(text)):
            chunk = text[offset : offset + WINDOW]
            try:
                matches = list(pattern.finditer(chunk, timeout=self._timeout()))
            except TimeoutError as exc:
                raise GuardrailTimeout from exc
            for m in matches:
                span = (offset + m.start(), offset + m.end())
                if span not in seen:
                    seen.add(span)
                    yield _Shifted(m, offset)

    def search(self, pattern: regex.Pattern, text: str) -> bool:
        for _ in self.finditer(pattern, text):
            return True
        return False


def _window_offsets(length: int) -> list[int]:
    if length <= WINDOW:
        return [0]
    offsets = list(range(0, length - WINDOW, WINDOW - OVERLAP))
    offsets.append(length - WINDOW)  # last window always ends exactly at the text end
    return offsets


class _Shifted:
    """Match view with spans shifted back to the full-text coordinates."""

    __slots__ = ("_m", "_offset")

    def __init__(self, m: regex.Match, offset: int) -> None:
        self._m = m
        self._offset = offset

    def start(self, group: int | str = 0) -> int:
        s = self._m.start(group)
        return s if s < 0 else s + self._offset

    def end(self, group: int | str = 0) -> int:
        e = self._m.end(group)
        return e if e < 0 else e + self._offset

    def span(self, group: int | str = 0) -> tuple[int, int]:
        return self.start(group), self.end(group)

    def group(self, group: int | str = 0) -> str:
        return self._m.group(group)

    def groupdict(self) -> dict:
        return self._m.groupdict()
