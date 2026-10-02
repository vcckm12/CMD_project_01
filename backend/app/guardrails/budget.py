"""Time budget for one inspection. Every regex call gets min(per-call timeout, remaining budget)."""

from __future__ import annotations

import time
from collections.abc import Iterator

import regex

from app.guardrails.types import GuardrailTimeout

# Long texts are scanned in overlapping windows so a single regex call stays well under its timeout.
# The overlap must exceed the longest match any rule can produce (bounded repeats keep it < 512).
WINDOW = 2000
OVERLAP = 512


class Budget:
    def __init__(self, total_ms: float, per_call_ms: float = 2.0) -> None:
        self.started = time.perf_counter()
        self.deadline = self.started + total_ms / 1000
        self.per_call = per_call_ms / 1000

    def _timeout(self) -> float:
        remaining = self.deadline - time.perf_counter()
        if remaining <= 0:
            raise GuardrailTimeout
        return min(self.per_call, remaining)

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
