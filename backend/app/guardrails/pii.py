"""Output PII / secret span detection (DES-006 §4.2).

Spans always point into the original text. Separator-split digits ("8 8 0 1 1 5 - 1 0 4 ...") are
found on a compacted copy whose indexes map back to the original positions.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import regex

from app.guardrails.budget import Budget
from app.guardrails.normalize import BASE64_CANDIDATE, HEX_ESCAPED, _decode_base64
from app.guardrails.ruleset import RuleSnapshot

PII_RULES = ("RULE_RRN", "RULE_PHONE", "RULE_EMAIL", "RULE_ADDRESS", "RULE_CARD", "RULE_ACCOUNT")
SECRET_RULES = ("RULE_SECRET", "RULE_TOKEN_SECRET")

JWT = regex.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
CLIENT_TOKEN = regex.compile(r"\bgct_[A-Za-z0-9_-]{20,}")
FINGERPRINT_TOKEN = regex.compile(r"[^\s\"'`<>()\[\]{},;]{8,128}")
CARD_CONTEXT = regex.compile(r"카드|card|visa|master|amex|결제|신용|체크", regex.I)
CARD_GROUPED = regex.compile(r"^\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}$")
ADDRESS_CONTEXT = regex.compile(r"주소|배송지|거주지|사는\s{0,2}곳|자택|address", regex.I)
ADDRESS_DETAIL = regex.compile(r"(?:\s{0,3},?\s{0,3}\d{1,5}\s{0,2}(?:동|호|층|번지))+")
DIGIT_SEPARATORS = frozenset(" \t.-_·")


@dataclass(frozen=True, order=True)
class Span:
    start: int
    end: int
    priority: int
    rule_id: str
    marker: str
    value: str = ""


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def rrn_date_ok(digits: str) -> bool:
    month, day = int(digits[2:4]), int(digits[4:6])
    return 1 <= month <= 12 and 1 <= day <= 31


def digit_compact(text: str) -> tuple[str, list[int]]:
    """Drop separators that sit between digits; return compact text and index map to the original."""
    kept: list[str] = []
    index: list[int] = []
    n = len(text)
    for i, ch in enumerate(text):
        if ch in DIGIT_SEPARATORS and kept and kept[-1].isdigit():
            j = i
            while j < n and j - i < 3 and text[j] in DIGIT_SEPARATORS:
                j += 1
            if j < n and text[j].isdigit():
                continue
        kept.append(ch)
        index.append(i)
    return "".join(kept), index


class Detector:
    def __init__(self, snapshot: RuleSnapshot, budget: Budget) -> None:
        self.snapshot = snapshot
        self.budget = budget

    def _rule(self, rule_id: str):
        compiled = self.snapshot.get(rule_id)
        return compiled if compiled and compiled.rule.action == "mask" else None

    def _span(self, rule_id: str, start: int, end: int, text: str) -> Span:
        r = self.snapshot.get(rule_id).rule
        return Span(start, end, r.priority, rule_id, r.marker or "[REDACTED]", text[start:end])

    def spans(self, text: str) -> list[Span]:
        found: list[Span] = []
        found += self._secret(text)
        found += self._tokens(text)
        compact, index = digit_compact(text)
        for rule_id, check in (("RULE_RRN", self._rrn_ok), ("RULE_CARD", self._card_ok), ("RULE_PHONE", None)):
            found += self._digits(rule_id, text, compact, index, check)
        found += self._value_group("RULE_ACCOUNT", text)
        found += self._plain("RULE_EMAIL", text)
        found += self._address(text)
        return found

    # --------------------------------------------------------------- per rule

    def _value_group(self, rule_id: str, text: str) -> list[Span]:
        rule = self._rule(rule_id)
        if not rule:
            return []
        out = []
        for m in self.budget.finditer(rule.pattern, text):
            start, end = m.span("value") if "value" in m.groupdict() and m.start("value") >= 0 else m.span()
            out.append(self._span(rule_id, start, end, text))
        return out

    def _secret(self, text: str) -> list[Span]:
        return self._value_group("RULE_SECRET", text)

    def _tokens(self, text: str) -> list[Span]:
        if not self._rule("RULE_TOKEN_SECRET"):
            return []
        out = []
        for pattern in (JWT, CLIENT_TOKEN):
            for m in self.budget.finditer(pattern, text):
                out.append(self._span("RULE_TOKEN_SECRET", m.start(), m.end(), text))
        return out

    def _plain(self, rule_id: str, text: str) -> list[Span]:
        rule = self._rule(rule_id)
        if not rule:
            return []
        return [self._span(rule_id, m.start(), m.end(), text) for m in self.budget.finditer(rule.pattern, text)]

    @staticmethod
    def _rrn_ok(value: str, text: str, start: int) -> bool:
        digits = "".join(ch for ch in value if ch.isdigit())
        return len(digits) == 13 and rrn_date_ok(digits)

    @staticmethod
    def _card_ok(value: str, text: str, start: int) -> bool:
        digits = "".join(ch for ch in value if ch.isdigit())
        if not 13 <= len(digits) <= 19 or not luhn_ok(digits):
            return False
        context = text[max(0, start - 40) : start]
        return bool(CARD_CONTEXT.search(context)) or bool(CARD_GROUPED.match(value.strip()))

    def _digits(self, rule_id: str, text: str, compact: str, index: list[int], check) -> list[Span]:
        rule = self._rule(rule_id)
        if not rule:
            return []
        out = []
        for source, mapping in ((text, None), (compact, index)):
            if mapping is not None and compact == text:
                break
            for m in self.budget.finditer(rule.pattern, source):
                start, end = m.span()
                if mapping is not None:
                    start, end = mapping[start], mapping[end - 1] + 1
                value = text[start:end]
                if check is None or check(value, text, start):
                    out.append(self._span(rule_id, start, end, text))
        return out

    def _address(self, text: str) -> list[Span]:
        rule = self._rule("RULE_ADDRESS")
        if not rule:
            return []
        out = []
        for m in self.budget.finditer(rule.pattern, text):
            start, end = m.span()
            detail = ADDRESS_DETAIL.match(text, end)
            has_detail = detail is not None and detail.end() > end
            labelled = ADDRESS_CONTEXT.search(text[max(0, start - 30) : start]) is not None
            if labelled or has_detail:
                out.append(self._span("RULE_ADDRESS", start, detail.end() if has_detail else end, text))
        return out


def fingerprint_hits(text: str, fingerprints: frozenset[str], budget: Budget) -> bool:
    """Exact match of registered secret fingerprints against candidate tokens (DES-006 §4.2)."""
    if not fingerprints:
        return False
    for m in budget.finditer(FINGERPRINT_TOKEN, text):
        token = m.group().strip(".:!?")
        if hashlib.sha256(token.encode("utf-8")).hexdigest() in fingerprints:
            return True
    return False


def encoded_tokens(text: str, budget: Budget) -> list[tuple[int, int, str]]:
    """(start, end, decoded_text) for Base64 / \\xNN tokens in the output that decode to text."""
    out = []
    for m in budget.finditer(BASE64_CANDIDATE, text):
        decoded = _decode_base64(m.group())
        if decoded:
            out.append((m.start(), m.end(), decoded))
    for m in budget.finditer(HEX_ESCAPED, text):
        try:
            out.append((m.start(), m.end(), bytes.fromhex(m.group().replace("\\x", "")).decode("utf-8")))
        except (UnicodeDecodeError, ValueError):
            continue
    return out


def merge(spans: list[Span]) -> list[Span]:
    """Overlapping spans merge into one, keeping the highest-precedence (lowest priority) marker."""
    merged: list[Span] = []
    for s in sorted(spans, key=lambda s: (s.start, s.priority)):
        if merged and s.start < merged[-1].end:
            last = merged[-1]
            best = last if last.priority <= s.priority else s
            merged[-1] = Span(last.start, max(last.end, s.end), best.priority, best.rule_id, best.marker)
        else:
            merged.append(s)
    return merged


def apply_masks(text: str, spans: list[Span]) -> str:
    out = []
    cursor = 0
    for s in merge(spans):
        out.append(text[cursor : s.start])
        out.append(s.marker)
        cursor = s.end
    out.append(text[cursor:])
    return "".join(out)
