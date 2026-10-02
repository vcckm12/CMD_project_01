"""Input Step 1~4 (DES-006 §3.1): inspection copies of untrusted text.

The original string is never modified for the model except `canonical()` (Zero-Width removal + NFKC).
Confusable/leet/separator/decoded variants exist only for inspection. Resource limits fail closed:
exceeding them raises ResourceLimit, which the engine turns into RULE_TOKEN_FLOOD (block).
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import unicodedata
from typing import Literal, NamedTuple
from urllib.parse import unquote_to_bytes

import regex

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

# Cyrillic look-alikes only (DES-006 §3.1); not a full Unicode confusables table.
CONFUSABLES = str.maketrans(
    {
        # Cyrillic (DES-006 base list)
        "А": "A", "а": "a", "В": "B", "Е": "E", "е": "e", "К": "K", "М": "M", "Н": "H",
        "О": "O", "о": "o", "Р": "P", "р": "p", "С": "C", "с": "c", "Т": "T", "Х": "X", "х": "x",
        # Cyrillic/Ukrainian extensions seen in evasion samples
        "І": "I", "і": "i", "Ј": "J", "ј": "j", "Ѕ": "S", "ѕ": "s", "у": "y", "Ү": "Y", "ԁ": "d",
        "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɡ": "g",
        # Greek capitals and the lower-case letters that render like Latin ones
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
        "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ο": "o", "α": "a", "ε": "e", "ι": "i",
        "κ": "k", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    }
)  # fmt: skip

LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "!": "i", "1": "i", "0": "o", "$": "s", "5": "s", "7": "t"})

# A leet character counts only when it sits inside a Latin word (P@ssw0rd), so prices and
# Korean text with digits do not spawn a variant.
LEET_IN_WORD = regex.compile(r"[A-Za-z][@4310!$57]|[@4310!$57][A-Za-z]")

# Runs of ≥3 single characters split by separators, spaces or symbols/emoji: "이-전-의", "i g n o r e", "비🔑밀🔒번".
SEPARATED_RUN = regex.compile(
    r"(?<![^\W_])([^\W_])(?:((?:[\s\-_.·•*~|/\\+=,:;'\"`^]|\p{So}|\p{Sk}){1,3})([^\W_])(?![^\W_])){2,}"
)

URL_ENCODED = regex.compile(r"(?:%[0-9A-Fa-f]{2})+")
HEX_ESCAPED = regex.compile(r"(?:\\x[0-9A-Fa-f]{2})+")
HEX_LITERAL = regex.compile(r"\b0x(?:[0-9A-Fa-f]{2}){8,4000}\b")
ROT13_MARKER = regex.compile(r"\brot[\s_-]{0,2}13\b", regex.IGNORECASE)
BASE64_CANDIDATE = regex.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,4096}={0,2}(?![A-Za-z0-9+/=_-])")

MAX_DECODE_DEPTH = 2
MAX_BASE64_CANDIDATES = 4
MAX_DECODED_CHARS = 8_000
MAX_VARIANT_CHARS = 32_000
MAX_VARIANTS = 16
MAX_TOTAL_VARIANT_CHARS = 128_000
MAX_GROWTH = 4


class ResourceLimit(Exception):
    pass


def canonical(text: str) -> str:
    """Model-facing normalization: Zero-Width removal + NFKC only."""
    return unicodedata.normalize("NFKC", text.translate(ZERO_WIDTH))


def _join_run(m: regex.Match) -> str:
    """Drop the run's dominant separator; a different separator containing whitespace (or a wider one)
    marks a word break: "i g n o r e  a l l" → "ignore all", "이-전-의 지-침" → "이전의 지침"."""
    chars = m.captures(1) + m.captures(3)
    seps = m.captures(2)
    dominant = max(set(seps), key=seps.count)
    dominant_has_space = any(c.isspace() for c in dominant)
    out = [chars[0]]
    for sep, ch in zip(seps, chars[1:], strict=True):
        has_space = any(c.isspace() for c in sep)
        is_break = sep != dominant and has_space and (not dominant_has_space or len(sep) > len(dominant))
        out.append((" " if is_break else "") + ch)
    return "".join(out)


def strip_separators(text: str) -> str:
    return SEPARATED_RUN.sub(_join_run, text)


def unleet(text: str) -> str:
    return text.translate(LEET) if LEET_IN_WORD.search(text) else text


def _printable_text(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")  # strict: invalid UTF-8 is not inspected as text
    except UnicodeDecodeError:
        return None
    if not text or len(text) > MAX_DECODED_CHARS:
        return None
    printable = sum(ch.isprintable() or ch in "\n\t\r" for ch in text)
    return text if printable / len(text) >= 0.9 else None


def _decode_base64(token: str) -> str | None:
    padded = token + "=" * (-len(token) % 4)
    try:
        if "-" in token or "_" in token:
            data = base64.urlsafe_b64decode(padded)
        else:
            data = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _printable_text(data)


def decoded_variants(text: str) -> list[str]:
    """One level of URL / \\xNN / Base64 decoding, each replacing the encoded span in place."""
    out: list[str] = []
    if URL_ENCODED.search(text):
        try:
            replaced = URL_ENCODED.sub(lambda m: unquote_to_bytes(m.group()).decode("utf-8"), text)
            out.append(replaced)
        except UnicodeDecodeError:
            pass
    if HEX_ESCAPED.search(text):
        try:
            out.append(HEX_ESCAPED.sub(lambda m: bytes.fromhex(m.group().replace("\\x", "")).decode("utf-8"), text))
        except (UnicodeDecodeError, ValueError):
            pass
    if HEX_LITERAL.search(text):
        try:
            out.append(HEX_LITERAL.sub(lambda m: bytes.fromhex(m.group()[2:]).decode("utf-8"), text))
        except (UnicodeDecodeError, ValueError):
            pass
    if ROT13_MARKER.search(text):
        # ROT13 only when the text says so; decoding everything would double the variants for nothing.
        out.append(codecs.decode(text, "rot13"))
    candidates = [m for m in BASE64_CANDIDATE.finditer(text)][:MAX_BASE64_CANDIDATES]
    for m in candidates:
        decoded = _decode_base64(m.group())
        if decoded is not None:
            out.append(text[: m.start()] + decoded + text[m.end() :])
    return out


class Variant(NamedTuple):
    text: str
    kind: Literal["original", "normalized", "decoded", "separators", "leet"]


def build_variants(text: str) -> list[Variant]:
    """Original first, then deduplicated inspection copies tagged by how they were derived.
    Raises ResourceLimit."""
    seen: set[bytes] = set()
    variants: list[Variant] = []

    def add(value: str, source_len: int, kind: str) -> bool:
        digest = hashlib.blake2b(value.encode("utf-8", "surrogatepass"), digest_size=16).digest()
        if digest in seen:
            return False
        if len(value) > MAX_VARIANT_CHARS or len(value) > max(source_len, 1) * MAX_GROWTH:
            raise ResourceLimit
        seen.add(digest)
        variants.append(Variant(value, kind))
        if len(variants) > MAX_VARIANTS or sum(len(v.text) for v in variants) > MAX_TOTAL_VARIANT_CHARS:
            raise ResourceLimit
        return True

    add(text, len(text), "original")
    base = canonical(text).translate(CONFUSABLES)
    add(base, len(text), "normalized")

    frontier = [base]
    for _depth in range(MAX_DECODE_DEPTH):
        next_frontier = []
        for current in frontier:
            for decoded in decoded_variants(current):
                normalized = canonical(decoded).translate(CONFUSABLES)
                if add(normalized, len(current), "decoded"):
                    next_frontier.append(normalized)
        frontier = next_frontier

    for value in [v.text for v in variants[1:]] or [base]:
        stripped = strip_separators(value)
        add(stripped, len(value), "separators")
        add(unleet(stripped), len(value), "leet")
    return variants
