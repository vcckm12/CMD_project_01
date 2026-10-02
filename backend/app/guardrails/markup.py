"""Renderer protection for model output (DES-006 §4.1 step 4, RULE_XSS_SANITIZE /
RULE_MARKDOWN_IMAGE_EXFIL / RULE_UNSAFE_URL).

- HTML: a browser only starts a tag at "<" followed by a letter, "/", "!" or "?" (HTML tokenizer
  tag-open state), so exactly those "<" become "&lt;". Plain "a < b" stays readable.
- Markdown images and dangerous links are rewritten, then a CommonMark parse verifies that no image
  and no unsafe link survived; anything that still parses as unsafe triggers a stricter fallback.
- If parsing fails, the text is degraded to inert plain text.
"""

from __future__ import annotations

import html
from collections.abc import Iterator
from urllib.parse import parse_qsl, urlsplit

import regex
from markdown_it import MarkdownIt

IMAGE_BLOCKED = "[IMAGE_BLOCKED]"
URL_BLOCKED = "#url-blocked"

TAG_OPEN = regex.compile(r"<(?=[A-Za-z/!?])")
INLINE_IMAGE = regex.compile(
    r"!\[(?:[^\[\]\\\n]|\\.|\[[^\[\]\n]{0,200}\]){0,500}\]\(\s{0,10}<?[^)\s>]{0,2000}>?"
    r"(?:\s{1,10}(?:\"[^\"\n]{0,200}\"|'[^'\n]{0,200}'|\([^)\n]{0,200}\)))?\s{0,10}\)"
)
REFERENCE_IMAGE = regex.compile(r"!\[[^\]\n]{0,500}\](?:\[[^\]\n]{0,200}\])?")
LINK_DESTINATION = regex.compile(r"\]\(\s{0,10}<?([^)\s>]{1,2000})")
REFERENCE_DEFINITION = regex.compile(r"(?m)^\s{0,3}\[[^\]\n]{1,200}\]:\s{0,10}<?(\S{1,2000}?)>?(?=\s|$)")
BARE_URL = regex.compile(r"(?i)\b(?:https?|ftp)://[^\s<>()\[\]]{1,2000}")
DANGEROUS_SCHEMES = ("javascript:", "vbscript:", "data:", "file:")
SECRET_LIKE = regex.compile(
    r"(?i)REDACTED|eyJ[A-Za-z0-9_-]{8,}|gct_|(?:key|token|secret|pass(?:word)?|pw|auth)"
    r"|(?=[A-Za-z0-9+/=_-]{20,})(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9+/=_-]{20,}"
)

_md = MarkdownIt("commonmark")


def _walk(tokens) -> Iterator:
    for t in tokens:
        if t.children:
            yield from _walk(t.children)
        yield t


def _normalized_scheme_target(url: str) -> str:
    # Defeat "java&#115;cript:", "JaVaScRiPt:", "java\tscript:" style obfuscation.
    decoded = html.unescape(url)
    return "".join(ch for ch in decoded if ch.isprintable() and not ch.isspace()).lower()


def is_unsafe_url(url: str) -> bool:
    target = _normalized_scheme_target(url)
    if target.startswith(DANGEROUS_SCHEMES):
        return True
    if target.startswith(("http://", "https://", "//")):
        parts = urlsplit(target if not target.startswith("//") else "https:" + target)
        values = [v for _, v in parse_qsl(parts.query, keep_blank_values=True)] + [parts.fragment]
        names = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
        return any(SECRET_LIKE.search(v) for v in values + names if v)
    return False


def _rewrite(text: str, hits: set[str]) -> str:
    escaped = TAG_OPEN.sub("&lt;", text)
    if escaped != text:
        hits.add("RULE_XSS_SANITIZE")
    text = escaped

    replaced = INLINE_IMAGE.sub(IMAGE_BLOCKED, text)
    replaced = REFERENCE_IMAGE.sub(IMAGE_BLOCKED, replaced)
    if replaced != text:
        hits.add("RULE_MARKDOWN_IMAGE_EXFIL")
    text = replaced

    def neutralize(m: regex.Match) -> str:
        url = m.group(1)
        if is_unsafe_url(url):
            hits.add("RULE_UNSAFE_URL")
            return m.group(0).replace(url, URL_BLOCKED)
        return m.group(0)

    text = LINK_DESTINATION.sub(neutralize, text)
    text = REFERENCE_DEFINITION.sub(neutralize, text)

    def neutralize_bare(m: regex.Match) -> str:
        if is_unsafe_url(m.group(0)):
            hits.add("RULE_UNSAFE_URL")
            return URL_BLOCKED
        return m.group(0)

    return BARE_URL.sub(neutralize_bare, text)


def _unsafe_after_parse(text: str) -> tuple[bool, bool]:
    images = unsafe_links = False
    for t in _walk(_md.parse(text)):
        if t.type == "image":
            images = True
        elif t.type == "link_open" and is_unsafe_url(str(t.attrs.get("href", ""))):
            unsafe_links = True
        elif t.type in ("html_inline", "html_block"):
            images = True  # cannot happen after TAG_OPEN escaping; treat as unsafe if it does
    return images, unsafe_links


def _inert(text: str) -> str:
    """Last resort: nothing in the result can render as an image, a link, or HTML."""
    text = TAG_OPEN.sub("&lt;", text)
    text = text.replace("![", "[")
    text = regex.sub(r"\]\(", "] (", text)
    return regex.sub(r"\]:", "] :", text)  # break reference definitions too


def sanitize_markup(text: str) -> tuple[str, set[str]]:
    hits: set[str] = set()
    try:
        result = _rewrite(text, hits)
        images, unsafe_links = _unsafe_after_parse(result)
        if images or unsafe_links:
            hits.add("RULE_MARKDOWN_IMAGE_EXFIL" if images else "RULE_UNSAFE_URL")
            result = _inert(result)
            images, unsafe_links = _unsafe_after_parse(result)
            if images or unsafe_links:
                raise ValueError("unsafe markup survived fallback")
        return result, hits
    except Exception:  # noqa: BLE001 - any parser problem degrades to plain text (DES-006 §4.1)
        hits.add("RULE_XSS_SANITIZE")
        return _inert(text), hits
