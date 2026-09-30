"""Security Utilities and Hash Helpers."""

import hashlib
import html
import re


def compute_sha256(text: str) -> str:
    """Compute SHA-256 hash of a given text string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def escape_html_entities(text: str) -> str:
    """Escape HTML entities to mitigate XSS attacks."""
    return html.escape(text)


def sanitize_whitespace(text: str) -> str:
    """Collapse consecutive whitespaces and strip string."""
    return re.sub(r"\s+", " ", text).strip()
