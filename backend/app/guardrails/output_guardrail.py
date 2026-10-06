"""OutputGuardrailEngine.sanitize() (DES-006 §4).

Order: 1 length → 2 critical checks on raw + bounded decoded/separator copies (whole-response block)
→ 3 per-span PII/secret masking (encoded tokens masked whole) → 4 HTML/Markdown/URL neutralizing
→ 5 re-inspection of the final text. A block always wins over masking.
"""

from __future__ import annotations

import regex

from app.guardrails import pii
from app.guardrails.budget import Budget, scaled_budget_ms
from app.guardrails.markup import sanitize_markup
from app.guardrails.normalize import canonical, decoded_variants, strip_separators
from app.guardrails.ruleset import RuleSnapshot
from app.guardrails.types import GuardrailTimeout, Hit, OutputTooLong, SanitizationResult

BLOCKED_MESSAGE = "🛡️ 보안 정책에 따라 이 응답을 표시할 수 없습니다."

SECRET_HEADING = regex.compile(
    r"기밀|대외비|confidential|secret|credential|접속\s{0,2}정보|비밀번호\s{0,2}목록|환경\s{0,2}변수|\.env\b", regex.I
)
CODE_SEGMENT = regex.compile(
    r"```[^\n]{0,40}\n(.{0,8000}?)```|`([^`\n]{1,500})`|(?m:^\s{0,4}(?:\$|#|>|PS>)\s(.{1,500})$)", regex.S
)
DESTRUCTIVE_OR_SINK = regex.compile(
    r"rm\s{1,5}-[a-z]{0,5}[rf][a-z]{0,5}\s{1,5}(?:/|~|\*)|\bmkfs\b|\bdd\s{1,5}if=.{0,100}of=/dev/"
    r"|:\(\)\s{0,3}\{\s{0,3}:\|:&\s{0,3}\};:|chmod\s{1,5}-R\s{1,5}777\s{1,5}/|(?:curl|wget)[^\n|]{0,200}\|\s{0,5}(?:sh|bash)\b"
    r"|format\s{1,5}c:|\bdel\s{1,5}/[sfq]|Remove-Item\s.{0,100}-Recurse|Invoke-Expression|\biex\s{0,3}\("
    r"|powershell(?:\.exe)?\s{1,5}-e(?:nc|ncodedcommand)?\s|\bshutdown\s{1,5}[-/][hrs]|drop\s{1,5}(?:table|database)"
    r"|os\.system\s{0,3}\(|subprocess\.[a-z_]{1,20}\([^)]{0,200}shell\s{0,3}=\s{0,3}True|\beval\s{0,3}\(|\bexec\s{0,3}\("
    r"|__import__\s{0,3}\(\s{0,3}['\"]os|pickle\.loads|Runtime\.getRuntime\(\)\.exec",
    regex.I,
)
MARKER = regex.compile(r"\[(?:REDACTED_[A-Z]{2,10}|IMAGE_BLOCKED)\]")
PROMPT_WINDOW = 48
PROMPT_STEP = 8
BULK_DISTINCT_VALUES = 5
BULK_RECORD_LINES = 3


def _prompt_windows(protected: tuple[str, ...]) -> frozenset[str]:
    windows = set()
    for text in protected:
        norm = " ".join(text.split()).lower()
        for i in range(0, max(len(norm) - PROMPT_WINDOW, 0) + 1, PROMPT_STEP):
            window = norm[i : i + PROMPT_WINDOW]
            if len(window) == PROMPT_WINDOW:
                windows.add(window)
    return frozenset(windows)


class OutputGuardrailEngine:
    def __init__(
        self,
        *,
        secret_fingerprints: frozenset[str] = frozenset(),
        protected_texts: tuple[str, ...] = (),
        budget_ms: float = 50.0,
        per_call_ms: float = 20.0,
    ) -> None:
        self.fingerprints = secret_fingerprints
        self.prompt_windows = _prompt_windows(protected_texts)
        self.budget_ms = budget_ms
        self.per_call_ms = per_call_ms

    def sanitize(self, raw: str, snapshot: RuleSnapshot) -> SanitizationResult:
        budget = Budget(scaled_budget_ms(self.budget_ms, len(raw)), self.per_call_ms)
        if len(raw) > snapshot.limit("max_output_chars"):
            raise OutputTooLong
        hits: dict[str, Hit] = {}

        def hit(rule_id: str, count: int = 1) -> None:
            compiled = snapshot.get(rule_id)
            if compiled is not None:
                r = compiled.rule
                prev = hits.get(rule_id)
                hits[rule_id] = Hit(r.rule_id, r.category, r.stage, r.action, count + (prev.match_count if prev else 0))

        def blocked() -> SanitizationResult:
            return SanitizationResult(BLOCKED_MESSAGE, True, True, tuple(hits.values()), budget.elapsed_ms())

        # Step 2: critical checks on raw and bounded decoded/separator-normalized copies.
        base = canonical(raw)
        copies = [raw] + [v for v in {base, strip_separators(base), *decoded_variants(base)} if v != raw]
        detector = pii.Detector(snapshot, budget)
        if self._critical(copies, detector, budget, snapshot, hit):
            return blocked()

        # Step 3: per-span masking on the original, plus encoded tokens that decode to PII/secrets.
        spans = detector.spans(raw)
        for start, end, decoded in pii.encoded_tokens(raw, budget):
            if pii.fingerprint_hits(decoded, self.fingerprints, budget):
                hit("RULE_CRITICAL_SECRET_DUMP")
                return blocked()
            inner = detector.spans(decoded)
            if inner:
                best = min(inner, key=lambda s: s.priority)
                spans.append(pii.Span(start, end, best.priority, best.rule_id, best.marker))
        if self._bulk_pii(raw, spans):
            hit("RULE_BULK_PII_DUMP")
            return blocked()
        for s in pii.merge(spans):
            hit(s.rule_id)
        masked = pii.apply_masks(raw, spans)

        # Step 4: renderer protection.
        content, markup_hits = sanitize_markup(masked)
        for rule_id in sorted(markup_hits):
            hit(rule_id)

        # Step 5: re-inspect the final text; anything still detectable means masking failed → block.
        final_copies = [content, strip_separators(canonical(content))]
        # Our own markers look like secret values to RULE_SECRET ("password: [REDACTED_SECRET]"); skip them.
        leftover = [s for c in final_copies for s in detector.spans(c) if not MARKER.fullmatch(s.value.strip("\"'"))]
        if self._critical(final_copies, detector, budget, snapshot, hit) or leftover:
            return blocked()
        return SanitizationResult(content, False, content != raw, tuple(hits.values()), budget.elapsed_ms())

    # ------------------------------------------------------------------ checks

    def _critical(self, copies, detector: pii.Detector, budget: Budget, snapshot: RuleSnapshot, hit) -> bool:
        for text in copies:
            if pii.fingerprint_hits(text, self.fingerprints, budget) or self._secret_dump(text, detector):
                hit("RULE_CRITICAL_SECRET_DUMP")
                return True
            if self._prompt_leak(text):
                hit("RULE_SYSTEM_PROMPT_OUTPUT")
                return True
            shell = snapshot.get("RULE_REVERSE_SHELL_OUTPUT")
            if shell and shell.pattern and budget.search(shell.pattern, text):
                hit("RULE_REVERSE_SHELL_OUTPUT")
                return True
            if self._rce(text, budget):
                hit("RULE_RCE_COMMAND_OUTPUT")
                return True
        return False

    @staticmethod
    def _secret_dump(text: str, detector: pii.Detector) -> bool:
        if not SECRET_HEADING.search(text):
            return False
        secret_lines = {text.count("\n", 0, s.start) for s in detector._secret(text) + detector._tokens(text)}
        return len(secret_lines) >= 3

    def _prompt_leak(self, text: str) -> bool:
        if not self.prompt_windows:
            return False
        norm = " ".join(text.split()).lower()
        return any(w in norm for w in self.prompt_windows)

    @staticmethod
    def _rce(text: str, budget: Budget) -> bool:
        for m in budget.finditer(CODE_SEGMENT, text):
            segment = m.group(1) or m.group(2) or m.group(3)
            if segment and budget.search(DESTRUCTIVE_OR_SINK, segment):
                return True
        return False

    @staticmethod
    def _bulk_pii(text: str, spans: list[pii.Span]) -> bool:
        personal = [s for s in spans if s.rule_id in pii.PII_RULES]
        distinct = {(s.rule_id, "".join(ch for ch in s.value if ch.isalnum() or ch == "@")) for s in personal}
        if len(distinct) >= BULK_DISTINCT_VALUES:
            return True
        types_per_line: dict[int, set[str]] = {}
        for s in personal:
            types_per_line.setdefault(text.count("\n", 0, s.start), set()).add(s.rule_id)
        return sum(1 for kinds in types_per_line.values() if len(kinds) >= 2) >= BULK_RECORD_LINES


__all__ = ["BLOCKED_MESSAGE", "GuardrailTimeout", "OutputGuardrailEngine"]
