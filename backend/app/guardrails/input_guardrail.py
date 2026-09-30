"""Input Guardrail Pipeline (7-Step Multi-Tier Security Inspection)."""

import base64
import re
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass

from app.core.config import settings
from app.core.logging import logger
from app.guardrails.rule_manager import rule_manager


@dataclass
class InputEvaluationResult:
    """Result of Input Guardrail inspection."""

    is_allowed: bool
    reason: str | None = None
    threat_type: str | None = None
    rule_id: str | None = None
    sanitized_text: str = ""
    latency_ms: float = 0.0


class InputGuardrailEngine:
    """7-Step Input Guardrail Pipeline."""

    # Cyrillic and Greek homoglyphs commonly used to bypass keyword filters
    HOMOGLYPH_MAP = {
        "а": "a",
        "А": "A",
        "е": "e",
        "Е": "E",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "с": "c",
        "С": "C",
        "у": "y",
        "У": "Y",
        "х": "x",
        "Х": "X",
        "і": "i",
        "І": "I",
        "ј": "j",
        "Ј": "J",
        "ѕ": "s",
        "Ѕ": "S",
    }

    # Common Base64 pattern candidate
    BASE64_PATTERN = re.compile(
        r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    )

    def __init__(self) -> None:
        pass

    def evaluate(self, raw_input: str) -> InputEvaluationResult:
        """Run the full 7-step Input Guardrail pipeline."""
        start_time = time.perf_counter()

        # -------------------------------------------------------------
        # Step 1: Request Validation
        # -------------------------------------------------------------
        if not raw_input or not raw_input.strip():
            latency = (time.perf_counter() - start_time) * 1000.0
            return InputEvaluationResult(
                is_allowed=False,
                reason="EMPTY_INPUT",
                threat_type="INVALID_REQUEST",
                sanitized_text="",
                latency_ms=latency,
            )

        text = raw_input.strip()

        # -------------------------------------------------------------
        # Step 2: Input & Token Length Limit
        # -------------------------------------------------------------
        if len(text) > settings.MAX_INPUT_LENGTH:
            latency = (time.perf_counter() - start_time) * 1000.0
            logger.warning(f"Input length {len(text)} exceeded limit {settings.MAX_INPUT_LENGTH}")
            return InputEvaluationResult(
                is_allowed=False,
                reason=f"INPUT_LENGTH_EXCEEDED ({len(text)} > {settings.MAX_INPUT_LENGTH})",
                threat_type="DOS_PAYLOAD_LIMIT",
                sanitized_text=text[:100],
                latency_ms=latency,
            )

        # -------------------------------------------------------------
        # Step 3: Unicode NFKC Normalization
        # -------------------------------------------------------------
        normalized_text = unicodedata.normalize("NFKC", text)

        # -------------------------------------------------------------
        # Step 4: Confusable Character Detection & Transliteration
        # -------------------------------------------------------------
        transliterated_chars = []
        for ch in normalized_text:
            transliterated_chars.append(self.HOMOGLYPH_MAP.get(ch, ch))
        transliterated_text = "".join(transliterated_chars)

        # -------------------------------------------------------------
        # Step 5: De-obfuscation (URL, Hex, Base64 inspection)
        # -------------------------------------------------------------
        decoded_text = urllib.parse.unquote(transliterated_text)

        # Check for embedded Base64 payload
        extracted_b64_payloads = []
        for match in self.BASE64_PATTERN.finditer(decoded_text):
            candidate = match.group(0)
            if len(candidate) >= 12:  # inspect plausible payload strings
                try:
                    decoded_bytes = base64.b64decode(candidate, validate=True)
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                    if any(c.isalnum() for c in decoded_str):
                        extracted_b64_payloads.append(decoded_str)
                except Exception:
                    pass

        # Text pool for signature inspection
        inspection_pool = [decoded_text]
        if extracted_b64_payloads:
            inspection_pool.extend(extracted_b64_payloads)

        # -------------------------------------------------------------
        # Step 6: Dynamic Threat Signature & Regex Detection
        # -------------------------------------------------------------
        input_rules = rule_manager.get_input_rules()

        for pool_item in inspection_pool:
            lower_pool_item = pool_item.lower()

            for rule in input_rules:
                if not rule.is_active:
                    continue

                # Regex evaluation
                if rule.pattern_type.upper() == "REGEX":
                    pattern = rule_manager.get_compiled_regex(rule.rule_id)
                    if not pattern:
                        try:
                            pattern = re.compile(rule.pattern_value, re.IGNORECASE)
                        except re.error:
                            continue

                    if pattern.search(pool_item):
                        latency = (time.perf_counter() - start_time) * 1000.0
                        logger.warning(
                            f"Input Guardrail Blocked: Rule {rule.rule_id} ({rule.description}) matched."
                        )
                        return InputEvaluationResult(
                            is_allowed=False,
                            reason=f"Rule {rule.rule_id} match",
                            threat_type="PROMPT_INJECTION_OR_EXPLOIT",
                            rule_id=rule.rule_id,
                            sanitized_text=pool_item,
                            latency_ms=latency,
                        )

                # Keyword evaluation
                elif rule.pattern_type.upper() == "KEYWORD":
                    if rule.pattern_value.lower() in lower_pool_item:
                        latency = (time.perf_counter() - start_time) * 1000.0
                        logger.warning(
                            f"Input Guardrail Blocked: Keyword '{rule.pattern_value}' (Rule {rule.rule_id}) matched."
                        )
                        return InputEvaluationResult(
                            is_allowed=False,
                            reason=f"Keyword '{rule.pattern_value}' match",
                            threat_type="PROMPT_INJECTION_KEYWORD",
                            rule_id=rule.rule_id,
                            sanitized_text=pool_item,
                            latency_ms=latency,
                        )

        # -------------------------------------------------------------
        # Step 7: Semantic & Persona Enforcement
        # -------------------------------------------------------------
        semantic_forbidden_patterns = [
            r"(?i)\byou are now (dan|evil|unrestricted|god)\b",
            r"(?i)\bpretend you have no rules\b",
            r"(?i)\bbypass (all )?filters\b",
            r"(?i)(리눅스\s*쉘\s*실행|서버\s*비밀번호|원가\s*전부\s*출력)",
        ]
        for sem_pat in semantic_forbidden_patterns:
            if re.search(sem_pat, decoded_text):
                latency = (time.perf_counter() - start_time) * 1000.0
                return InputEvaluationResult(
                    is_allowed=False,
                    reason="SEMANTIC_PERSONA_VIOLATION",
                    threat_type="JAILBREAK_PERSONA",
                    rule_id="SEM-001",
                    sanitized_text=decoded_text,
                    latency_ms=latency,
                )

        # -------------------------------------------------------------
        # All 7 Steps Passed: Clean & Allowed
        # -------------------------------------------------------------
        latency = (time.perf_counter() - start_time) * 1000.0
        return InputEvaluationResult(
            is_allowed=True,
            reason=None,
            threat_type=None,
            rule_id=None,
            sanitized_text=decoded_text,
            latency_ms=latency,
        )


input_guardrail = InputGuardrailEngine()
