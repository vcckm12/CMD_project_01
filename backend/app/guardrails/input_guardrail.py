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
from app.guardrails.semantic_guardrail import semantic_guardrail


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

    # Extended Cyrillic and Greek homoglyph mapping
    HOMOGLYPH_MAP = {
        "а": "a", "А": "A",
        "е": "e", "Е": "E",
        "о": "o", "О": "O",
        "р": "p", "Р": "P",
        "с": "c", "С": "C",
        "у": "y", "У": "Y",
        "х": "x", "Х": "X",
        "і": "i", "І": "I",
        "ј": "j", "Ј": "J",
        "ѕ": "s", "Ѕ": "S",
        "ԁ": "d", "ԃ": "d",
        "ԛ": "q", "ԝ": "w",
    }

    # Base64 pattern candidate
    BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

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
        # Step 3: Unicode NFKC Normalization & Zero-Width Stripping
        # -------------------------------------------------------------
        clean_zw_text = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u2061\u2062\u2063\u2064]", "", text)
        normalized_text = unicodedata.normalize("NFKC", clean_zw_text)

        # -------------------------------------------------------------
        # Step 4: Confusable Character Detection & Transliteration
        # -------------------------------------------------------------
        transliterated_chars = []
        for ch in normalized_text:
            transliterated_chars.append(self.HOMOGLYPH_MAP.get(ch, ch))
        transliterated_text = "".join(transliterated_chars)

        # -------------------------------------------------------------
        # Step 5: De-obfuscation (URL, Hex, Base64, ROT13, Leetspeak, Tags)
        # -------------------------------------------------------------
        decoded_text = urllib.parse.unquote(transliterated_text)

        # 5.1 Space and Punctuation collapsed variants
        collapsed_all_spaces = re.sub(r"\s+", "", decoded_text)
        punct_collapsed = re.sub(r"[\.\-_,/|#*`~<>\(\)\[\]\{\}]", "", decoded_text)
        punct_space_collapsed = re.sub(r"\s+", "", punct_collapsed)

        extra_payloads: list[str] = []

        # 5.2 Leetspeak de-obfuscation (e.g. 1gn0r3 -> ignore)
        leet_translated = decoded_text.translate(str.maketrans("013457@", "oieasta"))
        if leet_translated != decoded_text:
            extra_payloads.append(leet_translated)

        # 5.3 Delimiter and Tag Inner Content Extraction (e.g. <admin_command>...</admin_command>)
        tag_stripped = re.sub(r"<[^>]+>|\[/?[^\]]+\]|```[\w]*|<!--\s*#?\s*[\w:]*|-->", " ", decoded_text)
        if tag_stripped != decoded_text:
            extra_payloads.append(tag_stripped)
            extra_payloads.append(re.sub(r"\s+", "", tag_stripped))

        # 5.4 Base64 payload extraction (explicit prefix & pattern scan)
        b64_prefix = re.search(r"(?i)base64\s*:\s*([a-zA-Z0-9+/=]{8,})", decoded_text)
        if b64_prefix:
            try:
                extra_payloads.append(base64.b64decode(b64_prefix.group(1)).decode("utf-8", errors="ignore"))
            except Exception:
                pass

        for match in self.BASE64_PATTERN.finditer(decoded_text):
            candidate = match.group(0)
            if len(candidate) >= 8:
                try:
                    decoded_bytes = base64.b64decode(candidate, validate=True)
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                    if any(c.isalnum() for c in decoded_str):
                        extra_payloads.append(decoded_str)
                except Exception:
                    pass

        # 5.5 ROT13 Cipher Decoding
        rot13_prefix = re.search(r"(?i)(?:cipher\s+)?rot13\s*:\s*(.+)", decoded_text)
        if rot13_prefix:
            try:
                import codecs
                extra_payloads.append(codecs.decode(rot13_prefix.group(1).strip(), "rot_13"))
            except Exception:
                pass
        try:
            rot13_candidate = decoded_text.encode("utf-8").decode("rot13", errors="ignore")
            if any(w in rot13_candidate.lower() for w in ["ignore", "prompt", "system", "password", "select", "cost"]):
                extra_payloads.append(rot13_candidate)
        except Exception:
            pass
        except Exception:
            pass

        # 5.4 Hex Stream Decoding (e.g. 0x53595354... or 53595354...)
        hex_matches = re.findall(r"(?:0x)?([0-9a-fA-F]{10,})", decoded_text)
        for h in hex_matches:
            try:
                raw_bytes = bytes.fromhex(h)
                hex_str = raw_bytes.decode("utf-8", errors="ignore")
                if any(c.isalnum() for c in hex_str):
                    extra_payloads.append(hex_str)
            except Exception:
                pass

        # Text pool for signature and semantic inspection (both transliterated and raw normalized)
        inspection_pool = [
            decoded_text,
            collapsed_all_spaces,
            punct_collapsed,
            punct_space_collapsed,
            normalized_text,
            re.sub(r"\s+", "", normalized_text),
        ]
        if extra_payloads:
            inspection_pool.extend(extra_payloads)

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
                            threat_type=rule.description or "PROMPT_INJECTION_OR_EXPLOIT",
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
                            threat_type=rule.description or "PROMPT_INJECTION_KEYWORD",
                            rule_id=rule.rule_id,
                            sanitized_text=pool_item,
                            latency_ms=latency,
                        )

        # -------------------------------------------------------------
        # Step 7: Semantic & Vector-based Threat Evaluation
        # -------------------------------------------------------------
        # 7.1 Pattern-based Semantic Persona checks
        semantic_forbidden_patterns = [
            r"(?i)\byou are now (dan|evil|unrestricted|god|evilbot)\b",
            r"(?i)\bpretend you have no rules\b",
            r"(?i)\bbypass (all )?(safety )?filters?\b",
            r"(?i)(without guardrails|zero guardrails|developer mode)",
            r"(?i)(리눅스\s*쉘\s*실행|서버\s*비밀번호|원가\s*전부|대외비\s*원가|비밀\s*원가)",
        ]
        for sem_pat in semantic_forbidden_patterns:
            for pool_item in inspection_pool:
                if re.search(sem_pat, pool_item):
                    latency = (time.perf_counter() - start_time) * 1000.0
                    return InputEvaluationResult(
                        is_allowed=False,
                        reason="SEMANTIC_PERSONA_VIOLATION",
                        threat_type="JAILBREAK_PERSONA",
                        rule_id="SEM-001",
                        sanitized_text=decoded_text,
                        latency_ms=latency,
                    )

        # 7.2 Vector Cosine Similarity Threat Detection (Subword N-Gram TF-IDF)
        for pool_item in inspection_pool:
            sem_result = semantic_guardrail.evaluate(pool_item)
            if sem_result.is_threat:
                latency = (time.perf_counter() - start_time) * 1000.0
                return InputEvaluationResult(
                    is_allowed=False,
                    reason=f"SEMANTIC_SIMILARITY_MATCH ({sem_result.similarity_score:.3f} >= {semantic_guardrail.threshold:.2f})",
                    threat_type=sem_result.threat_category or "SEMANTIC_JAILBREAK",
                    rule_id=sem_result.rule_id or "SEM-VEC-001",
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
