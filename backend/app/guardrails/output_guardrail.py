"""Output Guardrail Pipeline (5-Step Multi-Tier Output Sanitization & Protection)."""

import re
import time
from dataclasses import dataclass

from app.core.logging import logger
from app.guardrails.rule_manager import rule_manager


@dataclass
class OutputEvaluationResult:
    """Result of Output Guardrail inspection."""

    is_allowed: bool
    sanitized_output: str
    pii_redacted: bool
    detected_threats: list[str]
    latency_ms: float = 0.0


class OutputGuardrailEngine:
    """5-Step Output Guardrail Pipeline."""

    # PII Regex Patterns
    RRN_PATTERN = re.compile(r"\b\d{6}-[1-4]\d{6}\b")
    CARD_PATTERN = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
    PHONE_PATTERN = re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b")
    COST_PATTERN = re.compile(r"(?i)(원가|cost_price|공급가)\s*[:=]?\s*([0-9,]+원?)")

    # Reverse shell and dangerous command payloads
    REVERSE_SHELL_PATTERNS = [
        re.compile(r"(?i)\bnc\s+-e\s+/bin/sh\b"),
        re.compile(r"(?i)/bin/bash\s+-i"),
        re.compile(r"(?i)cmd\.exe\s+/c"),
        re.compile(r"(?i)powershell\.exe\s+-enc"),
        re.compile(r"(?i)python\s+-c\s+[\"']import socket"),
    ]

    # Critical system prompt leakage indicators
    CRITICAL_LEAK_PATTERNS = [
        re.compile(r"(?i)POSTGRES_PASSWORD\s*="),
        re.compile(r"(?i)SECRET_KEY\s*="),
        re.compile(r"(?i)INTERNAL_API_KEY"),
        re.compile(r"(?i)You are an AI assistant created with the following secret instructions:"),
    ]

    def __init__(self) -> None:
        pass

    def evaluate(self, raw_output: str) -> OutputEvaluationResult:
        """Run the full 5-step Output Guardrail pipeline."""
        start_time = time.perf_counter()
        detected_threats: list[str] = []
        pii_redacted = False

        if not raw_output:
            latency = (time.perf_counter() - start_time) * 1000.0
            return OutputEvaluationResult(
                is_allowed=True,
                sanitized_output="",
                pii_redacted=False,
                detected_threats=[],
                latency_ms=latency,
            )

        text = raw_output

        # -------------------------------------------------------------
        # Step 1: Critical Leak Detection
        # -------------------------------------------------------------
        for leak_pat in self.CRITICAL_LEAK_PATTERNS:
            if leak_pat.search(text):
                detected_threats.append("CRITICAL_SYSTEM_LEAK")
                logger.error(
                    "Output Guardrail: Critical internal secret leak detected in AI response!"
                )
                latency = (time.perf_counter() - start_time) * 1000.0
                return OutputEvaluationResult(
                    is_allowed=False,
                    sanitized_output="🚨 [보안 정책 알림] 시스템 기밀 정보 노출이 감지되어 응답이 차단되었습니다.",
                    pii_redacted=False,
                    detected_threats=detected_threats,
                    latency_ms=latency,
                )

        # -------------------------------------------------------------
        # Step 2: Reverse Shell & Code Execution Payload Detection
        # -------------------------------------------------------------
        for rshell_pat in self.REVERSE_SHELL_PATTERNS:
            if rshell_pat.search(text):
                detected_threats.append("REVERSE_SHELL_PAYLOAD")
                logger.error(
                    "Output Guardrail: Reverse shell or command execution payload detected in AI output!"
                )
                latency = (time.perf_counter() - start_time) * 1000.0
                return OutputEvaluationResult(
                    is_allowed=False,
                    sanitized_output="🚨 [보안 정책 알림] 잠재적으로 유해한 실행 명령어가 감지되어 응답 생성이 중단되었습니다.",
                    pii_redacted=False,
                    detected_threats=detected_threats,
                    latency_ms=latency,
                )

        # Dynamic output rules from rule_manager
        for rule in rule_manager.get_output_rules():
            if rule.action.upper() == "BLOCK" and rule.pattern_type.upper() == "REGEX":
                compiled = rule_manager.get_compiled_regex(rule.rule_id)
                if compiled and compiled.search(text):
                    detected_threats.append(f"RULE_BLOCK_{rule.rule_id}")
                    latency = (time.perf_counter() - start_time) * 1000.0
                    return OutputEvaluationResult(
                        is_allowed=False,
                        sanitized_output="🚨 [보안 정책 알림] 보안 정책에 위배되는 내용이 출력되어 차단되었습니다.",
                        pii_redacted=False,
                        detected_threats=detected_threats,
                        latency_ms=latency,
                    )

        # -------------------------------------------------------------
        # Step 3: PII Detection & Redaction
        # -------------------------------------------------------------
        # Redact RRN
        if self.RRN_PATTERN.search(text):
            text = self.RRN_PATTERN.sub("[REDACTED_RRN]", text)
            pii_redacted = True
            detected_threats.append("PII_RRN")

        # Redact Credit Card
        if self.CARD_PATTERN.search(text):
            text = self.CARD_PATTERN.sub("[REDACTED_CARD]", text)
            pii_redacted = True
            detected_threats.append("PII_CARD")

        # Redact Phone Number
        if self.PHONE_PATTERN.search(text):
            text = self.PHONE_PATTERN.sub("[REDACTED_PHONE]", text)
            pii_redacted = True
            detected_threats.append("PII_PHONE")

        # Redact Confidential Cost Price
        if self.COST_PATTERN.search(text):
            text = self.COST_PATTERN.sub(r"\1: [REDACTED_CONFIDENTIAL_COST]", text)
            pii_redacted = True
            detected_threats.append("CONFIDENTIAL_COST_LEAK")

        # -------------------------------------------------------------
        # Step 4: XSS Sanitization (Escaping harmful tags)
        # -------------------------------------------------------------
        # Neutralize dangerous raw script tags while preserving safe markdown
        xss_patterns = [
            (re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL), "[BLOCKED_SCRIPT]"),
            (re.compile(r"<iframe.*?>.*?</iframe>", re.IGNORECASE | re.DOTALL), "[BLOCKED_IFRAME]"),
            (re.compile(r"on\w+\s*=\s*[\"'].*?[\"']", re.IGNORECASE), ""),
        ]
        for pattern, replacement in xss_patterns:
            if pattern.search(text):
                text = pattern.sub(replacement, text)
                detected_threats.append("XSS_TAG_STRIPPED")

        # -------------------------------------------------------------
        # Step 5: Markdown & Link Safety
        # -------------------------------------------------------------
        # Block javascript: or data: URIs in markdown links [text](javascript:...)
        malicious_link_pattern = re.compile(
            r"\[([^\]]+)\]\((javascript:|data:)[^\)]+\)", re.IGNORECASE
        )
        if malicious_link_pattern.search(text):
            text = malicious_link_pattern.sub(r"[\1](#blocked-unsafe-link)", text)
            detected_threats.append("UNSAFE_LINK_BLOCKED")

        latency = (time.perf_counter() - start_time) * 1000.0
        return OutputEvaluationResult(
            is_allowed=True,
            sanitized_output=text,
            pii_redacted=pii_redacted,
            detected_threats=detected_threats,
            latency_ms=latency,
        )


output_guardrail = OutputGuardrailEngine()
