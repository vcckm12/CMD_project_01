"""Output Guardrail Pipeline (5단계 출력 보안 살균 및 민감정보 마스킹 파이프라인).

이 모듈은 AI 모델(Ollama / SLM)이 생성한 텍스트가 사용자 화면에 출력되기 직전에
- 내부 시스템 프롬프트 및 API 키 유출 검사
- 리버스 쉘(/bin/bash) 및 유해 시스템 명령어 삽입 탐지
- 주민등록번호, 신용카드 번호, 휴대폰 번호, **대외비 상품 매입 원가(cost_price)** 자동 마스킹(`[REDACTED]`)
- 악성 자바스크립트 XSS 태그 및 위험 링크 살균
을 수행하여 클라이언트에게 안전하고 정제된 결과만을 전달합니다.
"""

import re
import time
from dataclasses import dataclass

from app.core.logging import logger
from app.guardrails.rule_manager import rule_manager


@dataclass
class OutputEvaluationResult:
    """Output Guardrail 검사 결과 데이터 클래스 (DTO).

    Attributes:
        is_allowed (bool): 응답 출력 허용 여부 (True: 출력 가능, False: 위험 응답 전면 차단)
        sanitized_output (str): PII 마스킹 및 XSS 살균 처리가 완료된 최종 텍스트
        pii_redacted (bool): 개인정보 또는 원가 정보가 마스킹되었는지 여부
        detected_threats (list[str]): 감지된 위협 항목 목록 (예: ['PII_CARD', 'CONFIDENTIAL_COST_LEAK'])
        latency_ms (float): 검사 소요 시간 (ms)
    """

    is_allowed: bool
    sanitized_output: str
    pii_redacted: bool
    detected_threats: list[str]
    latency_ms: float = 0.0


class OutputGuardrailEngine:
    """5-Step Output Guardrail 살균 및 검증 파이프라인 엔진."""

    # 1. 개인정보(PII) 및 대외비 원가 탐지 정규식
    RRN_PATTERN = re.compile(r"\b\d{6}-[1-4]\d{6}\b")                              # 주민등록번호 패턴
    CARD_PATTERN = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")      # 16자리 신용카드 번호 패턴
    PHONE_PATTERN = re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b")                  # 한국 휴대폰 번호 패턴
    COST_PATTERN = re.compile(r"(?i)(원가|cost_price|공급가)\s*[:=]?\s*([0-9,]+원?)")  # 대외비 원가 패턴

    # 2. 리버스 쉘 및 유해 OS 명령어 실행 페이로드 패턴
    REVERSE_SHELL_PATTERNS = [
        re.compile(r"(?i)\bnc\s+-e\s+/bin/sh\b"),
        re.compile(r"(?i)/bin/bash\s+-i"),
        re.compile(r"(?i)cmd\.exe\s+/c"),
        re.compile(r"(?i)powershell\.exe\s+-enc"),
        re.compile(r"(?i)python\s+-c\s+[\"']import socket"),
    ]

    # 3. 치명적인 시스템 내부 지침 및 시크릿 유출 패턴
    CRITICAL_LEAK_PATTERNS = [
        re.compile(r"(?i)POSTGRES_PASSWORD\s*="),
        re.compile(r"(?i)SECRET_KEY\s*="),
        re.compile(r"(?i)INTERNAL_API_KEY"),
        re.compile(r"(?i)You are an AI assistant created with the following secret instructions:"),
    ]

    def __init__(self) -> None:
        pass

    def evaluate(self, raw_output: str) -> OutputEvaluationResult:
        """5단계 출력 가드레일 살균 및 보안 검증을 실행합니다.

        Args:
            raw_output (str): 언어 모델이 생성한 원본 응답 텍스트

        Returns:
            OutputEvaluationResult: 안전하게 마스킹된 출력 텍스트 및 감사 지표
        """
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
        # Step 1: 치명적 시스템 기밀(DB 비밀번호, API Key) 유출 검사
        # 유출 조짐 발견 시 응답을 즉각 차단하고 경고 메시지로 대체합니다.
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
        # Step 2: 리버스 쉘 및 원격 명령어 실행(RCE) 페이로드 차단
        # LLM이 해킹 도구로 악용되어 쉘 명령어를 생성했을 때 전면 차단합니다.
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

        # 동적 룰셋(Output Rules) 적용
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
        # Step 3: PII(개인정보) 및 대외비 원가 마스킹 (Redaction)
        # 주민번호, 카드번호, 전화번호, 상품 원가를 [REDACTED] 로 자동 치환
        # -------------------------------------------------------------
        # 3.1 주민등록번호 마스킹
        if self.RRN_PATTERN.search(text):
            text = self.RRN_PATTERN.sub("[REDACTED_RRN]", text)
            pii_redacted = True
            detected_threats.append("PII_RRN")

        # 3.2 신용카드 번호 마스킹
        if self.CARD_PATTERN.search(text):
            text = self.CARD_PATTERN.sub("[REDACTED_CARD]", text)
            pii_redacted = True
            detected_threats.append("PII_CARD")

        # 3.3 휴대폰 번호 마스킹
        if self.PHONE_PATTERN.search(text):
            text = self.PHONE_PATTERN.sub("[REDACTED_PHONE]", text)
            pii_redacted = True
            detected_threats.append("PII_PHONE")

        # 3.4 대외비 상품 원가(cost_price) 마스킹
        if self.COST_PATTERN.search(text):
            text = self.COST_PATTERN.sub(r"\1: [REDACTED_CONFIDENTIAL_COST]", text)
            pii_redacted = True
            detected_threats.append("CONFIDENTIAL_COST_LEAK")

        # -------------------------------------------------------------
        # Step 4: XSS (Cross-Site Scripting) 태그 무력화
        # 챗봇 응답에 악성 <script>, <iframe> 태그가 포함되어 브라우저에서 실행되는 것을 방지
        # -------------------------------------------------------------
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
        # Step 5: 마크다운 악성 링크(javascript:, data:) 살균
        # 클릭 시 악성 스크립트를 실행하는 링크를 무해한 앵커로 치환
        # -------------------------------------------------------------
        malicious_link_pattern = re.compile(
            r"\[([^\]]+)\]\((javascript:|data:)[^\)]+\)", re.IGNORECASE
        )
        if malicious_link_pattern.search(text):
            text = malicious_link_pattern.sub(r"[\1](#blocked-unsafe-link)", text)
            detected_threats.append("UNSAFE_LINK_BLOCKED")

        # 최종 살균 결과 반환
        latency = (time.perf_counter() - start_time) * 1000.0
        return OutputEvaluationResult(
            is_allowed=True,
            sanitized_output=text,
            pii_redacted=pii_redacted,
            detected_threats=detected_threats,
            latency_ms=latency,
        )


# 전역 인스턴스
output_guardrail = OutputGuardrailEngine()
