"""Input Guardrail Pipeline (7단계 심층 입력 보안 검증 파이프라인).

이 모듈은 사용자가 입력한 프롬프트가 언어 모델(LLM)에 전달되기 전에
악의적인 프롬프트 인젝션, 탈옥(Jailbreak), 난독화 공격, SQL 인젝션, 대외비 원가 탈취 시도를
7단계의 정밀 필터링을 거쳐 초고속(< 0.3ms)으로 탐지하고 차단합니다.
"""

import base64
import contextlib
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
    """Input Guardrail 검사 결과 데이터 클래스 (DTO).

    Attributes:
        is_allowed (bool): 입력 허용 여부 (True: 정상 통과, False: 보안 차단)
        reason (str | None): 차단 또는 처리 사유
        threat_type (str | None): 탐지된 위협 명칭 (예: 'PROMPT_INJECTION', 'SQL_INJECTION')
        rule_id (str | None): 일치한 보안 룰 ID (예: 'INJ-001', 'SEM-VEC-001')
        sanitized_text (str): 유니코드 정규화 및 난독화 해제 과정을 거친 정제된 텍스트
        latency_ms (float): 검사에 소요된 시간 (밀리초, ms)
    """

    is_allowed: bool
    reason: str | None = None
    threat_type: str | None = None
    rule_id: str | None = None
    sanitized_text: str = ""
    latency_ms: float = 0.0


class InputGuardrailEngine:
    """7-Step Multi-Tier Input Guardrail 엔진.

    [검증 파이프라인 단계]:
    - Step 1: 요청 유효성 검증 (빈 문자열, 공백 방지)
    - Step 2: 글자 수 및 토큰 길이 제한 (DoS/버퍼 고갈 방지)
    - Step 3: 유니코드 NFKC 정규화 및 제로 너비(Zero-Width) 숨김 문자 제거
    - Step 4: 호모글리프(유사 문자) 치환 (러시아어/키릴 문자 혼합 우회 무력화)
    - Step 5: 다중 난독화 해제 (URL 디코딩, Base64, ROT13, Leetspeak, XML 태그 파싱)
    - Step 6: 동적 위협 인텔리전스 시그니처 및 정규식 검사 (Hot-Reload 룰 매칭)
    - Step 7: Subword N-Gram TF-IDF 벡터 코사인 유사도 시맨틱 검사
    """

    # 키릴(Cyrillic) 문자 및 유사 알파벳을 표준 라틴 문자로 매핑하는 호모글리프 사전
    # 예: 러시아어 'а'(U+0430) -> 영어 'a'(U+0061)로 변환하여 시그니처 우회 방지
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

    # Base64 인코딩 문자열 패턴 (4의 배수 길이와 패딩 문자 '=' 탐지)
    BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

    def __init__(self) -> None:
        pass

    def evaluate(self, raw_input: str) -> InputEvaluationResult:
        """7단계 입력 검증 파이프라인을 순차적으로 실행합니다.

        Args:
            raw_input (str): 사용자가 전송한 원본 텍스트 문자열

        Returns:
            InputEvaluationResult: 보안 차단 여부, 탐지된 위협, 정제된 텍스트
        """
        start_time = time.perf_counter()

        # -------------------------------------------------------------
        # Step 1: 요청 유효성 검증 (Request Validation)
        # 빈 문자열이나 공백만 들어온 경우 불필요한 LLM 호출을 차단합니다.
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
        # Step 2: 입력 길이 제한 (Token / Character Length Limit)
        # 과도하게 긴 페이로드를 주입하여 서버 메모리를 고갈시키는 DoS 공격을 차단합니다.
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
        # Step 3: 유니코드 NFKC 정규화 & 제로 너비(Zero-Width) 숨김 문자 제거
        # 눈에 보이지 않는 제로 너비 공백(\u200b 등)을 문자 사이에 끼워넣는 공격을 완전히 제거합니다.
        # -------------------------------------------------------------
        clean_zw_text = re.sub(
            r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u2061\u2062\u2063\u2064]",
            "",
            text,
        )
        normalized_text = unicodedata.normalize("NFKC", clean_zw_text)

        # -------------------------------------------------------------
        # Step 4: 호모글리프(Confusable) 탐지 및 라틴 문자 치환
        # 모양이 동일한 러시아어/키릴 자모를 영어 알파벳으로 변환합니다.
        # -------------------------------------------------------------
        transliterated_chars = []
        for ch in normalized_text:
            transliterated_chars.append(self.HOMOGLYPH_MAP.get(ch, ch))
        transliterated_text = "".join(transliterated_chars)

        # -------------------------------------------------------------
        # Step 5: 다중 난독화 해제 (De-obfuscation)
        # URL 디코딩, Leetspeak, XML/HTML 태그 제거, Base64/ROT13 암호문 복호화
        # -------------------------------------------------------------
        decoded_text = urllib.parse.unquote(transliterated_text)

        # 5.1 공백 제거 및 특수문자 제거 변형본 생성 (중간에 특수문자를 끼워넣은 공격 방어)
        collapsed_all_spaces = re.sub(r"\s+", "", decoded_text)
        punct_collapsed = re.sub(r"[\.\-_,/|#*`~<>\(\)\[\]\{\}]", "", decoded_text)
        punct_space_collapsed = re.sub(r"\s+", "", punct_collapsed)

        extra_payloads: list[str] = []

        # 5.2 릿스픽(Leetspeak) 치환 (예: 1gn0r3 -> ignore)
        leet_translated = decoded_text.translate(str.maketrans("013457@", "oieasta"))
        if leet_translated != decoded_text:
            extra_payloads.append(leet_translated)

        # 5.3 태그 및 구분자 제거 후 내부 원본 추출 (예: <admin_command>...</admin_command>)
        tag_stripped = re.sub(
            r"<[^>]+>|\[/?[^\]]+\]|```[\w]*|<!--\s*#?\s*[\w:]*|-->", " ", decoded_text
        )
        if tag_stripped != decoded_text:
            extra_payloads.append(tag_stripped)
            extra_payloads.append(re.sub(r"\s+", "", tag_stripped))

        # 5.4 Base64 인코딩 페이로드 탐지 및 디코딩
        b64_prefix = re.search(r"(?i)base64\s*:\s*([a-zA-Z0-9+/=]{8,})", decoded_text)
        if b64_prefix:
            with contextlib.suppress(Exception):
                extra_payloads.append(
                    base64.b64decode(b64_prefix.group(1)).decode("utf-8", errors="ignore")
                )

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

        # 5.5 ROT13 카이사르 암호 복호화
        rot13_prefix = re.search(r"(?i)(?:cipher\s+)?rot13\s*:\s*(.+)", decoded_text)
        if rot13_prefix:
            try:
                import codecs
                extra_payloads.append(codecs.decode(rot13_prefix.group(1).strip(), "rot_13"))
            except Exception:
                pass
        try:
            rot13_candidate = decoded_text.encode("utf-8").decode("rot13", errors="ignore")
            if any(
                w in rot13_candidate.lower()
                for w in ["ignore", "prompt", "system", "password", "select", "cost"]
            ):
                extra_payloads.append(rot13_candidate)
        except Exception:
            pass

        # 5.6 16진수(Hex) 스트림 디코딩 (예: 0x53595354...)
        hex_matches = re.findall(r"(?:0x)?([0-9a-fA-F]{10,})", decoded_text)
        for h in hex_matches:
            try:
                raw_bytes = bytes.fromhex(h)
                hex_str = raw_bytes.decode("utf-8", errors="ignore")
                if any(c.isalnum() for c in hex_str):
                    extra_payloads.append(hex_str)
            except Exception:
                pass

        # 정규식 및 시맨틱 검사 대상 텍스트 풀 구성
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
        # Step 6: 동적 위협 인텔리전스 시그니처 및 정규식 검사 (Hot-Reload 룰 매칭)
        # PostgreSQL / RuleCacheManager 에 등록된 룰들을 실시간으로 대조합니다.
        # -------------------------------------------------------------
        input_rules = rule_manager.get_input_rules()

        for pool_item in inspection_pool:
            lower_pool_item = pool_item.lower()

            for rule in input_rules:
                if not rule.is_active:
                    continue

                # 6.1 정규식(REGEX) 패턴 검사
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

                # 6.2 키워드(KEYWORD) 단순 일치 검사
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
        # Step 7: 시맨틱 & 벡터 기반 위협 평가 (Semantic Threat Evaluation)
        # 정규식을 교묘하게 우회한 의미론적(Semantic) 공격을 벡터 유사도로 탐지합니다.
        # -------------------------------------------------------------
        # 7.1 페르소나 하이재킹 및 탈옥 키워드 조합 검사
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

        # 7.2 서브워드 N-Gram TF-IDF 벡터 코사인 유사도 검사
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
        # 모든 7단계 검증 통과: 안전한 정상 입력으로 최종 승인
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


# 전역 인스턴스
input_guardrail = InputGuardrailEngine()
