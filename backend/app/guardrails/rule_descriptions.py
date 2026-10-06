"""Plain-language descriptions of rule ids for the ops screens (no patterns, no user text)."""

from __future__ import annotations

RULE_DESCRIPTIONS: dict[str, str] = {
    # input: prompt injection / jailbreak
    "RULE_TOKEN_FLOOD": "입력이 너무 길거나 반복이 많아 처리량을 고갈시키려는 시도",
    "RULE_IGNORE_INSTRUCTIONS": "기존 지시를 무시하라는 영어 지시 주입",
    "RULE_KOREAN_IGNORE_INSTRUCTIONS": "기존 지시를 무시하라는 한국어 지시 주입",
    "RULE_DAN_JAILBREAK": "DAN 등 '제한 없는 AI' 탈옥 시도",
    "RULE_DEV_MODE_JAILBREAK": "개발자 모드 전환을 가장한 탈옥 시도(영어)",
    "RULE_KOREAN_DEV_MODE": "개발자·관리자 모드 전환을 가장한 탈옥 시도(한국어)",
    "RULE_JAILBREAK_PERSONA": "역할극·가상 인격으로 규칙을 우회하려는 시도",
    "RULE_OBFUSCATED_SENSITIVE_TERM": "띄어쓰기·인코딩 등으로 민감한 단어를 숨긴 요청",
    "RULE_SEMANTIC_GRANDMA_EXPLOIT": "감정·사연에 기대어 금지 정보를 얻으려는 우회(할머니 수법 등)",
    "RULE_SEMANTIC_PERSONA_ESCAPE": "가상 상황을 빌려 원래 역할에서 벗어나게 하려는 시도",
    "RULE_MULTI_TURN_SECRET_FOLLOWUP": "여러 턴에 걸쳐 비밀정보를 이어서 캐내려는 시도",
    "RULE_INDIRECT_CONTEXT_INJECTION": "참고자료·도구 결과 안에 숨겨진 지시(간접 주입)",
    # input: disclosure / data access
    "RULE_SYSTEM_PROMPT_LEAK": "시스템 프롬프트·숨겨진 지시를 보여 달라는 요청(영어)",
    "RULE_KOREAN_SECRET_LEAK": "시스템 프롬프트·내부 설정을 보여 달라는 요청(한국어)",
    "RULE_PROMPT_EXTRACTION": "프롬프트 원문을 다른 형식으로 옮겨 빼내려는 시도",
    "RULE_CREDENTIAL_REQUEST": "비밀번호·API 키·토큰 등 자격 증명 요구",
    "RULE_PII_EXTRACTION_ATTEMPT": "다른 고객의 개인정보 요구",
    "RULE_CONFIDENTIAL_BUSINESS_DATA": "원가·마진·공급처 등 내부 영업정보 요구",
    "RULE_SEMANTIC_INDIRECT_EXFILTRATION": "우회 표현으로 내부 정보를 빼내려는 시도",
    # input: excessive agency / injection into downstream systems
    "RULE_PRIVILEGE_ESCALATION": "관리자 권한 획득 시도",
    "RULE_SQL_INJECTION_SYNTAX": "SQL 인젝션 구문",
    "RULE_SQL_COMMAND_ABUSE": "SQL 명령 실행 요구",
    "RULE_DANGEROUS_SHELL_INJECTION": "위험한 셸 명령 실행 요구",
    "RULE_SEMANTIC_PYTHON_SANDBOX_ESCAPE": "코드 실행 환경을 탈출하려는 시도",
    # LLM judge
    "RULE_LLM_JUDGE_INPUT": "AI 판별기가 입력(또는 클라이언트 참고자료)을 공격으로 판정",
    "RULE_LLM_JUDGE_TOOL": "AI 판별기가 도구 결과 안의 지시 주입을 탐지",
    "RULE_LLM_JUDGE_OUTPUT": "AI 판별기가 답변의 정보 유출을 탐지",
    # execution / policy
    "RULE_TOOL_NOT_ALLOWED": "허용되지 않은 도구 호출",
    "RULE_TOOL_ARGUMENT_INVALID": "도구 인자 형식 오류",
    "RULE_TOOL_OBJECT_ACCESS": "본인 소유가 아닌 주문·장바구니 등에 접근 시도",
    "RULE_TOOL_CONFIRMATION_REQUIRED": "변경 작업이라 고객 승인 대기(차단 아님, 기록용)",
    "RULE_TOOL_BUDGET": "한 요청의 도구 호출 횟수 한도 초과",
    "RULE_SERVER_ENFORCEMENT": "서버 정책(가드레일 강제)에 따른 거부",
    # output
    "RULE_CRITICAL_SECRET_DUMP": "답변에 핵심 비밀정보가 포함되어 답변 전체 차단",
    "RULE_BULK_PII_DUMP": "답변에 개인정보가 대량으로 포함되어 차단",
    "RULE_SYSTEM_PROMPT_OUTPUT": "답변이 시스템 프롬프트를 재현하여 차단",
    "RULE_REVERSE_SHELL_OUTPUT": "답변에 리버스 셸 명령이 포함되어 차단",
    "RULE_RCE_COMMAND_OUTPUT": "답변에 원격 코드 실행 명령이 포함되어 차단",
    "RULE_SECRET": "답변 속 비밀값 마스킹",
    "RULE_TOKEN_SECRET": "답변 속 토큰·키 형태 문자열 마스킹",
    "RULE_RRN": "답변 속 주민등록번호 마스킹",
    "RULE_CARD": "답변 속 카드번호 마스킹",
    "RULE_ACCOUNT": "답변 속 계좌번호 마스킹",
    "RULE_PHONE": "답변 속 전화번호 마스킹",
    "RULE_EMAIL": "답변 속 이메일 마스킹",
    "RULE_ADDRESS": "답변 속 주소 마스킹",
    "RULE_XSS_SANITIZE": "답변 속 실행 가능한 HTML·스크립트 무력화",
    "RULE_MARKDOWN_IMAGE_EXFIL": "외부 이미지로 정보를 빼내는 마크다운 무력화",
    "RULE_UNSAFE_URL": "위험한 링크 무력화",
}

# Fallback for rules added later through the ruleset screen (OWASP Top 10 for LLM Applications 2025).
CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "LLM01:2025": "프롬프트 인젝션",
    "LLM02:2025": "민감정보 노출",
    "LLM03:2025": "공급망",
    "LLM04:2025": "데이터·모델 오염",
    "LLM05:2025": "부적절한 출력 처리",
    "LLM06:2025": "과도한 권한",
    "LLM07:2025": "시스템 프롬프트 유출",
    "LLM08:2025": "벡터·임베딩 취약점",
    "LLM09:2025": "허위 정보",
    "LLM10:2025": "무제한 자원 소비",
}


def describe(rule_id: str, category: str) -> str:
    return RULE_DESCRIPTIONS.get(rule_id) or f"{CATEGORY_DESCRIPTIONS.get(category, category)} 관련 규칙"
