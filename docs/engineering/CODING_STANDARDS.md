# 코딩 표준 및 개발 규약 (CODING_STANDARDS.md)

## 1. 개요 (Overview)
본 문서는 `AI Security Guardrail Chatbot` 프로젝트의 모든 소스코드에 적용되는 표준 코딩 규칙 및 아키텍처 원칙을 정의합니다. 일관된 코드 스타일과 높은 보안성을 유지하여 결함을 사전에 방지하는 것을 목표로 합니다.

---

## 2. Python 코딩 표준

### 2.1 스타일 및 포맷팅 (Style & Formatting)
- **표준 가이드**: PEP 8 표준을 준수하며, 린터 및 포매터로 **Ruff**를 사용합니다.
- **최대 라인 길이 (Line Length)**: 100자 이내.
- **들여쓰기 (Indentation)**: 4개의 공백(Spaces) 사용 (Tab 사용 금지).
- **따옴표 (Quotes)**: 문자열은 큰따옴표(`"`)를 기본으로 사용합니다.

### 2.2 타입 힌트 (Type Hints)
- 모든 함수의 인자(Parameters)와 반환값(Return Type)에는 엄격한 Type Hint를 적용합니다.
- 복합 타입에는 Python 3.10+ 표준 문법(`list[str]`, `dict[str, Any]`, `str | None`)을 사용합니다.
```python
# 올바른 예시
def validate_payload(input_text: str, max_length: int = 2000) -> tuple[bool, str | None]:
    if len(input_text) > max_length:
        return False, "INPUT_LENGTH_EXCEEDED"
    return True, None
```

### 2.3 데이터 유효성 검증 (Pydantic v2)
- 모든 API 요청 및 응답, 내부 DTO는 `pydantic.BaseModel`을 사용하여 데이터 타입을 검증합니다.
- 환경변수 로딩은 `pydantic_settings.BaseSettings`를 통해 엄격하게 검증합니다.

### 2.4 네이밍 컨벤션 (Naming Conventions)
- **모듈/패키지**: 소문자 및 밑줄 (`input_guardrail.py`)
- **클래스명**: 파스칼 표기법 (`InputGuardrailEngine`, `ShopDAO`)
- **함수/메서드/변수명**: 스네이크 표기법 (`check_security_rules`, `threat_count`)
- **상수명**: 대문자 및 밑줄 (`DEFAULT_MAX_TOKENS`, `CONFUSABLE_MAP`)

---

## 3. 아키텍처 및 설계 원칙

### 3.1 계층 분리 (Separation of Concerns)
1. **API Layer (`api/`)**: HTTP 라우팅, 요청/응답 직렬화, HTTP 상태 코드 매핑. 비즈니스 로직 및 DB 쿼리 직접 작성 금지.
2. **Service Layer (`services/`)**: 핵심 비즈니스 로직, 오케스트레이션, 외부 AI 모델 연동.
3. **Guardrail Layer (`guardrails/`)**: 순수 보안 검증 로직, 룰셋 엔진. 비즈니스 DB에 직접 의존하지 않고 DAO/Cache를 통해 전달받음.
4. **Repository / DAO Layer (`repositories/`)**: 데이터베이스 접근 및 SQL 실행 전담.
5. **Core Layer (`core/`)**: 공통 설정, 로깅, 커스텀 예외.

### 3.2 예외 처리 규약 (Exception Handling)
- `except Exception:`과 같은 무분별한 Catch-All 패턴은 금지하며, 발생 가능한 구체적 예외를 포착합니다.
- 보안 예외 발생 시 내부 시스템 스택트레이스나 DB 에러가 클라이언트에 노출되지 않도록 표준 `SecurityException`으로 래핑합니다.
- 예외 발생 시 반드시 구조화된 로거(`logging`)를 통해 원인을 기록합니다.

```python
# 올바른 예시
from app.core.exceptions import GuardrailBlockException
from app.core.logging import logger

try:
    rule_engine.evaluate(user_input)
except ThreatDetectedError as e:
    logger.warning(f"Security threat detected: {e.rule_id} from {client_ip}")
    raise GuardrailBlockException(reason=e.message)
```

---

## 4. 하드코딩 방지 및 시크릿 관리 규칙
1. 소스코드 내에 IP, 포트, DB 접속 패스워드, JWT Secret, API Key 등을 직접 문자열로 기록하는 행위를 절대 금지합니다.
2. 로컬 개발 환경은 `.env` 파일을 사용하며, Git 저장소에는 템플릿인 `.env.example`만 커밋합니다.
3. 설정값은 반드시 `app.core.config.Settings` 인스턴스를 통해서만 접근합니다.

---

## 5. 프론트엔드 (Frontend) 코딩 규약
- 외부 라이브러리(JQuery 등)의 무분별한 의존을 지양하고, 최신 Vanilla JavaScript (ES6+) 및 시맨틱 HTML5를 사용합니다.
- API 엔드포인트 URL은 상대 경로(`/api/v1/...`)를 사용하여 Nginx 프록시 환경에서 유연하게 작동하도록 구성합니다.
- 사용자 입력 텍스트를 렌더링할 때는 `innerHTML` 대신 `textContent`를 사용하여 DOM 기반 XSS를 방지합니다.
