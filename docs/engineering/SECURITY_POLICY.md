# 보안 정책 및 위협 모델링 (SECURITY_POLICY.md)

## 1. 개요 (Security Policy Overview)
본 문서는 `AI Security Guardrail Chatbot`의 전반적인 보안 원칙, 위협 모델(Threat Model), OWASP Top 10 for LLM 대응 체계 및 다계층 방어 정책을 명시합니다.

---

## 2. 핵심 보안 원칙 (Core Security Principles)

1. **심층 방어 (Defense-in-Depth)**:
   단일 방어선(예: 단순 키워드 필터)에 의존하지 않고, 입력(Input), 도구 실행(Execution), 출력(Output), 감사(Audit)의 4중 방어선을 구축합니다.
2. **기본 차단 (Fail-Closed)**:
   보안 검사 엔진에서 예외 또는 타임아웃이 발생하거나 불확실한 상태일 경우, 요청을 통과시키지 않고 안전하게 차단(`BLOCKED`)합니다.
3. **최소 권한 (Least Privilege)**:
   AI 모델 및 도구(Shop Tools)는 사용자의 세션 및 인가된 권한 범위 내의 데이터에만 접근할 수 있습니다.
4. **절대 신뢰 금지 (Zero-Trust for AI Outputs)**:
   AI 모델(SLM/LLM)이 생성한 응답 텍스트와 Function Calling 인자는 악의적 프롬프트에 오염될 수 있으므로, 최종 사용자 또는 DB에 전달되기 전에 반드시 재검증합니다.

---

## 3. OWASP Top 10 for LLM 위협 대응 매트릭스

| OWASP LLM ID | 위협 명칭 (Threat Name) | 공격 시나리오 | 적용 보안 통제 (Security Control) |
| :--- | :--- | :--- | :--- |
| **LLM01** | **Prompt Injection** (프롬프트 인젝션) | 지시 무시, 시스템 프롬프트 우회, 악의적 명령 주입 | Input Guardrail 단계별 유니코드 정규화, 디오브퓨스케이션, 위협 시그니처 매칭 |
| **LLM02** | **Insecure Output Handling** (출력 취급 부실) | AI 응답에 XSS 스크립트, 리버스 쉘 명령어 삽입 | Output Guardrail의 XSS 살균(HTML Escape), 리버스 쉘 패턴 탐지, 마크다운 필터링 |
| **LLM06** | **Excessive Agency** (과도한 권한 위임) | 타인의 주문 임의 취소, 대량 환불 트리거 | Execution Guardrail의 BOLA/IDOR 검증 및 세션-소유권 엄격 일치 확인 |
| **LLM07** | **System Prompt Leakage** (시스템 프롬프트 유출) | 내부 시스템 지침, 내부 API Key, DB 구조 질의 | Input 단계 프롬프트 덤프 시그니처 차단 및 Output 단계 시스템 지침 유출 패턴 검출 |
| **LLM08** | **Vector and Embedding Weaknesses** | 오염된 데이터 주입 | Ground-Truth RDBMS 데이터 주입 시 엄격한 스키마 검증 |

---

## 4. 세부 가드레일 정책 명세

### 4.1 Input Guardrail (7단계 파이프라인)
1. **Request Validation**: 유효하지 않은 JSON 구조, 빈 페이로드, 비정상 헤더 즉시 거부 (HTTP 400).
2. **Length & Token Limit**: 최대 2,000자 초과 시 차단하여 버퍼 고갈 및 DoS 공격 방지.
3. **Unicode Normalization**: Unicode NFKC 표준 변환을 수행하여 전각 문자, 서식 변형을 통한 필터 우회 무력화.
4. **Confusable Character Detection**: 키릴 문자(а, е, о, р, с), 그리스 문자 등 라틴 알파벳과 시각적으로 동일한 위장 문자 탐지 및 변환.
5. **De-obfuscation**: Base64 문자열, URL 인코딩(`%20`, `%27`), Hex 인코딩(`0x...`)을 디코딩하여 은닉된 페이로드 검사.
6. **Threat Signature Matching**:
   - `ignore (all )?previous instructions`
   - `system prompt (leak|dump|show)`
   - `DAN mode|jailbreak|unrestricted AI`
   - `UNION SELECT|OR 1=1|DROP TABLE`
   - `관리자 권한|비밀번호 알려줘|원가 공개`
7. **Semantic & Persona Boundary**: 고객 상담 범위를 벗어난 해킹, 시스템 파일 열람, 공격적 페르소나 강제 요구 차단.

### 4.2 Execution Guardrail (BOLA / IDOR 인가 통제)
- `get_order_detail`, `cancel_order` 등 도구 실행 시:
  - 현재 인증된 `customer_id`와 요청 파라미터의 주문 소유자가 일치하는지 DB 레벨 교차 검증.
  - 관리자 전용 기능(상품 원가 수정, 전체 회원 조회) 호출 요청 시 즉시 인가 실패(`FORBIDDEN`) 처리.

### 4.3 Output Guardrail (5단계 정제 파이프라인)
1. **Critical Leak Detection**: `INTERNAL_API_KEY`, `POSTGRES_PASSWORD`, `You are an AI developed by...` 등 시스템 내부 자산 유출 차단.
2. **Reverse Shell / Code Payload Detection**:
   - `nc -e /bin/sh`, `/bin/bash -i`, `cmd.exe /c`, `powershell.exe -enc`, `python -c "import socket..."` 패턴 탐지 시 마스킹 또는 차단.
3. **PII Detection & Redaction**:
   - 주민등록번호: `\d{6}-[1-4]\d{6}` -> `[REDACTED_RRN]`
   - 카드번호: `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}` -> `[REDACTED_CARD]`
   - 전화번호: `01[016789]-?\d{3,4}-?\d{4}` -> `[REDACTED_PHONE]`
   - **대외비 상품 원가(`cost_price`)**: 텍스트 내 원가 노출 패턴 탐지 시 `[REDACTED_COST]` 마스킹.
4. **XSS Sanitization**: `<script>`, `onerror=`, `onload=`, `<iframe>` 등 악성 태그 무력화.
5. **Markdown Safety**: `javascript:`, `data:text/html` 링크 스키마 차단.

---

## 5. 보안 감사 및 인시던트 대응 (Security Audit & Response)
- 모든 차단(`BLOCKED`) 및 변조(`REDACTED`) 이벤트는 **Async Audit Logger**를 통해 `audit.security_logs`에 영구 기록.
- 공격자의 원본 IP, 탐지 룰 ID, 페이로드 해시, 처리 시간을 기록하여 향후 위협 인텔리전스 룰셋 고도화에 활용.
