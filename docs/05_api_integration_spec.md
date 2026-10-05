# API·연동 명세서

| 항목 | 값 |
|---|---|
| 문서 번호 / 버전 / 작성일 | DES-005 / 1.1 / 2026-10-02 (D-14~D-21 반영) |
| 상태 | 구현 전 제안 API·wire 계약 |
| 연계 | [DB](02_database_design.md), [화면](04_screen_design.md), [가드레일·Tool](06_guardrail_security_design.md) |

## 1. 공통 계약과 인증

고객 Base URL은 `https://shop.example.internal`, 관리 API는 관리망의 `https://ops.example.internal`이다. 모든 고객 API는 `/api/v1`, OpenAI 호환 subset은 `/v1`을 사용한다. JSON은 UTF-8, UUID는 canonical 문자열, 시간은 UTC ISO 8601, 금액은 KRW 정수다. 요청·응답·오류 모두 `X-Request-Id`를 반환한다. 클라이언트가 보낸 같은 이름의 헤더는 추적 연계용일 뿐 서버 ID를 덮어쓰지 않는다.

### 1.1 인증 방식

access JWT는 `Authorization: Bearer <access_token>`으로 전달한다. RS256, 키 ID `kid`, `iss=ai-guardrail`, `aud=ai-guardrail-api`, `sub=user UUID`, `role`, `token_version`, `jti`, `iat`, `exp`를 사용한다. 유효기간은 15분이다. 허용 알고리즘·키·issuer·audience·시간을 고정 검증하고 DB의 is_active·role·token_version을 대조한다. 사용자·role·scope를 body나 클라이언트 system message에서 취득하지 않는다.

refresh token은 7일 유효한 opaque 난수다. 웹에서는 `guardrail_refresh` 이름의 `HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth` cookie로 보관하고 회전한다. 회전은 token 행을 잠근 한 transaction에서 수행해 같은 token이 두 번 회전되지 않게 한다. cookie 기반 refresh/logout은 허용 Origin과 CSRF cookie/header의 일치도 검증한다. CSRF 값은 로그인 응답의 `csrf_token`에도 제공하며 쿠키명은 `guardrail_csrf`(새로고침 후에도 읽을 수 있도록 HttpOnly 아님, `Secure; SameSite=Strict; Path=/`), 헤더는 `X-CSRF-Token`이다. 로그인 실패는 IP·이메일별 15분 10회를 넘으면 429다(단일 worker 메모리 카운터). 동일 refresh가 재사용되면 family 전체를 폐기한다. 비밀번호는 최소 12자·최대 128자, Argon2id 해시를 사용하고 로그인 오류는 계정 존재 여부를 구분하지 않는다.

웹 access token은 메모리에 보관하며 localStorage·URL에 넣지 않는다. Streamlit은 사용자별 requests session·JWT·refresh cookie를 해당 사용자 `st.session_state`에만 유지하고 브라우저의 관리망 Origin에 해당하는 값으로 서버 간 인증 요청을 보낸다. 전역 변수·캐시로 사용자 토큰을 공유하지 않는다. 로그아웃은 refresh family를 폐기하고 token_version을 증가시켜 **모든 기기 JWT·클라이언트 토큰**을 무효화한다.

AnythingLLM은 30일 유효 opaque token(`gct_` 접두사 + 256-bit 난수)을 API Key에 입력한다. 저장은 전체 문자열 SHA-256 해시만 수행한다. 발급 시 token_version·scope를 저장하고 매 요청 사용자 활성·현재 버전을 확인한다. 기본 scope는 `chat:write`, `models:read`, `tools:read`, `shop:read`, `actions:propose`다. token으로 승인 실행·계정·관제·룰 게시 API에 접근할 수 없다.

| 주체 | 허용 |
|---|---|
| customer JWT | 본인 세션·상품·주문·cart·쿠폰·제안·승인·클라이언트 토큰 |
| operator JWT | 관제 조회·PDF·본인 검증 챗, 고객 데이터 변경·정책 게시 불가 |
| admin JWT | operator 기능 + 룰 편집·검증·게시·롤백, 고객으로 가장한 변경 불가 |
| client token | scope와 소유권 범위의 호환 챗·모델 목록·Tool 목록·읽기·변경 제안 |

operator/admin 검증 챗에는 합성 컨텍스트만 제공하고 실제 고객 주문·cart Tool을 부여하지 않는다. 관리망 외부에서는 관리 API를 라우팅하지 않는다. role 검증은 네트워크 제한과 별도로 수행한다.

진입 채널은 `X-Edge-Channel` 헤더로 판정한다(D-17). shop Nginx는 이 값을 항상 `shop`으로 덮어쓰고, Streamlit 서버만 app 내부망에서 `ops`로 호출한다. AUDIT·RULE·LAB API는 ops 채널이 아니면 404, operator/admin 토큰을 shop 채널에서 쓰거나 customer·client token을 ops 채널에서 쓰면 403 FORBIDDEN이다. AUTH-02도 채널과 계정 role이 맞지 않으면 일반 인증 실패와 같은 401로 응답한다.

### 1.2 공통 응답·오류

챗봇 외 정상 JSON은 `{"request_id":"UUID","data":...}` 형식이다. 목록의 data는 `{"items":[],"next_cursor":null}`이며 기본 limit=20·최대 100이다. cursor는 서버가 서명한 정렬 위치이며 임의 SQL·사용자 ID가 아니다. 조회 시간 범위는 `[from,to)`이고 최대 90일이다. 감사 PDF는 최대 31일·10,000 이벤트로 제한한다.

```json
{
  "request_id": "10000000-0000-4000-8000-000000000001",
  "error": {
    "code": "ACTION_STALE",
    "message": "장바구니가 변경되었습니다. 내용을 다시 확인해 주세요."
  }
}
```

| HTTP | 대표 code | 처리 |
|---|---|---|
| 400 | INVALID_REQUEST, UNSUPPORTED_MODEL | 형식·지원 옵션 오류 |
| 401 | AUTH_REQUIRED, INVALID_CREDENTIALS, TOKEN_EXPIRED, TOKEN_REVOKED | 로그인·토큰 갱신, 로그인 실패는 계정 유무·비활성·채널 불일치를 구분하지 않는 INVALID_CREDENTIALS |
| 403 | FORBIDDEN, GUARDRAIL_BLOCKED | 역할·scope 금지, 전용 챗 차단 |
| 404 | NOT_FOUND | 객체 없음 또는 다른 사용자 소유, 존재 여부 비공개 |
| 409 | SESSION_BUSY, ACTION_STALE, ACTION_TERMINAL, IDEMPOTENCY_CONFLICT, EMAIL_UNAVAILABLE | 동시성·terminal 충돌, 회원가입 이메일 중복 |
| 410 | ACTION_EXPIRED | 만료한 본인 승인 |
| 413 | BODY_TOO_LARGE | body 262,144 bytes 초과 |
| 422 | VALIDATION_ERROR | 필드·길이·인자·미지원 role 오류 |
| 429 | RATE_LIMITED | Retry-After 정수 초 제공 |
| 502 / 504 | INFERENCE_UNAVAILABLE / INFERENCE_TIMEOUT | 모델 연결 / deadline 실패 |
| 503 | AUDIT_UNAVAILABLE, RULESET_UNAVAILABLE, SERVICE_NOT_READY, GUARDRAIL_TIMEOUT, GUARDRAIL_UNAVAILABLE | 안전한 처리 기반 미준비·검사 예산 초과·AI 판별 실패(Retry-After 포함, "잠시 후 다시 시도") |

429는 사용자·IP 예산 외에 서버 추론 대기열(동시 1건, 대기 30초 초과)에서도 발생한다. 인증 성공 이전에 반환하는 401·413·429·400은 감사 outbox에 기록하지 않고 access log·메트릭에만 남긴다(D-19). 비밀·토큰·매칭 공격 원문·stack trace·DB error detail은 오류 응답에 포함하지 않는다. 운영 가드레일 해제 필드는 어떤 API에도 없다. 감사 저장 실패는 다른 결과보다 우선하여 503으로 반환한다.

## 2. API 목록

### 2.1 인증·세션

| API ID | Method / Path | 인증·입력 | 정상 출력 |
|---|---|---|---|
| AUTH-01 | POST /api/v1/auth/register | 공개, email·password, customer만 생성 | 201 user{id,email,role}, cart 함께 생성 |
| AUTH-02 | POST /api/v1/auth/login | 공개, email·password | 200 access_token·expires_in=900·user·csrf_token, refresh cookie |
| AUTH-03 | POST /api/v1/auth/refresh | refresh cookie + CSRF | 200 새 access_token·csrf_token, refresh 회전 |
| AUTH-04 | POST /api/v1/auth/logout | JWT + refresh/CSRF | 204 모든 기기 토큰 무효화·cookie 제거 |
| AUTH-05 | POST /api/v1/auth/client-tokens | customer JWT, name·scopes | 201 id·token(1회)·scopes·expires_at |
| AUTH-06 | GET /api/v1/auth/client-tokens | customer JWT | 200 본인 목록, token/hash 미노출 |
| AUTH-07 | DELETE /api/v1/auth/client-tokens/{id} | customer JWT, 본인 토큰 | 204 폐기, 재폐기 204 |
| SESSION-01 | POST /api/v1/sessions | JWT 또는 chat:write token, body {} | 201 session_id·source |
| SESSION-02 | GET /api/v1/sessions/{id} | 본인 세션 | 200 정제된 context_redacted·last_activity_at, 내부 risk_signals 미노출 |

register로 operator/admin을 요청하면 422다. 관리 계정 생성·역할 변경은 초기 내부 관리 명령의 업무로 두고 공개 API로 제공하지 않는다. 계정·토큰 변경도 outbox 영속화와 같은 transaction으로 처리한다. 토큰 발급 응답은 HTTPS에서 한 번만 전달하며 서버는 평문을 복구할 수 없다.

source는 서버가 토큰 종류·역할·라우트로 결정한다. client token은 anythingllm, customer JWT는 web, 관리 JWT의 검증 세션은 streamlit이다. source 필드는 접근 권한의 근거로 쓰지 않는다.

### 2.2 챗봇·도구

| API ID | Method / Path | 인증·계약 | 정상 출력 |
|---|---|---|---|
| CHAT-01 | POST /api/v1/chat/completions | JWT, native ChatRequest | ChatResponse JSON 또는 native SSE |
| CHAT-02 | POST /v1/chat/completions | customer JWT 또는 chat:write token | OpenAI 호환 text chat JSON/SSE subset |
| CHAT-03 | GET /v1/models | customer JWT 또는 models:read token | data에 qwen3:8b 1개 |
| TOOL-01 | GET /api/v1/tools | JWT 또는 tools:read token | 허용 Tool 명칭·인자·requires_confirmation |

Tool 목록 API는 실행 endpoint가 아니다. 모델이 제안한 함수는 서버 ToolRegistry에서만 실행한다. 클라이언트가 보낸 임의 tools·tool_choice 또는 role=tool을 통해 함수를 실행하지 않는다.

### 2.3 쇼핑·승인

| API ID | Method / Path | 입력·권한 | 정상 data |
|---|---|---|---|
| SHOP-01 | GET /api/v1/products | customer JWT 또는 shop:read token, q≤100자·cursor·limit | id·sku·name·description·price_krw·stock_count |
| SHOP-02 | GET /api/v1/products/{id} | 위와 동일, 활성 상품 | 상품 상세 |
| SHOP-03 | GET /api/v1/orders | 본인 소유, cursor·limit | id·external_ref·status·total_krw·placed_at |
| SHOP-04 | GET /api/v1/orders/{id} | 본인 주문 | 주문과 items{product_id,name,quantity,unit_price_krw} |
| SHOP-05 | GET /api/v1/cart | 본인 cart | cart_id·version·items·coupon·subtotal_krw·discount_krw·total_krw |
| SHOP-06 | GET /api/v1/coupons | 본인 쿠폰 | id(보유 쿠폰 UUID)·code·state·expires_at·eligible·reason |
| ACTION-01 | POST /api/v1/actions | customer JWT 또는 actions:propose token | 201 action_id·state=pending·expires_at·preview·confirmation_url |
| ACTION-02 | GET /api/v1/actions/{id} | customer JWT, 본인 승인 | state·안전한 preview·확정 result |
| ACTION-03 | POST /api/v1/actions/{id}/confirm | customer JWT, Idempotency-Key 필수, body {} | 200 state=executed·result, 재확인 시 저장 결과 |
| ACTION-04 | POST /api/v1/actions/{id}/cancel | customer JWT, body {} | 200 state=cancelled, 이미 cancelled면 같은 결과 |

ACTION-01 입력은 `tool_name`, `arguments`, `base_version`, 선택 `session_id`다. target_id·user_id·ruleset_version·hash·만료는 서버가 정한다. tool_name은 `set_cart_item`, `remove_cart_item`, `apply_coupon`, `remove_coupon` 중 하나이며 [DES-006 Tool 표](06_guardrail_security_design.md#5-tool-실행-권한과-변경-확인)의 strict 인자를 적용한다.

```json
{
  "tool_name": "set_cart_item",
  "arguments": {"product_id": "20000000-0000-4000-8000-000000000001", "quantity": 2},
  "base_version": 4
}
```

preview는 모델이 쓴 문장 대신 서버가 조회한 상품명·변경 전후 수량·현재 금액·쿠폰 조건으로 생성한다. confirmation_url은 `https://shop.example.internal/actions/{action_id}`이며 토큰·사용자 식별 정보를 query에 포함하지 않는다. action_id는 권한을 대신하지 않으며 열람·확인 때 반드시 로그인·소유권을 재검증한다. 승인 단계에서 추가 인자·가격·user_id를 받으면 422다.

### 2.4 관제·규칙·상태

| API ID | Method / Path | 입력·권한 | 정상 출력 |
|---|---|---|---|
| AUDIT-01 | GET /api/v1/audit/events | operator/admin, from·to·status·stage·session_id·cursor·limit | 마스킹된 이벤트 목록 |
| AUDIT-02 | GET /api/v1/audit/events/{id} | operator/admin | 이벤트·rule_hits·tool_executions |
| AUDIT-03 | GET /api/v1/audit/stats | operator/admin, from·to·session_id | total·status_counts·category_counts·latency_p95_ms |
| AUDIT-04 | GET /api/v1/audit/report | operator/admin, from·to·session_id·format=pdf | application/pdf, attachment, no-store |
| RULE-01 | GET /api/v1/rulesets | operator/admin | 버전 목록·state·checksum·active 표시 |
| RULE-02 | GET /api/v1/rulesets/{id} | operator/admin | rules·policy·checksum·검증 상태 |
| RULE-03 | POST /api/v1/rulesets | admin, parent_id·version_label | 201 복제 draft |
| RULE-04 | PUT /api/v1/rulesets/{id} | admin, draft만, rules·policy 전체 | 200 draft, checksum 아직 없음 |
| RULE-05 | POST /api/v1/rulesets/{id}/validate | admin, body {} | 200 validated 또는 422 validation_failed·고정 failure codes |
| RULE-06 | POST /api/v1/rulesets/{id}/publish | admin, password 재인증·expected_active_id | 200 active·checksum, 실패 시 기존 active 유지 |
| RULE-07 | POST /api/v1/rulesets/{id}/rollback | admin, retired 대상·password·expected_active_id | 200 이전 검증 버전 active |
| HEALTH-01 | GET /api/v1/health/live | 공개, 상세 데이터 없음 | 200 alive |
| HEALTH-02 | GET /api/v1/health/ready | 내부 모니터·operator/admin | 200 ready 또는 503, 구성요소별 정상 여부 |
| LAB-01 | POST /api/v1/lab/ab-runs | lab admin, ops 채널, APP_ENV=lab만 등록, dataset_id·categories | 202 run_id |
| LAB-02 | GET /api/v1/lab/ab-runs/{id} | lab admin | 진행률·사례별 OFF/ON status·노출 여부·막은 계층·rule_ids |
| LAB-03 | GET /api/v1/lab/ab-runs/{id}/report | lab admin, format=pdf | application/pdf, no-store |

PUT ruleset은 rule_id·stage·category·kind·pattern·flags·action·marker·priority와 policy allowlist만 허용한다. DB에 없는 필드, 길이 제한 완화, 강제 가드레일 해제를 거부한다. 게시 재인증 비밀번호는 모델·DB payload·로그에 저장하지 않는다. 변경 충돌은 409 RULESET_CONFLICT, compile·검증 실패는 422 RULESET_VALIDATION_FAILED다. 게시·롤백도 outbox와 함께 transaction으로 기록한다.

관제 목록에는 원문·token_hash·password_hash를 반환하지 않는다. category_counts는 이벤트 수가 아니라 rule_hits 수의 합계임을 명시한다. stats는 비동기 적재된 audit.events 기준이며 `ingestion_lag_seconds`와 `as_of`를 함께 제공한다. PDF는 동일 필터·시간대·지연·룰 버전을 표시하고 사용자 본문을 포함하지 않는다. 이벤트가 10,000건 초과하면 422 REPORT_TOO_LARGE로 범위 축소를 안내한다.

## 3. Native Chat 계약

### 3.1 요청

```json
{
  "session_id": "30000000-0000-4000-8000-000000000001",
  "prompt": "무선 마우스를 찾아줘",
  "model": "qwen3:8b",
  "stream": false
}
```

session_id와 prompt는 필수다. prompt는 비어 있지 않은 문자열·최대 8,000 code points, model 기본값은 qwen3:8b, stream 기본값은 false다. body 미정의 필드는 거부한다. 모델명 접미사 raw/bypass를 alias로 등록하지 않는다. `[off]`는 일반 비신뢰 텍스트이며 검사 면제 지시가 아니다.

서버는 본인 세션의 정제된 히스토리와 최신 prompt를 검사한다. 최대 40개·합계 32,000자를 초과하면 가장 오래된 완료 turn 쌍부터 제거하고 새 prompt 자체는 절단하지 않는다. prompt만 초과하면 422다. 검사에는 제거 전 저장된 risk_signals도 활용한다. 운영 system prompt와 Tool 최소 결과도 별도 내부 컨텍스트 예산 안에서 제한하며 사용자 길이 제한을 우회하는 경로로 사용하지 않는다.

### 3.2 응답

```json
{
  "request_id": "10000000-0000-4000-8000-000000000001",
  "session_id": "30000000-0000-4000-8000-000000000001",
  "status": "confirmation_required",
  "content": "장바구니 변경 내용을 확인해 주세요.",
  "guardrail": {
    "active": true,
    "ruleset_version": "40000000-0000-4000-8000-000000000001",
    "stage": null,
    "rule_ids": []
  },
  "action": {
    "action_id": "50000000-0000-4000-8000-000000000001",
    "expires_at": "2026-10-02T03:05:00Z",
    "confirmation_url": "https://shop.example.internal/actions/50000000-0000-4000-8000-000000000001"
  },
  "error": null,
  "timing": {"input_ms": 1.0, "output_ms": 1.2, "total_ms": 2400.0}
}
```

예제 시간·측정값은 wire 형식 설명용 합성 값이다. action은 승인 대기에만 존재하며 나머지는 null이다. error는 blocked에서 `GUARDRAIL_BLOCKED`의 고정 메시지, 일반 오류에서는 해당 code/message, 성공·마스킹·승인 대기에서는 null이다. customer에는 rule_ids를 빈 배열로 제공하고, operator/admin에게만 실제 룰 목록을 보여 준다.

| status | HTTP | content·우선순위 |
|---|---|---|
| success | 200 | 정제된 정상 답변 |
| masked | 200 | PII·기밀·HTML·이미지 정화가 적용된 답변 |
| confirmation_required | 200 | 서버 확인 안내 + action, 비치명적 마스킹은 rule_hits에 별도 기록 |
| blocked | 403 | 단계별 고정 거절문, action=null |
| error | 오류 표의 HTTP | 일반 공통 error envelope, ChatResponse를 성공처럼 반환하지 않음 |

판정 우선순위는 기반 장애 error → 보안 blocked → 승인 대기 confirmation_required → 정화 masked → success다. pending 생성 후 출력 blocked가 결정되면 action을 cancelled 처리하고 같은 transaction에 blocked outbox를 저장한다.

### 3.3 Native SSE

입력·출력·감사 영속화가 모두 끝나기 전에는 HTTP SSE headers를 열지 않는다. 따라서 입력 차단은 JSON 403, 장애는 일반 JSON 오류로 반환할 수 있다. stream=true 정상 응답은 `Content-Type: text/event-stream`, `Cache-Control: no-store`, `X-Accel-Buffering: no`다. raw 모델 토큰의 실시간 전송이 아니라 **검사 완료된 답변의 분할 전송**이다.

```text
event: meta
data: {"request_id":"10000000-0000-4000-8000-000000000001","status":"success","session_id":"30000000-0000-4000-8000-000000000001"}

event: delta
data: {"content":"상품 정보를 안내합니다."}

event: done
data: {"status":"success","action":null,"guardrail":{"active":true,"ruleset_version":"40000000-0000-4000-8000-000000000001","stage":null,"rule_ids":[]},"timing":{"input_ms":1.0,"output_ms":1.0,"total_ms":2000.0}}

```

delta는 이미 정제된 문자열을 Unicode 경계에서 최대 256자로 분할한다. arbitrary model metadata·thinking·tool_calls·원시 인자를 보내지 않는다. 클라이언트는 done 전 끊긴 답변을 완료로 표시하지 않고 같은 요청을 자동 재전송하지 않는다.

## 4. AnythingLLM·OpenAI 호환 subset

Generic OpenAI 설정의 Base URL은 `https://shop.example.internal/v1`, API Key는 사용자 client token, model은 `qwen3:8b`다. 설치 버전에서 Base URL suffix 중복 여부·SSE 파싱·모델 목록 호출을 실제로 확인한다. 모델 서버 직접 연결을 허용하지 않는다. [AnythingLLM 설정 공식 문서](https://docs.anythingllm.com/setup/llm-configuration/overview)

### 4.1 지원 요청과 세션

```json
{
  "model": "qwen3:8b",
  "messages": [{"role": "user", "content": "내 주문 배송 상태를 알려줘"}],
  "stream": true,
  "temperature": 0.2,
  "max_tokens": 512
}
```

model·messages는 필수다. role은 system/user/assistant, content는 text 문자열만 지원한다. 사용자 메시지마다 8,000자, 모든 전달 메시지의 합계 32,000자, 최대 40개, 마지막 메시지는 user여야 한다. 초과 히스토리를 클라이언트 몰래 절단하지 않고 422로 반환한다. system/assistant 포함 전 메시지를 비신뢰 입력으로 검사하며 서버 system prompt와 구조적으로 분리한다. role=tool/developer, 멀티모달, 임의 tools/tool_choice, n≠1은 지원하지 않는다.

temperature는 0~1, max_tokens는 1~512로 제한한다. optional `n=1`, `user`(≤128자, 권한 판정에 사용하지 않음), `stream_options={"include_usage":false}`를 허용하며 다른 옵션은 400으로 거부한다. guardrail 해제·사용자 ID 대입 필드는 허용하지 않는다. 모든 메타데이터가 가드레일을 통과하는 입력과 같다고 가정하지 않는다.

선택 `X-Session-Id`가 있으면 본인 세션인지 검증하고 없으면 새 세션을 생성해 response `X-Session-Id`로 반환한다. AnythingLLM이 이 헤더를 재사용하지 않아도 전달한 messages 전체의 문맥 검사는 수행한다. 대화 간 누적 risk_signals는 동일 세션 ID가 있을 때만 보장한다. body.user를 세션·계정 ID로 사용하지 않는다.

### 4.2 JSON·SSE

```json
{
  "id": "chatcmpl-10000000-0000-4000-8000-000000000001",
  "object": "chat.completion",
  "created": 1790906400,
  "model": "qwen3:8b",
  "choices": [{"index": 0, "message": {"role": "assistant", "content": "상품 정보를 안내합니다."}, "finish_reason": "stop"}],
  "usage": {"prompt_tokens": 120, "completion_tokens": 40, "total_tokens": 160}
}
```

usage는 완료된 Ollama 호출들의 실제 token count 누계다. 검사된 답변의 글자 수를 토큰 수로 추정해 기입하지 않는다. 입력 조기 차단에서는 모두 0이다. ruleset·status는 `X-Guardrail-Status`, `X-Ruleset-Version` 헤더로 제공하며 JSON에 비호환 필드를 강제 추가하지 않는다.

```text
data: {"id":"chatcmpl-10000000-0000-4000-8000-000000000001","object":"chat.completion.chunk","created":1790906400,"model":"qwen3:8b","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}

data: {"id":"chatcmpl-10000000-0000-4000-8000-000000000001","object":"chat.completion.chunk","created":1790906400,"model":"qwen3:8b","choices":[{"index":0,"delta":{"content":"상품 정보를 안내합니다."},"finish_reason":null}]}

data: {"id":"chatcmpl-10000000-0000-4000-8000-000000000001","object":"chat.completion.chunk","created":1790906400,"model":"qwen3:8b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]

```

차단도 JSON/SSE의 assistant.content에 `🛡️ 요청을 보안 정책에 따라 처리할 수 없습니다.`를 넣어 HTTP 200으로 반환한다. 감사 status와 X-Guardrail-Status는 blocked다. 승인 대기 content에는 서버 확인 안내와 안전한 확인 URL을 넣는다. tool_calls를 클라이언트 실행용으로 노출하지 않는다. 입력·출력 치명적 차단과 일반 오류를 구분하여, 인증·제한·모델·감사 장애는 표준 HTTP 오류로 반환한다.

호환 경로의 일반 오류는 `{"error":{"message":"고정 오류 문구","type":"invalid_request_error 또는 server_error","param":null,"code":"고정 코드"}}`다. 내부 오류 메시지는 제외한다. 모델 완료 후 전체 검사·outbox commit까지 마친 뒤 SSE를 시작하므로 raw 응답을 뒤늦게 회수하는 방식에 의존하지 않는다.

## 5. Ollama·Tool 내부 연동

환경변수 `OLLAMA_BASE_URL=http://10.10.70.65:11434`, `OLLAMA_MODEL=qwen3:8b`, 모델 digest를 배포 시 고정하고 readiness에서 `/api/tags`의 digest와 대조한다. 내부 HTTP `POST /api/chat`에 서버 system prompt, 검사를 통과한 text messages, 서버에서 선택한 function schemas, `stream:false`, `think:false`, `keep_alive:"30m"`, `options.num_predict≤512`, `options.num_ctx=8192`를 보낸다. 호출당 120초, 연결 3초, 전체 챗 요청 240초 deadline을 적용한다. 응답에 `message.thinking`이 있으면 사용·저장·전달하지 않는다. raw response는 메모리에서만 보관한다. [Ollama API](https://docs.ollama.com/api/chat)

모델의 `message.tool_calls[].function.name/arguments`는 요청 제안이다. strict Tool schema와 소유권 검증을 통과한 읽기 결과를 `role=tool`, `tool_name`, 최소 JSON content로 추가한 뒤 모델을 다시 호출한다. 클라이언트가 보낸 role=tool과 이 서버 생성 메시지를 혼합하지 않는다. [Ollama Tool Calling](https://docs.ollama.com/capabilities/tool-calling)

요청당 Tool round 최대 3·총 6개, 읽기 Tool 결과 합계 최대 8,000자다. 모델에 보내는 전체 컨텍스트(system prompt·Tool schema·history·Tool 결과)는 Ollama의 실제 `prompt_eval_count` 기준 num_ctx의 75%(6,144 tokens) 이하로 유지한다. 초과가 예상되면 가장 오래된 완료 turn부터 제거하고 system prompt는 절대 잘리지 않게 한다. 2026-10-02 실측(qwen3:8b, CPU)에서 생성은 약 7.2 tokens/s이므로, Tool round가 있는 요청은 수십 초~2분이 걸릴 수 있다. 변경 Tool은 최대 1개의 pending 제안만 생성하며 바로 confirmation_required로 완료한다. 추가 변경 제안·무한 Tool loop·잘못된 JSON은 실행하지 않고 안전한 오류·차단으로 기록한다. 상품 설명·도구 결과도 간접 인젝션 검사 후 모델에 전달한다.

모델에 없는 기능을 일반 텍스트의 JSON처럼 보이는 문자열에서 추측하여 실행하지 않는다. 배포 후보가 공식 tool_calls 형태를 안정적으로 반환하는지 시험한다. 호환 실패 시 배포 준비 상태를 실패로 표시한다.

## 6. 전송·재시도·배포 수용 조건

고객 API Origin allowlist는 쇼핑 도메인으로 한정한다. 관리 Origin은 관리 도메인만 사용한다. CORS wildcard + credentials 조합을 사용하지 않는다. SSE proxy read timeout은 270초로 두어 240초 처리 deadline 이후에도 헤더·최종 응답을 전달할 여유를 둔다. 외부로 노출되는 응답은 no-store, 민감 query·Authorization·cookie는 Nginx와 앱 로그에서 제거한다.

GET은 제한된 재시도가 가능하다. confirm은 같은 action_id·Idempotency-Key로만 재시도하며 모델·제안 API를 장애 시 자동 재실행하지 않는다. 불명확한 응답은 ACTION-02로 상태를 먼저 확인한다. UI·AnythingLLM·PDF·Streamlit에서 잘못된 권한과 장애가 실제 계약대로 표시되는지 [DES-007](07_verification_operations_plan.md)의 수용 시험으로 확인한다.
