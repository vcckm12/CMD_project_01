# AI 보안 가드레일 챗봇 설계 문서

| 항목 | 기준 |
|---|---|
| 문서 번호 / 버전 | DES-000 / 1.1 |
| 작성일 / 개정일 | 2026-10-02 / 2026-10-02 (1.1: D-14~D-24, 1.2: D-25~D-28 반영), Asia/Seoul |
| 상태 | 구현 전 제안 설계 — 소스·실행 환경·성능을 확인한 구현 명세가 아님 |
| 대상 독자 | 백엔드·프론트엔드 개발자, 보안 담당자, DB·운영 담당자 |
| 시스템 | ai-guardrail-chatbot |

## 1. 설계 목적과 범위

고객의 쇼핑 질의를 안전하게 처리하고, 허용된 상품·주문 정보를 조회하며, 고객 확인을 받은 장바구니·쿠폰 변경만 실행하는 시스템을 설계한다. Nginx, FastAPI, Ollama, PostgreSQL, 쇼핑 웹, AnythingLLM Desktop, Streamlit 관제를 사용한다. 운영 환경에서는 입력·실행·출력 가드레일을 항상 적용한다.

현재 작업 폴더에는 참조 자료만 있다. 이 문서의 파일 경로, 함수, 데이터 타입, API, 정규식, SQL은 앞으로 구현할 **제안 인터페이스**다. 제공된 초안의 함수명을 구현된 함수로 해석하지 않는다. 문서 작성은 서비스 코드·배포·DB 변경을 포함하지 않는다.

주문 생성·취소, 실제 결제, 서버 측 벡터 검색, 딥러닝 분류 가드레일은 이번 구현 범위에 포함하지 않는다. 기존 주문 이력은 사전에 적재된 데이터 또는 검증된 배치 연동을 통해 조회한다. 주문 이력 적재는 고객·AI 도구의 권한으로 실행하지 않는다.

## 2. 문서 목차

| 문서 | 필수 여부 | 내용과 기준 정보 |
|---|---|---|
| [DES-001 시스템 구성도](01_system_architecture.md) | 필수 | 논리·배포 구성, 신뢰 경계, 구성요소·통신·장애 책임 |
| [DES-002 DB 설계서](02_database_design.md) | 필수 | ERD, 컬럼·제약·인덱스, 초기 DDL, 권한·트랜잭션·보존 |
| [DES-003 User Flow](03_user_flow.md) | 필수 | 6단계 E2E 처리, Mermaid Flowchart·Sequence, 모듈·룰 매핑 |
| [DES-004 화면설계서](04_screen_design.md) | 필수 | 고객·관제 화면, 와이어프레임, 상태·검증·이벤트·API |
| [DES-005 API·연동 명세서](05_api_integration_spec.md) | 추가 필수 | 인증, JSON·SSE 계약, 쇼핑·승인·관제 API, 외부 제품 연동 |
| [DES-006 가드레일·권한 상세 설계](06_guardrail_security_design.md) | 추가 필수 | 전처리·탐지·정화 룰, 도구 목록·권한, 정책 버전·감사 |
| [DES-007 검증·운영 계획서](07_verification_operations_plan.md) | 추가 필수 | 수용 기준·시험 시나리오, 배포·관측·백업·복구 |

추가 3종은 필요하다. API 계약 없이 클라이언트별 차단 응답을 통일하기 어렵고, 보안 상세 설계 없이 모델 제안과 실제 데이터 변경의 권한 경계를 구현하기 어렵다. 검증·운영 계획은 방어율·지연시간의 목표를 실제 결과와 구분하고 장애 시 안전한 동작을 확인하기 위한 문서다.

## 3. 참조 자료와 적용 우선순위

| 자료 | 활용 | 취급 |
|---|---|---|
| [참조 시스템 구성도](../reference/CMD_프로젝트.png) | PostgreSQL, Shopping Web, Tool Calling, Threat Intelligence, 감사 흐름 | 전체 구조의 출발점 |
| [PLN-002 요구사항·MVP](<../reference/시스템 요구사항 및 MVP 범위 명세서 (가드레일 버전).html>) | REQ-F01~04, REQ-N01~03 | 운영용 결정으로 변경된 항목은 아래 표에 명시 |
| [PLN-003 가드레일 정책](<../reference/AI 보안 가드레일 정책 명세서.html>) | 입력·출력·인프라 방어 의도 | OWASP 번호와 처리 방식은 재정의 |
| [위협 모델링 분석서](../reference/AI_보안_가드레일_위협모델링_및_공격기법_분석서.html) | 우회·다중 턴·출력 유출·ReDoS·권한 위협 | 시험 범주에 반영, 기존 성능 주장 미검증 |
| [Prompt Injection 참고](<../reference/PayloadsAllTheThings-master/Prompt Injection/README.md>) | 공격 분류·시험 데이터 후보 | 실행하지 않고 합성 시험 사례 설계에 활용 |
| [ReDoS 참고](<../reference/PayloadsAllTheThings-master/Regular Expression/README.md>) | 정규식 자원 소모 위험 | 안전성 시험·검사 예산에 반영 |
| [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/) | 보안 위험 분류 | 번호·영문 명칭의 기준, 2026-10-02 확인 |
| [Ollama Chat API](https://docs.ollama.com/api/chat), [Tool Calling](https://docs.ollama.com/capabilities/tool-calling) | 모델·메시지·도구 결과 연동 | 실제 모델·버전 호환 시험 필요 |
| [AnythingLLM LLM 설정](https://docs.anythingllm.com/setup/llm-configuration/overview) | Generic OpenAI 클라이언트 연동 | 설치 버전을 고정해 수용 시험 |

확정된 운영 설계 결정 → 해당 분야의 상세 문서 → 기존 참조 자료 순으로 적용한다. API wire 형식은 DES-005, DB 컬럼은 DES-002, 룰 정의는 DES-006을 기준으로 한다. 서로 다른 영역의 계약 변경은 연결된 문서와 시험도 함께 변경한다.

## 4. 확정된 설계 결정과 기존 자료의 차이

| 결정 ID | 이번 설계 | 기존 자료와의 차이 |
|---|---|---|
| D-01 | PostgreSQL 17 기준, 단일 인스턴스·DB, commerce/threat_intel/audit 3개 스키마 | SQLite security_audit.db 초안 대체 |
| D-02 | 고객 customer, 관제 operator, 관리자 admin / 자체 계정·JWT | MVP에서 제외했던 역할 권한을 운영 필수로 추가 |
| D-03 | 서버에서 가드레일 ON 강제 | REQ-F03의 ON/OFF 비교는 운영에서 제외하고 D-21의 분리된 lab 환경에서만 수행 |
| D-04 | 전체 응답 검사 후 JSON 또는 SSE 전달 | 생성 토큰 즉시 전달·사후 스트림 중단 방식 대체 |
| D-05 | 조회 + 사용자 확인을 받은 장바구니·쿠폰 변경 | SLM 자체는 DB·셸 실행 권한 없음, 승인된 서비스만 변경 |
| D-06 | 사용자 메시지 8,000자 / 요청 메시지 합계 32,000자 | 참조 자료의 1,000·2,000자와 초안의 8,000자 충돌 해소 |
| D-07 | 입력 검사 P95 ≤10ms, 전체 가드레일 추가 지연 P95 ≤30ms 목표 | 0.03·0.13·0.08·0.2ms와 100% 방어는 결과로 인용하지 않음 |
| D-08 | 영속 outbox 후 비동기 감사 적재 | 메모리 큐만으로 응답 후 기록하는 방식 방지 |
| D-09 | 마스킹된 감사 요약, 원문·토큰·비밀번호 저장 금지 / 감사 90일 | 원문 대화 덤프·무기한 보존 방지 |
| D-10 | OWASP 2025 번호 명시 | 2023-24와 2025 항목 혼용 해소 |
| D-11 | ~~Qwen2.5-7B~~ → D-14로 대체 | 10.10.70.65 실재·접속은 2026-10-02 확인 |
| D-12 | 서버 벡터 RAG·소형 분류 모델은 확장 | 클라이언트가 첨부한 RAG 컨텍스트도 비신뢰 입력으로 검사 |
| D-13 | 실제 비밀번호·PII를 시스템 프롬프트에 넣지 않음 | 사내 DB 전체·실제 관리자 키를 컨텍스트에 넣는 초안 수정 |
| D-14 | 모델 `qwen3:8b`(Q4_K_M, digest `500a1f067a9f…`), 원격 Ollama `http://10.10.70.65:11434`, 모든 호출 `think:false` | Qwen2.5-7B·동일 호스트 Ollama 컨테이너 대체, thinking 출력·지연 금지 |
| D-15 | CPU 추론 실측(생성 약 7.2 tokens/s, prompt 약 80 tokens/s) 기준: num_predict 512·num_ctx 8192·호출당 120초·요청 240초·Nginx 270초·서버 추론 동시 1건·keep_alive 30분 | 60/120/150초·1024 tokens·동시 2건은 이 장비에서 timeout 발생 |
| D-16 | 입력·출력 검사 hard budget 각 50ms, P95 목표(입력 10ms·전체 30ms)는 유지 | 목표값과 강제 timeout이 같아 정상 요청 503이 발생하는 충돌 해소 |
| D-17 | Streamlit 서버는 내부망에서 FastAPI에 직접 호출하고 `X-Edge-Channel: ops`를 설정, shop Nginx는 이 헤더를 `shop`으로 덮어씀. operator/admin은 ops 채널, customer·client token은 shop 채널에서만 허용 | 논리도(Streamlit→Nginx)와 배포도(직접 호출)의 불일치 해소, 브라우저→관리 API 직접 경로 제거 |
| D-18 | 스케줄러 컨테이너 + `maintenance_worker` DB 역할(승인·쿠폰 만료, 만료 outbox) / `retention_worker`는 삭제만 | 만료 batch의 outbox INSERT·user_coupons UPDATE 권한 누락 해소 |
| D-19 | 인증 성공 이전의 4xx·Nginx 거절은 감사 outbox 대신 access log·메트릭에만 기록 | 비인증 요청이 DB 쓰기를 유발하고 DB 장애 시 401이 503으로 바뀌는 문제 방지 |
| D-20 | 메트릭 수집 스택(Prometheus 등)은 1단계 범위 밖, 지표 이름·임계값만 유지 | 수집·노출 방식 미정 상태를 명시 |
| D-21 | ON/OFF 비교는 별도 compose project `lab`(독립 DB·합성 데이터·미끼 비밀)에서만 허용, 운영 빌드는 OFF 설정 시 readiness 실패 | 운영 OFF 금지와 "OFF면 공격 성공 / ON이면 차단·마스킹" 검증 요구를 함께 충족 |
| D-22 | .65 Ollama 11434는 Windows 방화벽으로 10.10.70.0/24만 허용, 인터넷 공개 금지, 공용 사용에 따른 지연·모델 교체를 readiness·지연 메트릭으로 관측 | 다른 사용자도 쓰는 공유 모델 서버라 .149 단독 허용 불가 |
| D-23 | 1단계 내부망(사설 CA TLS·hosts) → 2단계 외부 공개(공인 도메인·인증서, Nginx 443만 공개, ops·Ollama·DB 비공개) | 외부 공개 시점의 경계 확정 |
| D-25 | 정규식 규칙 뒤에 qwen3:8b LLM 판별 단계를 입력·Tool 결과·출력 세 곳에 둔다. 판정은 OR(규칙 또는 판별이 막으면 차단), 판별 실패는 1회 재시도 후 503 | D-12의 "분류 모델은 확장"을 앞당김. 규칙만으로 held-out 탐지율 33.3%였기 때문 |
| D-26 | 판별 반복 실패는 관제 화면 경보(audit.alerts)로 알린다. 모델 장애(5분 내 3회)와 같은 입력 반복 실패(2회)를 구분하고, 원문 대신 keyed 지문만 저장한다. 외부 알림은 고도화 단계 | 관리자는 시스템을 조치하며 막힌 답변을 승인하지 않음 |
| D-27 | 챗 구현 세부: 읽기 Tool `list_orders`(본인 최근 주문, 인자 없음) 추가, 모델 입력은 글자수÷1.2 토큰 추정으로 6,656 token 이내(넘으면 오래된 대화부터 제거, 질문만으로 넘으면 422 PROMPT_TOO_LONG), Ollama가 보고한 prompt token이 문맥 한도에 닿으면 답변 폐기(502), native temperature 0.2, 사용자별 요청 예산 거절(429·409)은 감사 outbox 대신 로그만 | 주문 번호 없는 배송 질문 처리, system prompt 잘림 방지, 수치 왜곡 감소 |
| D-28 | 검사 예산 보정: 단계 예산은 검사 스레드의 CPU 시간으로 세고(GIL 대기 제외), 8,000자당 50ms로 길이에 비례, 정규식 호출당 wall-clock 20ms를 ReDoS 안전망으로 둔다. 챗에서 제안된 변경은 최종 transaction에서만 pending으로 저장하므로 출력이 차단되면 저장되지 않는다(취소 행 없음). 시험은 별도 compose project(`ag_test`)의 일회용 DB에서 실행 | wall-clock 2ms 호출 제한이 스레드 전환(5ms) 때문에 정상 긴 입력을 간헐적으로 503 처리하던 문제, 32,000자 영문 이력 CPU 57ms 측정 |
| D-29 | 클라이언트가 보낸 system·참고자료(RAG) 텍스트는 고객 메시지와 다른 판별 기준(context)으로 판정한다. 일반적인 어시스턴트 지시는 SAFE, 프롬프트·자격 증명·타인 정보·내부 영업정보 요구, 권한 상승, 규칙 무력화, 코드 실행 같은 공격 목적만 ATTACK. 차단 시 rule_id는 RULE_LLM_JUDGE_INPUT 그대로 | AnythingLLM은 system 프롬프트를 비워도 기본 지시문을 보내며, 고객 메시지 기준으로는 "안녕"까지 오차단(2026-10-06 운영 감사 4건) |
| D-30 | 관제 감사 상세의 룰 적중에 규칙별 한국어 설명을 붙인다(원문 없음). LAB(APP_ENV=lab)에 한해 차단된 채팅 요청의 검사 대상 메시지를 API 메모리에 보관(최대 500건, 재시작 시 삭제)하고 관리자에게 보여 준다. 운영은 원문 미저장(D-26 등) 그대로 | 시연·검증 때 무엇이 막혔는지 확인 필요. LAB은 합성 데이터만 사용(D-21). 운영 원문 보관(마스킹 요약)은 필요해지면 별도 결정 |
| D-31 | 상품·주문·쿠폰·장바구니 id는 도구 호출에만 쓰는 내부 값이며 고객 답변에는 이름으로 안내한다(시스템 프롬프트 지시, 출력 마스킹은 하지 않음) | id는 비밀이 아니고 접근 통제는 서버 소유권 검사가 담당. 답변 품질·내부 구조 노출 최소화 목적 |
| D-32 | 관제 대시보드 이벤트 목록은 최신 50건을 10초마다 갱신하고(더 보기 중에는 정지, 새로고침 버튼), 세션 ID 칸을 표시한다. lab_up.sh는 합성 카탈로그를 seed한다 | 목록이 첫 조회 결과에 고정되어 새 차단 건이 안 보이던 문제, event_id와 세션 ID 혼동, lab 상품 없음 |
| D-24 | 공개 GitHub 저장소 `vcckm12/CMD_project_01`의 `v2` 브랜치에서 신규 구성, 기존 MVP의 datasets·화면 디자인만 선별 이전. `.env`·키·인증서·`reference/PayloadsAllTheThings-master`는 커밋 금지 | 기존 MVP(무인증·원문 감사·mock fallback 답변)는 이 설계와 호환되지 않음 |

## 5. 공통 식별자·상태·기본값

`request_id`는 서버가 생성한 요청 UUID, `session_id`는 사용자 소유 대화 세션 UUID, `event_id`는 감사 이벤트 UUID, `action_id`는 변경 승인 UUID, `ruleset_version`은 검사에 고정한 게시 룰셋 UUID다. UUID 예제는 합성 값이며 비밀 토큰으로 사용하지 않는다.

| 공통 값 | 정의 |
|---|---|
| 응답·감사 status | success / blocked / masked / confirmation_required / error |
| 차단 stage | input / execution / output / policy, 정상·일반 오류는 null |
| 변경 승인 state | pending / executed / cancelled / expired / failed |
| API 시간 | UTC ISO 8601, DB timestamptz, 화면에서 Asia/Seoul로 변환 |
| 금액 | KRW 정수, 소수점·부동소수점 금지 |
| 글자 수 | Unicode code point 수, UTF-8 byte 길이·토큰 수와 별도 제한 |

| 설정명 | 초기 기본값 | 책임 문서 |
|---|---|---|
| JUDGE_ENABLED / JUDGE_TIMEOUT | production은 true 고정 / 호출당 45초(2026-10-06 20초에서 상향, CPU 추론에서 긴 Tool 결과 판별이 20초 초과), 1회 재시도 | DES-006 |
| INPUT_FINGERPRINT_KEY | 경보용 입력 지문 HMAC 키, production 필수(32자 이상) | DES-006 |
| GUARDRAIL_ENFORCED | production은 true 고정(그 외 값이면 readiness 실패), lab만 요청별 비교 허용 | DES-006 |
| MAX_USER_CHARS / MAX_REQUEST_CHARS | 8000 / 32000 | DES-005·006 |
| MAX_BODY_BYTES / MAX_MESSAGES | 262144 / 40 | DES-005 |
| MAX_OUTPUT_CHARS / MAX_OUTPUT_TOKENS | 16000 / 512 | DES-006 |
| MAX_DECODE_DEPTH / MAX_VARIANTS | 2 / 16 | DES-006 |
| ACCESS_TOKEN_TTL / REFRESH_TOKEN_TTL | 15분 / 7일 | DES-005 |
| CLIENT_TOKEN_TTL / ACTION_TTL | 30일 / 5분 | DES-005 |
| OLLAMA_BASE_URL / OLLAMA_MODEL | http://10.10.70.65:11434 / qwen3:8b | DES-001·005 |
| OLLAMA_MODEL_DIGEST / OLLAMA_THINK | 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41 / false | DES-005 |
| OLLAMA_NUM_CTX / OLLAMA_KEEP_ALIVE | 8192 / 30m | DES-005 |
| OLLAMA_TIMEOUT / CHAT_DEADLINE | 호출당 120초 / 요청 전체 240초 | DES-005 |
| INFERENCE_CONCURRENCY | 서버 전체 1, 사용자별 1 | DES-001 |
| INPUT_GUARD_BUDGET_MS / OUTPUT_GUARD_BUDGET_MS | 50 / 50 | DES-006 |
| APP_ENV | production / lab, lab에서만 GUARDRAIL_ENFORCED=false 허용 | DES-001·006 |
| MAX_TOOL_ROUNDS / MAX_TOOL_CALLS | 3 / 요청 전체 6 | DES-006 |
| AUDIT_RETENTION_DAYS / SESSION_RETENTION_DAYS | 90 / 30 | DES-002·007 |

정책의 실행 제한은 서버 환경설정과 게시 룰셋 중 더 엄격한 값을 적용한다. 입력·출력 검사 자체를 비활성화하는 정책은 게시할 수 없다. 입력 텍스트·모델명·client-supplied metadata로 설정을 덮어쓸 수 없다.

## 6. 요구사항 추적표

| 요구사항 | 운영용 해석 | 설계 | 검증 ID |
|---|---|---|---|
| REQ-F01 | 입력·난독화·문맥 검사와 추론 전 차단 | DES-003·006 | T-01~05 |
| REQ-F02 | 출력 전체 검사, 마스킹, HTML·외부 이미지 무효화 | DES-003·006 | T-06~09 |
| REQ-F03 | 운영 ON 고정, ON/OFF 비교는 lab 환경의 A/B 시험으로 수행 | DES-001·004·006·007 | T-10·T-26 |
| REQ-F04 | 권한 있는 관제에서 룰·OWASP·통계·PDF 확인 | DES-004·005 | T-20~21 |
| REQ-F05 | 자체 인증, 역할·객체 소유권, 제한 클라이언트 토큰 | DES-002·005·006 | T-11~13·T-27 |
| REQ-F06 | Tool allowlist·인자 검증·변경 승인·중복 실행 방지 | DES-002·003·006 | T-14~17 |
| REQ-F07 | 상품·주문 조회, 장바구니·쿠폰 변경 | DES-002·004·005 | T-14~17 |
| REQ-F08 | 룰 버전 게시·원자적 캐시 교체·마지막 정상 버전 | DES-002·006 | T-18 |
| REQ-F09 | outbox·중복 제거·감사 장애 시 응답 제한 | DES-002·007 | T-19·22 |
| REQ-N01 | 검사 지연 P95 목표, 생성 속도와 최초 응답 대기 별도 측정 | DES-001·005·007 | T-23·T-28 |
| REQ-N02 | 고정 독립 시험셋 탐지율 ≥95%, FPR ≤5% | DES-006·007 | T-24 |
| REQ-N03 | 모델 추론·데이터 처리 내부망, 클라우드 추론·자동 재학습 없음 | DES-001·007 | T-25 |

온프레미스 운영의 장비·전력·유지 비용은 존재한다. 기존의 비용 0원 표현은 외부 모델 API 이용료가 없다는 범위로만 해석한다.

## 7. 문서 활용과 수용 기준

시스템 구성 → DB·API → 사용자 흐름·화면 → 보안 상세 → 검증·운영 순서로 읽는다. 구현은 DB → 인증 → 입력·출력 가드레일 엔진 → 챗 파이프라인 → Tool·승인 → 감사 worker·스케줄러 → 고객 웹 → Streamlit 관제 → lab ON/OFF 비교 순서로 진행한다. 개발 착수 전에는 문서 버전과 모델·제품 버전을 함께 고정한다. 화면의 모든 변경 동작은 승인 API에, 모든 룰 ID는 게시 룰셋·감사·검증에 연결되어야 한다.

설계 검증 결과와 남은 실제 서비스 시험은 [DES-007의 문서 검증 기록](07_verification_operations_plan.md#8-문서-검증-기록)에 구분해 기록한다. 문서·DDL의 검증 성공은 서비스 구현·보안 목표 달성을 뜻하지 않는다.
