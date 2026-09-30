# 프로젝트 범위 정의서 (PROJECT_SCOPE.md)

## 1. 프로젝트 개요 (Project Overview)
- **프로젝트 명칭**: AI Security Guardrail Chatbot (AI 보안 가드레일 챗봇 시스템)
- **목적**: 생성형 AI(Generative AI) 및 소형 언어 모델(SLM: Small Language Model) 도입 시 발생하는 OWASP Top 10 for LLM 보안 위협(프롬프트 인젝션, 시스템 탈취, 권한 상승, PII 유출, 리버스 쉘 페이로드 등)을 방어하고, E-커머스 환경에서 안전하게 Tool Calling 및 데이터 조회를 수행하는 다계층 보안 가드레일 아키텍처 구축.
- **핵심 가치**:
  1. **Defense-in-Depth (심층 방어)**: Input -> Execution -> Output에 이르는 전방위 보안 파이프라인.
  2. **Zero-Trust Security**: AI 모델의 응답과 도구 호출 파라미터를 신뢰하지 않고 상시 검증.
  3. **High-Performance & Low-Latency**: 실시간 In-Memory Rule Cache 및 비동기 감사 로깅(Async Audit Logging)을 통한 초저지연 보안 검사.
  4. **Dynamic Extensibility**: RDBMS(PostgreSQL) 기반의 위협 인텔리전스 룰셋 관리 및 Hot-Reload 지원.

---

## 2. 주요 이해관계자 및 페르소나 (Target Personas)
1. **일반 고객 (End User)**: 쇼핑몰 웹 UI(`mock_store`) 및 AnythingLLM 챗봇을 통해 상품 조회, 배송 조회, 반품 문의 등을 진행하는 사용자.
2. **보안 관제자 / 시스템 관리자 (Security Administrator)**: Streamlit Admin 대시보드를 통해 실시간 보안 위협 로그를 관제하고, 동적 가드레일 룰셋(정규식, 키워드, 차단 정책)을 런타임에 튜닝하는 운영자.
3. **개발자 / DevOps 엔지니어 (Engineers)**: Clean Architecture 및 CI/CD 파이프라인을 기반으로 안전한 비즈니스 로직 및 확장 툴(Tool Calling)을 개발하는 엔지니어.

---

## 3. 핵심 시스템 범위 (System Scope)

### 3.1 포함 범위 (In-Scope)
- **Client & Presentation Layer**:
  - `mock_store`: 순수 HTML5/CSS3/JavaScript 기반의 반응형 가상 이커머스 웹 애플리케이션 및 플로팅 AI 챗봇 위젯.
  - `admin_ui`: Streamlit 기반 보안 관제 대시보드 (실시간 공격 로그 모니터링, 동적 룰셋 CRUD 및 Hot-Reload 토글).
  - AnythingLLM / 외부 AI 클라이언트 연동용 OpenAI 표준 규격 엔드포인트 (`/v1/chat/completions`).
- **Gateway & API Layer**:
  - Nginx Reverse Proxy (SSL 종단, 트래픽 라우팅, Rate Limiting 기초).
  - FastAPI 기반 AI Security Gateway (`/api/v1/chat/completions`, `/api/v1/tools`, `/api/v1/guardrails/rules`, `/api/v1/audit/logs`, `/api/v1/health`).
- **Security Guardrail Engine**:
  - **Input Guardrail (7단계)**: 요청 검증 -> 입력 길이/토큰 제한 -> 유니코드 NFKC 정규화 -> 유사 문자(Confusable) 탐지 -> 다중 인코딩(URL/Hex/Base64) 난독화 해제 -> 정규식/위협 시그니처 매칭 -> 시맨틱/페르소나 위반 탐지.
  - **Execution Guardrail**: BOLA(Broken Object Level Authorization) / IDOR 방어, 주문/고객 파라미터 경계 검증, 툴 실행 권한 제어.
  - **Output Guardrail (5단계)**: 내부 프롬프트/설정 탈취 방지 -> 리버스 쉘/명령어 삽입 탐지 -> 개인정보(PII: 주민번호, 카드번호, 전화번호, 원가) 마스킹(`[REDACTED]`) -> XSS 살균 -> 마크다운/링크 안전성 검증.
- **Data & Threat Intelligence**:
  - PostgreSQL 16 기반 3대 논리 스키마 분리:
    - `threat_intel`: 보안 룰셋, 시그니처, 탐지 패턴, 활성화 여부.
    - `commerce`: 고객, 상품(대외비 원가 `cost_price` 포함), 주문, 장바구니, 쿠폰.
    - `audit`: 비동기 보안 이벤트 감사 로그.
  - In-Memory Thread-Safe Rule Cache 및 Hot-Reload 엔진.
- **AI Processing**:
  - Ollama 연동 (Qwen 2.5 / Llama 3 로컬 모델 추론) 및 장애 대응 Fallback 모의 추론 엔진.
  - 컨텍스트 그라운딩 (Ground-Truth Context 주입) 및 RAG 인터페이스.
- **DevOps & Quality**:
  - Docker Compose 기반 멀티 컨테이너 원클릭 실행 환경.
  - GitHub Actions 기반 정적 분석(Ruff), 타입 검사(mypy), 단위/통합 테스트(pytest), 시크릿 스캐닝 CI.

### 3.2 제외 범위 (Out-of-Scope)
- 실제 PG사(이니시스, 토스 등) 연동 실결제 시스템.
- 대규모 분산 클러스터(Kubernetes, Kafka) 구축 (단일 노드 컨테이너 아키텍처로 충분한 요구사항).
- 외부 유료 LLM API(OpenAI GPT-4, Anthropic Claude 등)에 대한 과도한 결제 종속성 (로컬 Ollama 중심 구성).

---

## 4. 비기능적 요구사항 (Non-Functional Requirements)
1. **보안성 (Security)**:
   - 모든 외부 입력값은 절대 신뢰하지 않는 원칙(Fail-Closed) 준수.
   - 소스코드 및 형상관리 내 DB 패스워드, 시크릿 키 등 하드코딩 절대 금지.
2. **성능 (Performance)**:
   - 가드레일 검사 지연시간(Inspection Latency): 95th 백분위수 5ms 이하.
   - 보안 감사 로깅은 비동기 큐/백그라운드 태스크로 처리하여 사용자 응답 지연 0ms 지향.
3. **가용성 및 복원력 (Availability & Resilience)**:
   - AI 추론 런타임(Ollama) 장애 시 비즈니스 폴백(Smart Rule Fallback)을 통해 서비스 중단 방지.
   - 헬스체크 엔드포인트를 통한 컨테이너 오케스트레이션 안정성 확보.
4. **유지보수성 (Maintainability)**:
   - Clean Architecture 및 Repository/DAO 패턴 적용.
   - 100% Type Annotation 및 Pydantic v2 데이터 유효성 검증.
