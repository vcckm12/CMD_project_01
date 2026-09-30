# 아키텍처 결정 기록 (ADR/README.md)

## 1. 개요 (Architecture Decision Records)
본 디렉터리는 `AI Security Guardrail Chatbot` 프로젝트의 핵심 아키텍처 및 기술 스택 결정에 대한 맥락, 대안 분석, 최종 결정 이유 및 그에 따른 영향을 기록(Architectural Decision Records)하여 팀의 일관된 기술적 방향성을 유지합니다.

---

## 2. 등록된 아키텍처 결정 목록 (ADR Index)

| ADR 번호 | 의사결정 제목 (Title) | 상태 (Status) | 결정 일자 |
| :--- | :--- | :--- | :--- |
| **[ADR-001](#adr-001-postgresql-16-기반-3대-논리-스키마-분리-선정)** | PostgreSQL 16 기반 3대 논리 스키마 분리 선정 | Approved | 2026-09-30 |
| **[ADR-002](#adr-002-자체-경량-다계층-가드레일-파이프라인-구축)** | 자체 경량 다계층 가드레일 파이프라인 구축 (외부 무거운 프레임워크 지양) | Approved | 2026-09-30 |
| **[ADR-003](#adr-003-인메모리-스레드-안전-룰-캐시-및-db-hot-reload-채택-redis-배제)** | 인메모리 스레드 안전 룰 캐시 및 DB Hot-Reload 채택 (Redis 배제) | Approved | 2026-09-30 |
| **[ADR-004](#adr-004-로컬-ollama-slm-추론-및-스마트-폴백-엔진-선정)** | 로컬 Ollama SLM 추론 및 스마트 폴백 엔진 선정 | Approved | 2026-09-30 |
| **[ADR-005](#adr-005-streamlit-기반-보안-관제-대시보드-및-순수-htmljs-mock-store-채택)** | Streamlit 기반 보안 관제 대시보드 및 순수 HTML/JS Mock Store 채택 | Approved | 2026-09-30 |

---

## 3. 세부 ADR 명세

### ADR-001: PostgreSQL 16 기반 3대 논리 스키마 분리 선정
- **상태**: Approved
- **맥락 (Context)**: 위협 인텔리전스 룰, 이커머스 비즈니스 데이터, 보안 감사 로그를 효과적으로 관리하고 보안 영역을 분리해야 함.
- **대안 검토**:
  1. MySQL / MariaDB 단일 DB 사용: JSON 및 고급 쿼리 지원 부족, 스키마 격리 제한.
  2. MongoDB / NoSQL 사용: 관계형 데이터(고객-주문-상품) 무결성 보장 한계.
  3. PostgreSQL 16 단일 인스턴스 내 3대 논리 스키마(`threat_intel`, `commerce`, `audit`) 분리: 관계형 무결성, 스키마 레벨 권한 제어, 고성능 인덱싱 동시 만족.
- **결정 (Decision)**: 대안 3(PostgreSQL 16 3대 논리 스키마 분리)을 채택함.
- **결과 및 영향**: 서비스 간 결합도를 낮추고 데이터 일관성과 보안 분리를 달성함.

---

### ADR-002: 자체 경량 다계층 가드레일 파이프라인 구축
- **상태**: Approved
- **맥락 (Context)**: 외부 무거운 가드레일 프레임워크(NeMo Guardrails, Llama Guard 등)는 막대한 메모리와 GPU 리소스를 요구하며 응답 지연(Latency)이 큽니다.
- **대안 검토**:
  1. 외부 무거운 LLM 기반 Guardrail: 높은 정확도이나 지연시간(500ms 이상) 발생 및 GPU 필요.
  2. 자체 개발 순수 파이썬 7단계 Input / 5단계 Output 가드레일: 5ms 이내 초저지연, 정규화(NFKC), 호모글리프, 인코딩 해제, 정규식/시그니처 매칭 기반 초고속 검사.
- **결정 (Decision)**: 대안 2(자체 경량 다계층 가드레일 파이프라인)를 채택함.
- **결과 및 영향**: 초저지연 보안 검증과 쉬운 커스터마이징 및 100% 테스트 가능성 확보.

---

### ADR-003: 인메모리 스레드 안전 룰 캐시 및 DB Hot-Reload 채택 (Redis 배제)
- **상태**: Approved
- **맥락 (Context)**: 보안 룰 검사는 매 요청마다 수십 회 수행되므로 DB 쿼리 오버헤드를 방지해야 함.
- **대안 검토**:
  1. Redis 캐시 서버 도입: 네트워크 홉 발생 및 불필요한 인프라 복잡도 증가.
  2. 인메모리 Python 딕셔너리/스레드 락 기반 캐시 + DB 동기화 Hot-Reload API: 인프라 오버헤드 0, 마이크로초 단위 룰 조회 가능.
- **결정 (Decision)**: 불필요한 Redis 도입을 배제하고 대안 2(In-Memory Rule Cache)를 채택함.

---

### ADR-004: 로컬 Ollama SLM 추론 및 스마트 폴백 엔진 선정
- **상태**: Approved
- **맥락 (Context)**: 민감한 고객 주문 데이터 및 기업 대외비가 포함된 질의를 외부 퍼블릭 클라우드 LLM에 전송 시 데이터 유출 위험 존재.
- **결정 (Decision)**: 온프레미스/로컬 구동 가능한 Ollama(Qwen2.5/Llama3)를 기본 AI 런타임으로 채택하고, 모델 오프라인 시 자동 동작하는 비즈니스 Smart Fallback을 구현함.
- **결과 및 영향**: 데이터 주권 확보, 비용 0원, 장애 내성 극대화.

---

### ADR-005: Streamlit 기반 보안 관제 대시보드 및 순수 HTML/JS Mock Store 채택
- **상태**: Approved
- **맥락 (Context)**: 보안 관제 UI와 쇼핑몰 테스트 웹 UI를 빠르고 유지보수하기 쉽게 구축해야 함.
- **결정 (Decision)**: 관리자 관제는 Python Streamlit을, 사용자 웹은 의존성 없는 순수 HTML5/CSS3/Vanilla JS를 사용하여 직관적인 분리와 빠른 배포 달성.
