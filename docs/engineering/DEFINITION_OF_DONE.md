# 완료의 정의 (DEFINITION_OF_DONE.md)

## 1. 개요 (Overview)
본 문서는 `AI Security Guardrail Chatbot` 프로젝트에서 하나의 작업, 기능(Feature), 또는 버그 수정이 "완료(Done)" 상태로 인정받기 위해 반드시 충족해야 하는 공통 기준(Definition of Done, DoD)을 정의합니다.

---

## 2. 완료 기준 체크리스트 (DoD Checklist)

### 2.1 코드 품질 및 구현 기준 (Code Quality)
- [ ] **요구사항 충족**: 명시된 기능 요구사항 및 비기능 요구사항을 100% 충족하는가?
- [ ] **타입 힌트 적용**: 모든 함수와 메서드에 적절한 Type Annotation이 누락 없이 작성되었는가?
- [ ] **Pydantic 모델 검증**: API 입출력 및 데이터 교환 시 Pydantic 스키마 검증을 거치는가?
- [ ] **Ruff 린트 통과**: `ruff check .` 실행 시 어떠한 경고나 에러도 발생하지 않는가?
- [ ] **데드 코드 배제**: 사용되지 않는 디버깅용 print문, 미사용 import, 불필요한 주석이 제거되었는가?

### 2.2 보안 기준 (Security & Secret Management)
- [ ] **하드코딩 배제**: 소스코드 내에 IP, 포트, 패스워드, API Key, Secret 문자열이 직접 작성되지 않았는가?
- [ ] **환경변수 분리**: 신규 설정값이 필요한 경우 `.env.example` 및 `app.core.config.Settings`에 반영되었는가?
- [ ] **보안 원칙 준수**: 입력값 유효성 검사, BOLA 권한 검증, PII 마스킹 정책이 누락 없이 적용되었는가?
- [ ] **에러 메시지 보호**: 클라이언트에 내부 시스템 경로, SQL 쿼리, 스택트레이스가 노출되지 않는가?

### 2.3 테스트 및 검증 기준 (Testing & Verification)
- [ ] **단위 테스트 작성**: 신규 로직에 대한 단위 테스트(`tests/test_*.py`)가 작성되었는가?
- [ ] **전체 테스트 통과**: `pytest` 실행 시 모든 테스트 케이스가 성공하는가?
- [ ] **예외 케이스 검증**: 정상 흐름뿐만 아니라 경계값, Null 입력, 악의적 페이로드에 대한 차단 테스트가 포함되었는가?

### 2.4 문서화 기준 (Documentation)
- [ ] **API 명세 갱신**: 신규/수정된 API가 있는 경우 `docs/engineering/API_CONTRACT.md`에 반영되었는가?
- [ ] **DB 변경 반영**: 스키마 수정 시 `docs/engineering/DATABASE_DESIGN.md` 및 DDL 마이그레이션 파일이 갱신되었는가?
- [ ] **코드 문서화**: 비자명한 알고리즘이나 보안 로직에 대해 명확한 Docstring 및 설명 주석이 포함되었는가?

### 2.5 CI/CD 및 형상관리 기준 (Git & CI/CD)
- [ ] **커밋 규약 준수**: Conventional Commits 포맷(`feat:`, `fix:`, `chore:` 등)을 준수하였는가?
- [ ] **GitHub Actions 통과**: PR 생성 시 CI 파이프라인의 모든 검사(Lint, Test, Secret Scan)가 성공하였는가?
- [ ] **코드 리뷰 완료**: 최소 1인 이상의 동료 엔지니어 검토 및 승인을 득하였는가?

---

## 3. DoD 위반 시 조치
- 상기 항목 중 단 하나라도 충족되지 않은 PR은 `main` 브랜치로 병합될 수 없으며, 요청자에게 수정이 요구됩니다.
