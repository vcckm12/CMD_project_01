# AI 보안 가드레일 챗봇 (v2)

쇼핑 고객 질의를 입력·실행·출력 가드레일로 검사하는 FastAPI 게이트웨이입니다. 모델(로컬 Ollama `qwen3:8b`)은 권한 판정자가 아니며, 상품·주문 조회와 고객 확인을 거친 장바구니·쿠폰 변경만 허용합니다.

> v2 브랜치는 설계 문서 [docs/](docs/README.md)를 기준으로 새로 구성하는 중입니다. 이전 MVP는 `main` 브랜치에 있습니다.

## 진행 상태

| 단계 | 상태 |
|---|---|
| 설계 문서 DES-000~007 v1.1 | 완료 |
| PostgreSQL 17 스키마·역할·권한 + 통합 테스트 | 완료 |
| 인증(JWT·refresh·client token) | 완료 |
| 입력·출력 가드레일 엔진·룰셋 게시 | 완료 (탐지율은 [DES-007 §8](docs/07_verification_operations_plan.md#8-문서-검증-기록) 참고) |
| 챗 파이프라인·Ollama 연동 | 예정 |
| Tool·변경 승인 | 예정 |
| 감사 worker·스케줄러 | 예정 |
| 고객 웹 / Streamlit 관제 / lab ON·OFF 비교 | 예정 |

## 로컬 실행 (현재 단계: DB)

필요: Docker Desktop, Python 3.12

```bash
python scripts/gen_env.py                 # .env 생성 (임의 비밀번호, 커밋 금지)
docker compose up -d --wait postgres      # PostgreSQL 17
docker compose run --rm migrate           # 스키마 적용 + 로그인 역할 발급
docker compose --profile test run --rm db-test   # DB·API 통합 테스트
```

API 서버(현재 인증·health만 제공):

```bash
python scripts/gen_jwt_key.py              # secrets/jwt_private.pem (cryptography 필요)
docker compose up -d --wait api
# 관리자 계정은 공개 API가 아닌 내부 명령으로만 생성 (비밀번호는 프롬프트로 입력)
docker compose exec api python -m app.cli.create_user --email admin@example.internal --role admin
```

JWT 서명 키 `secrets/jwt_private.pem`은 커밋하지 않습니다.

DB 포트는 호스트에 공개하지 않습니다. 데이터를 지우고 다시 시작하려면 `docker compose down -v`.

## 디렉터리

| 경로 | 내용 |
|---|---|
| `docs/` | 설계 문서 (아키텍처는 [01_system_architecture.md](docs/01_system_architecture.md)) |
| `backend/migrations/` | SQL migration (DES-002가 기준) |
| `backend/app/` | FastAPI 애플리케이션 |
| `deployment/` | Postgres 초기화, (예정) Nginx |
| `frontend/shop/` | 고객 쇼핑 웹 (이전 MVP 화면, 재작성 예정) |
| `datasets/` | 공격·정상 시험셋 (이전 MVP에서 이전, 재라벨링 예정) |
| `reference/` | 기획 참조 자료 (공격 payload corpus는 저장소 제외) |
