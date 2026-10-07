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
| AI 판별(입력·Tool·출력)·관제 경보 | 완료 (held-out v2: 입력 100%, 출력 83%, 지연 p50 1.7초) |
| 챗 파이프라인(native·SSE·AnythingLLM 호환·읽기 Tool) | 완료 (실모델 응답 20~55초, CPU) |
| Tool·변경 승인(ACTION-01~04)·쇼핑 조회(SHOP-01~06) | 완료 |
| 감사 worker·스케줄러 | 완료 |
| Nginx·TLS·고객 웹 | 완료 (브라우저 E2E 통과) |
| 관제 API·Streamlit(대시보드·감사·경보·룰 게시·PDF·검증 챗) | 완료 (브라우저 E2E 통과) |
| lab ON·OFF 비교 (분리 환경, A/B 러너, 관제 비교 화면) | 완료 |

## 로컬 실행 (현재 단계: DB)

필요: Docker Desktop, Python 3.12

```bash
python scripts/gen_env.py                 # .env 생성 (임의 비밀번호, 커밋 금지)
docker compose up -d --wait postgres      # PostgreSQL 17
docker compose run --rm migrate           # 스키마 적용 + 로그인 역할 발급
sh scripts/test.sh                        # 통합 테스트 (일회용 DB, 개발 DB와 분리)
```

API 서버(현재 인증·health만 제공):

```bash
python scripts/gen_jwt_key.py              # secrets/jwt_private.pem (cryptography 필요)
docker compose up -d --wait api audit-worker scheduler streamlit nginx
# 관리자 계정은 공개 API가 아닌 내부 명령으로만 생성 (비밀번호는 프롬프트로 입력)
docker compose exec api python -m app.cli.create_user --email admin@example.internal --role admin
```

JWT 서명 키 `secrets/jwt_private.pem`은 커밋하지 않습니다.

ON/OFF 비교용 lab 환경(운영과 분리, 합성 데이터·미끼 비밀만 사용, 8443 포트):

```bash
LAB_ADMIN_PASSWORD='12자 이상 비밀번호' sh scripts/lab_up.sh
# https://ops.example.internal:8443 → 관리자 로그인 → "LAB ON/OFF 비교" 메뉴
docker compose --env-file .env.lab down      # 종료 (데이터 유지, 삭제는 down -v)
```

HTTPS 진입점 (내부망 1단계, D-23):

```bash
python scripts/gen_certs.py                 # secrets/tls/ 사설 CA·서버 인증서 (cryptography 필요)
docker compose up -d --wait nginx
```

접속할 PC에서는 `secrets/tls/ca.crt`를 신뢰할 수 있는 루트 인증서로 설치합니다. 그리고 hosts 파일에 `10.10.70.149 shop.example.internal ops.example.internal`을 추가합니다. 이후 `https://shop.example.internal`로 접속합니다. 브라우저 E2E: `scripts/e2e_web.py`(파일 머리말 참고).

### 같은 대역의 다른 PC에서 접속·시연

1. hosts(관리자 메모장, `C:\Windows\System32\drivers\etc\hosts`)에 `10.10.70.149 shop.example.internal ops.example.internal` 추가
2. `ca.crt` **한 파일만** 복사(`ca.key`·`server.key`는 복사 금지) 후 관리자 PowerShell:
   `Import-Certificate -FilePath <경로>\ca.crt -CertStoreLocation Cert:\LocalMachine\Root` → 브라우저 재시작(Firefox는 별도 가져오기)
3. 시연은 LAB 기준: 쇼핑몰 `https://shop.example.internal:8443`, 관제 `https://ops.example.internal:8443`(LAB DB는 운영과 분리되어 서로의 기록이 보이지 않음)
   - 상품 검색 → 상품명·가격 안내, "장바구니에 담아줘" → 확인 화면, 공격 문장 → 🛡️ 차단
   - 관제 대시보드 목록에서 차단 건의 event_id → 감사 상세(규칙 설명 + LAB 전용 입력 원문), "LAB ON/OFF 비교"에서 A/B 실행
   - 고객 계정의 합성 주문·쿠폰: `docker compose --env-file .env.lab run --rm migrate python -m app.cli.seed --customer-email <이메일>`
4. 인증서는 `gen_certs.py`로 다시 만들거나 도메인을 바꿀 때만 다시 배포합니다.

### 브라우저 E2E (LAB 8443 기준)

```bash
docker build -t ag-e2e -f scripts/e2e.Dockerfile scripts      # Playwright 실행 이미지(최초 1회)
HIP=$(docker run --rm ag-e2e getent hosts host.docker.internal | awk '{print $1}')
docker run --rm -e EDGE_IP=$HIP -e SHOP_URL=https://shop.example.internal:8443 -v "$PWD/scripts:/s" ag-e2e python /s/e2e_web.py
docker run --rm -e EDGE_IP=$HIP -e OPS_URL=https://ops.example.internal:8443 -e OPS_EMAIL=<lab 관리자> -e OPS_PASSWORD=<비밀번호>   -e EVENT_ID=<최근 차단 event_id> -v "$PWD/scripts:/s" ag-e2e python /s/e2e_ops.py
docker run --rm -e EDGE_IP=$HIP -e OPS_EMAIL=<lab 관리자> -e OPS_PASSWORD=<비밀번호> -v "$PWD/scripts:/s" -v "$PWD/tmp:/out" ag-e2e python /s/e2e_lab.py
```

쇼핑 웹 E2E는 LAB DB에 이름에 markup이 든 XSS 시험 상품(SKU `E2E-XSS-001`)이 있어야 합니다. 점검 전용 LAB 관리자 비밀번호는 `secrets/lab/e2e_admin_password.txt`, 개발 DB 관리자(admin@example.internal) 비밀번호는 `secrets/prod_admin_password.txt`(둘 다 커밋 제외)에 있습니다.

### AnythingLLM 연결

- 해당 PC 환경변수 `NODE_EXTRA_CA_CERTS=<ca.crt 경로>` 지정 후 AnythingLLM 완전 종료·재시작(없으면 `Connection error`)
- LLM Provider는 **Generic OpenAI**(Ollama 아님): Base URL `https://shop.example.internal:8443/v1`(LAB), API Key는 그 쇼핑몰에서 발급한 `gct_…` 토큰(환경별 발급), Model `qwen3:8b`, Token context window 8192, Max Tokens는 512보다 커도 서버가 512로 맞춤
- 워크스페이스 ⚙ → Chat Settings → 채팅 모드 **Chat**(Agent/Automatic은 `tools`를 보내 400). Workspace LLM 설정이 따로 있으면 System default로
- 답변은 CPU 모델이라 20~50초 걸릴 수 있습니다.

개발용 합성 데이터와 룰셋:

```bash
docker compose exec api python -m app.cli.rules bootstrap --actor-email admin@example.internal  # 최초 1회
docker compose run --rm migrate python -m app.cli.seed --customer-email <가입한 고객 이메일>      # 합성 상품·주문·쿠폰
```

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
