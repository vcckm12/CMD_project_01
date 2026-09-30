# 🛡️ AI Security Guardrail Chatbot System

[![Python 3.12](https://img.shields.io/badge/python-3.10%20~%203.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://www.docker.com/)
[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![OWASP Top 10 for LLM](https://img.shields.io/badge/OWASP-LLM_Defense-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Ollama](https://img.shields.io/badge/Ollama-Qwen2.5--7B-orange.svg)](https://ollama.ai/)

---

## 📖 프로젝트 소개 (Introduction)

**AI Security Guardrail Chatbot**은 생성형 AI(Generative AI) 및 소형 언어 모델(SLM)을 실제 E-커머스 및 비즈니스 환경에 도입할 때 발생하는 **OWASP Top 10 for LLM 위협(프롬프트 인젝션, 시스템 탈취, BOLA 권한 상승, PII 유출, 리버스 쉘 페이로드, 대외비 원가 유출 등)**을 선제적으로 방어하는 **엔터프라이즈급 3-Tier AI 보안 게이트웨이 시스템**입니다.

### 🌟 핵심 특징
1. **7단계 Input Guardrail**: 길이 제한 ➔ 유니코드 NFKC 정규화 ➔ 호모글리프 탐지 ➔ Base64/Hex/URL 난독화 해제 ➔ 정규식/위협 시그니처 ➔ TF-IDF 코사인 유사도 시맨틱 벡터 제어.
2. **BOLA / IDOR Execution Guardrail**: 도구 호출(Tool Calling) 시 파라미터 경계 및 고객 주문 소유권 상시 검증.
3. **5단계 Output Guardrail**: 시스템 프롬프트 유출 차단, 리버스 쉘 탐지, PII(주민번호, 카드, 전화번호, **대외비 상품 원가**) 자동 마스킹(`[REDACTED]`), XSS 살균.
4. **동적 문맥 생성 엔진 (Dynamic Contextual Reasoning)**: Ollama (`qwen2.5:7b`) 연동 및 스마트 패션 어드바이저 추론 엔진 탑재.
5. **표준 클라이언트 호환**: 모던 쇼핑몰 웹 UI(`mock_store`), AnythingLLM 연동용 OpenAI 규격(`/v1/chat/completions`), Streamlit 보안 관제 대시보드(`admin_ui`).

---

## 💻 다른 컴퓨터에서 실행하는 방법 (Deployment Guide)

다른 컴퓨터(Windows, Mac, Linux)에서 이 프로젝트를 처음 실행할 때 다음 단계 중 편한 방법을 선택하세요.

### 📋 사전 준비 사항 (Prerequisites)
1. **Git 설치**: [https://git-scm.com/](https://git-scm.com/)
2. **Python 3.10 이상 설치**: [https://www.python.org/](https://www.python.org/) *(PATH 환경변수 추가 체크 필수)*
3. **(선택 사항 - 로컬 LLM 구동 시)** **Ollama 설치**: [https://ollama.ai/](https://ollama.ai/)
   ```bash
   ollama pull qwen2.5:7b
   ```
   *(Ollama가 없어도 내장된 고도화 동적 생성 엔진으로 100% 정상 작동합니다.)*

---

### 🚀 방법 1: Windows 원클릭 실행 (가장 추천)

1. **저장소 클론**:
   ```cmd
   git clone https://github.com/vcckm12/CMD_project_01.git
   cd CMD_project_01
   ```

2. **`run_all.bat` 더블 클릭 또는 명령 프롬프트에서 실행**:
   ```cmd
   run_all.bat
   ```
   - 필요한 패키지(`requirements.txt`)가 자동 설치되고, 3개 서비스가 즉시 기동되며 브라우저가 열립니다.

---

### 🚀 방법 2: Mac / Linux 원클릭 실행

1. **저장소 클론**:
   ```bash
   git clone https://github.com/vcckm12/CMD_project_01.git
   cd CMD_project_01
   ```

2. **실행 스크립트 구동**:
   ```bash
   chmod +x run_all.sh
   ./run_all.sh
   ```

---

### 🚀 방법 3: 수동 명령어 직접 실행 (CLI)

1. **의존성 패키지 설치**:
   ```bash
   pip install -r requirements.txt
   ```

2. **3개 서비스 개별 터미널에서 실행**:
   - **터미널 1 (FastAPI 백엔드)**:
     ```bash
     python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend
     ```
   - **터미널 2 (Streamlit 관리자 대시보드)**:
     ```bash
     python -m streamlit run admin_ui/app.py --server.port 8501
     ```
   - **터미널 3 (쇼핑몰 Mock Store 웹 서버)**:
     ```bash
     python -m http.server 3000 --directory mock_store --bind 127.0.0.1
     ```

---

### 🐳 방법 4: Docker Compose 컨테이너 실행

Docker가 설치된 컴퓨터에서는 단 한 줄로 전체 인프라(PostgreSQL + FastAPI + Streamlit + Nginx)를 구동할 수 있습니다.

```bash
docker compose up --build -d
```

---

## 🌐 접속 주소 안내 (Service Endpoints)

| 서비스 명칭 | 포트 / URL | 설명 |
|---|---|---|
| 🛍️ **쇼핑몰 웹 & 챗봇 UI** | [http://localhost:3000](http://localhost:3000) *(Docker는 :80)* | 실제 고객용 패션 쇼핑몰 및 우측 하단 AI 챗봇 위젯 |
| 🛡️ **가드레일 관리자 대시보드** | [http://localhost:8501](http://localhost:8501) | 실시간 위협 감사 로그 모니터링, 동적 룰셋 관리, 공격 시뮬레이터 |
| ⚡ **FastAPI Swagger API 문서** | [http://localhost:8000/docs](http://localhost:8000/docs) | RESTful API 엔드포인트 대화형 문서 |
| 💬 **AnythingLLM 연동 Base URL** | `http://localhost:8000/v1` | AnythingLLM 데스크톱 앱 연동용 OpenAI 호환 엔드포인트 |

---

## 💬 AnythingLLM 데스크톱 연동 가이드

1. AnythingLLM Desktop 앱 실행 ➔ **Settings** ➔ **LLM Preference** 이동.
2. LLM Provider를 **`OpenAI Compatible`** 또는 **`Generic OpenAI`** 선택.
3. 설정값 입력:
   - **Base URL**: `http://localhost:8000/v1`
   - **API Key**: 아무 문자열 입력 (예: `guardrail-key`)
   - **Model Name**: `qwen2.5:7b` (또는 `qwen2.5:latest`)
4. 연동 후 질의 시 가드레일이 모든 입력/출력을 실시간 검사 및 차단합니다.

---

## 🧪 보안 벤치마크 및 테스트 실행

```bash
# 1. 30종 pytest 단위 및 통합 테스트
python -m pytest backend/tests -v

# 2. 250종 종합 보안 & 레드팀 공격 벤치마크 평가 (100% 방어율 검증)
python backend/tests/benchmark_test.py
```

---

## 📁 디렉터리 구조 (Project Layout)

```
CMD_project/
├── backend/                        # FastAPI 가드레일 백엔드 게이트웨이
│   ├── app/
│   │   ├── api/                    # Native Chat, OpenAI-Compat, Tools, Rules, Audit 라우터
│   │   ├── guardrails/             # 7-Step Input, 5-Step Output, Execution 가드레일
│   │   ├── repositories/           # ThreatDAO, ShopDAO, AuditDAO
│   │   ├── services/               # SLMService, ShopService, AuditService
│   │   └── main.py                 # FastAPI 애플리케이션 진입점
│   ├── tests/                      # pytest 테스트 및 250-Case 벤치마크 스크립트
│   └── Dockerfile
├── mock_store/                     # 반응형 패션 쇼핑몰 웹 UI & 챗봇 위젯
├── admin_ui/                       # Streamlit 보안 관제 및 동적 룰셋 관리 UI
├── datasets/                       # 250건 종합 보안 평가 데이터셋
├── run_all.bat                     # Windows 원클릭 실행 배치 스크립트
├── run_all.sh                      # Linux / macOS 원클릭 실행 쉘 스크립트
├── requirements.txt                # 통합 패키지 의존성 목록
├── docker-compose.yml              # PostgreSQL + Backend + AdminUI + Nginx 오케스트레이션
└── README.md                       # 종합 시스템 안내 및 배포 가이드
```
