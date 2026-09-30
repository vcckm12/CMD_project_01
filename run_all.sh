#!/usr/bin/env bash

set -e

echo "========================================================"
echo "  AI Security Guardrail Chatbot System Launcher (Linux/Mac)"
echo "========================================================"
echo ""

# 1. Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3이 설치되어 있지 않습니다."
    exit 1
fi

# 2. Install dependencies
echo "[1/3] 의존성 패키지 설치 확인 중..."
pip install -r requirements.txt --quiet

# 3. Launch Services
echo "[2/3] 서비스 구동 시작..."
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --app-dir backend &
BACKEND_PID=$!

python3 -m streamlit run admin_ui/app.py --server.port 8501 --server.headless true &
ADMIN_PID=$!

python3 -m http.server 3000 --directory mock_store --bind 0.0.0.0 &
MOCK_PID=$!

sleep 3

echo ""
echo "========================================================"
echo "  모든 서비스가 백그라운드에서 정상 가동 중입니다!"
echo ""
echo "  - 🛍️ 쇼핑몰 웹 & 챗봇 UI : http://localhost:3000"
echo "  - 🛡️ 보안 관제 대시보드   : http://localhost:8501"
echo "  - ⚡ 백엔드 Swagger Docs   : http://localhost:8000/docs"
echo "========================================================"
echo ""
echo "서비스를 종료하려면 Ctrl+C 를 누르세요."

trap "kill $BACKEND_PID $ADMIN_PID $MOCK_PID" EXIT
wait
