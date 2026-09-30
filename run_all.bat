@echo off
chcp 65001 > nul
title AI Security Guardrail Chatbot Launcher

echo ========================================================
echo   AI Security Guardrail Chatbot System Launcher
echo ========================================================
echo.

echo [1/4] Python 환경 및 의존성 확인 중...
python --version > nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python이 설치되어 있지 않거나 PATH에 등록되지 않았습니다.
    echo https://www.python.org/ 에서 Python 3.10 이상을 설치해 주세요.
    pause
    exit /b 1
)

echo [2/4] 패키지 설치 확인 (pip install -r requirements.txt)...
pip install -r requirements.txt --quiet

echo [3/4] 서비스 백그라운드 구동 시작...
echo - FastAPI 백엔드 게이트웨이 시작 중 (Port 8000)...
start "Backend - FastAPI" cmd /k "python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend"

timeout /t 2 /nobreak > nul

echo - Streamlit 관리자 대시보드 시작 중 (Port 8501)...
start "Admin UI - Streamlit" cmd /k "python -m streamlit run admin_ui/app.py --server.port 8501"

timeout /t 2 /nobreak > nul

echo - 쇼핑몰 Mock Store 웹 서버 시작 중 (Port 3000)...
start "Mock Store - Web" cmd /k "python -m http.server 3000 --directory mock_store --bind 127.0.0.1"

timeout /t 2 /nobreak > nul

echo.
echo ========================================================
echo   모든 서비스가 성공적으로 구동되었습니다!
echo.
echo   - 🛍️ 쇼핑몰 웹 & 챗봇 UI : http://localhost:3000
echo   - 🛡️ 보안 관제 대시보드   : http://localhost:8501
echo   - ⚡ 백엔드 Swagger Docs   : http://localhost:8000/docs
echo ========================================================
echo.

start http://localhost:3000
start http://localhost:8501

echo 창을 닫으면 실행 안내가 종료됩니다. (각 서비스 콘솔창에서 개별 종료 가능)
pause
