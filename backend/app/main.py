"""Main FastAPI Application Entrypoint (백엔드 서버 메인 진입점).

이 모듈은 FastAPI 웹 프레임워크 애플리케이션을 초기화하고,
- 서버 시작/종료 시점의 생명주기(Lifespan) 관리 (룰셋 캐시 로딩, Ollama SLM 사전 웜업)
- 브라우저 간 통신을 위한 CORS 미들웨어 등록
- 보안 가드레일 및 BOLA 예외 핸들러 등록
- 각 도메인별 REST API 라우터(채팅, 도구, 룰, 감사로그, OpenAI 호환, Judge/Fuzzer)를 등록합니다.
"""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# 1. API 라우터 모듈 임포트
from app.api.openai_compat import router as openai_router
from app.api.v1.audit import router as audit_router
from app.api.v1.chat import router as chat_router
from app.api.v1.guardrails import router as guardrails_router
from app.api.v1.health import router as health_router
from app.api.v1.security_adv import router as security_adv_router
from app.api.v1.tools import router as tools_router
from app.core.config import settings
from app.core.exceptions import (
    AppBaseException,
    BOLAAuthorizationException,
    GuardrailBlockException,
)
from app.core.logging import logger
from app.guardrails.rule_manager import rule_manager
from app.services.slm_service import slm_service


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """FastAPI 애플리케이션의 생명주기(시작 및 종료) 관리 함수.

    - [Startup]: 서버가 켜질 때 DB/DAO로부터 보안 룰을 메모리에 로드하고,
      로컬 Ollama LLM 모델을 메모리에 상주(Pre-warm)시켜 첫 응답 지연을 방지합니다.
    - [Shutdown]: 서버가 종료될 때 안전한 정리 작업을 수행합니다.
    """
    logger.info("Initializing AI Security Guardrail Gateway...")

    # 1. 인메모리 위협 인텔리전스 룰셋 캐시 초기화
    await rule_manager.initialize()
    logger.info("RuleCacheManager initialized successfully.")

    # 2. 백그라운드 태스크로 Ollama 모델 사전 로딩(Warm-up) 실행
    asyncio.create_task(slm_service.prewarm())

    yield  # 이 시점부터 서버가 정상적으로 클라이언트 요청을 수신합니다.

    logger.info("Shutting down AI Security Guardrail Gateway...")


# FastAPI 인스턴스 생성
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Multi-tier AI Security Guardrail Gateway for E-Commerce Chatbot",
    lifespan=lifespan,
)

# 2. CORS (Cross-Origin Resource Sharing) 설정
# 쇼핑몰 웹 UI(3000 포트)나 관리자 대시보드(8501 포트) 등 다른 포트에서의 비동기 API 요청을 허용합니다.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 3. 전역 예외 처리기 (Global Exception Handlers)
@app.exception_handler(GuardrailBlockException)
async def guardrail_block_exception_handler(
    request: Request, exc: GuardrailBlockException
) -> JSONResponse:
    """가드레일 차단 예외 발생 시 표준 403 JSON 응답을 반환합니다."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.message,
            "error_code": "GUARDRAIL_BLOCKED",
            "details": exc.details,
        },
    )


@app.exception_handler(BOLAAuthorizationException)
async def bola_exception_handler(request: Request, exc: BOLAAuthorizationException) -> JSONResponse:
    """BOLA / IDOR 타인 자원 접근 시도 시 403 접근 금지 JSON 응답을 반환합니다."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.message,
            "error_code": "BOLA_AUTHORIZATION_FAILED",
            "details": exc.details,
        },
    )


@app.exception_handler(AppBaseException)
async def app_base_exception_handler(request: Request, exc: AppBaseException) -> JSONResponse:
    """기타 애플리케이션 공통 에러 발생 시 처리기."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.message,
            "error_code": "APPLICATION_ERROR",
            "details": exc.details,
        },
    )


# 4. 엔드포인트 라우터 등록
app.include_router(health_router, prefix=settings.API_V1_PREFIX)         # 헬스체크 (/api/v1/health)
app.include_router(chat_router, prefix=settings.API_V1_PREFIX)           # 네이티브 챗봇 (/api/v1/chat)
app.include_router(tools_router, prefix=settings.API_V1_PREFIX)          # E-커머스 도구 (/api/v1/tools)
app.include_router(guardrails_router, prefix=settings.API_V1_PREFIX)     # 룰셋 관리 (/api/v1/guardrails)
app.include_router(audit_router, prefix=settings.API_V1_PREFIX)          # 감사 로그 (/api/v1/audit)
app.include_router(security_adv_router, prefix=settings.API_V1_PREFIX)   # LLM Judge & Fuzzer (/api/v1/security)
app.include_router(openai_router)                                        # AnythingLLM 호환 (/v1/chat/completions)


@app.get("/")
async def root() -> dict[str, str]:
    """기본 루트 접속 시 서비스 정보 및 Swagger 문서 링크를 반환합니다."""
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs_url": "/docs",
        "health_url": f"{settings.API_V1_PREFIX}/health",
    }


if __name__ == "__main__":
    import uvicorn

    # 로컬 개발 환경에서 직접 python main.py 로 실행할 때 사용
    uvicorn.run(
        "app.main:app", host=settings.HOST, port=settings.BACKEND_PORT, reload=settings.DEBUG
    )
