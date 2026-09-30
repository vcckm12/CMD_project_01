"""Main FastAPI Application Entrypoint."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.openai_compat import router as openai_router
from app.api.v1.audit import router as audit_router
from app.api.v1.chat import router as chat_router
from app.api.v1.guardrails import router as guardrails_router
from app.api.v1.health import router as health_router
from app.api.v1.tools import router as tools_router
from app.core.config import settings
from app.core.exceptions import (
    AppBaseException,
    BOLAAuthorizationException,
    GuardrailBlockException,
)
from app.core.logging import logger
from app.guardrails.rule_manager import rule_manager


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context for startup and shutdown."""
    logger.info("Initializing AI Security Guardrail Gateway...")
    await rule_manager.initialize()
    logger.info("RuleCacheManager initialized successfully.")
    yield
    logger.info("Shutting down AI Security Guardrail Gateway...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Multi-tier AI Security Guardrail Gateway for E-Commerce Chatbot",
    lifespan=lifespan,
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception Handlers
@app.exception_handler(GuardrailBlockException)
async def guardrail_block_exception_handler(
    request: Request, exc: GuardrailBlockException
) -> JSONResponse:
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
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.message,
            "error_code": "APPLICATION_ERROR",
            "details": exc.details,
        },
    )


# Include API Routers
app.include_router(health_router, prefix=settings.API_V1_PREFIX)
app.include_router(chat_router, prefix=settings.API_V1_PREFIX)
app.include_router(tools_router, prefix=settings.API_V1_PREFIX)
app.include_router(guardrails_router, prefix=settings.API_V1_PREFIX)
app.include_router(audit_router, prefix=settings.API_V1_PREFIX)
app.include_router(openai_router)


@app.get("/")
async def root() -> dict[str, str]:
    """Root entrypoint."""
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs_url": "/docs",
        "health_url": f"{settings.API_V1_PREFIX}/health",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app", host=settings.HOST, port=settings.BACKEND_PORT, reload=settings.DEBUG
    )
