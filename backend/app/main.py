"""FastAPI entry point (DES-001 §3). Run with a single worker (in-memory limits and caches)."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import auth, health
from app.config import Settings, get_settings
from app.context import RequestContextMiddleware
from app.db.pools import Pools
from app.errors import install_error_handlers
from app.security.auth import LoginRateLimiter
from app.security.tokens import JwtSigner


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pools = Pools(settings.auth_database_url)
        await app.state.pools.open()
        try:
            yield
        finally:
            await app.state.pools.close()

    app = FastAPI(
        title="AI Guardrail API",
        lifespan=lifespan,
        docs_url=None if settings.app_env == "production" else "/docs",
        redoc_url=None,
        openapi_url=None if settings.app_env == "production" else "/openapi.json",
    )
    app.state.settings = settings
    app.state.jwt_signer = JwtSigner(
        settings.jwt_private_key_file, settings.jwt_issuer, settings.jwt_audience, settings.access_token_ttl_seconds
    )
    app.state.login_limiter = LoginRateLimiter(settings.login_failure_limit, settings.login_failure_window_seconds)
    install_error_handlers(app)
    app.add_middleware(RequestContextMiddleware, max_body_bytes=settings.max_body_bytes)
    app.include_router(health.router)
    app.include_router(auth.router)
    return app


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
