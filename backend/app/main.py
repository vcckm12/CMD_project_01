"""FastAPI entry point (DES-001 §3). Run with a single worker (in-memory limits and caches)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from app.api import auth, chat, compat, health
from app.chat.service import UserBudget
from app.config import Settings, get_settings
from app.context import RequestContextMiddleware
from app.db.pools import Pools
from app.errors import install_error_handlers
from app.guardrails.alerts import AlertMonitor
from app.guardrails.input_guardrail import InputGuardrailEngine
from app.guardrails.judge import SafetyJudge
from app.guardrails.output_guardrail import OutputGuardrailEngine
from app.guardrails.pipeline import GuardrailPipeline
from app.guardrails.rule_cache import RuleCache
from app.security.auth import LoginRateLimiter
from app.security.tokens import JwtSigner
from app.services.ollama import OllamaClient
from app.services.prompts import PROTECTED_TEXTS
from app.services.slm import SLMService


def load_fingerprints(path: Path | None) -> frozenset[str]:
    if path is None:
        return frozenset()
    lines = (line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines())
    return frozenset(line for line in lines if len(line) == 64 and all(c in "0123456789abcdef" for c in line))


def create_app(settings: Settings | None = None, *, ollama_transport=None) -> FastAPI:
    """`ollama_transport` lets integration tests script the model server (httpx MockTransport)."""
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pools = Pools(settings.auth_database_url, settings.chat_database_url)
        await app.state.pools.open()
        app.state.alert_monitor.pool = app.state.pools.chat
        if app.state.pools.chat is not None:
            app.state.slm = SLMService(
                app.state.ollama,
                app.state.guardrails,
                app.state.pools.chat,
                num_predict=settings.ollama_num_predict,
                call_timeout_s=settings.ollama_call_timeout_seconds,
            )
        reloader = None
        if app.state.pools.chat is not None:
            # First load happens before serving; afterwards a poller swaps snapshots atomically.
            await app.state.rule_cache.refresh(app.state.pools.chat)
            reloader = asyncio.create_task(
                app.state.rule_cache.run(app.state.pools.chat, settings.ruleset_poll_seconds)
            )
        try:
            yield
        finally:
            if reloader is not None:
                reloader.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reloader
            await app.state.ollama.close()
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
    app.state.rule_cache = RuleCache()
    app.state.input_engine = InputGuardrailEngine(budget_ms=settings.guardrail_budget_ms)
    app.state.output_engine = OutputGuardrailEngine(
        secret_fingerprints=load_fingerprints(settings.secret_fingerprints_file),
        protected_texts=PROTECTED_TEXTS,
        budget_ms=settings.guardrail_budget_ms,
    )
    app.state.ollama = OllamaClient(
        settings.ollama_base_url,
        settings.ollama_model,
        num_ctx=settings.ollama_num_ctx,
        queue_wait_s=settings.ollama_queue_wait_seconds,
        transport=ollama_transport,
    )
    app.state.alert_monitor = AlertMonitor(None, settings.input_fingerprint_key.encode("utf-8"))
    app.state.guardrails = GuardrailPipeline(
        app.state.input_engine,
        app.state.output_engine,
        SafetyJudge(app.state.ollama, timeout_s=settings.judge_timeout_seconds) if settings.judge_enabled else None,
        app.state.alert_monitor,
    )
    app.state.user_budget = UserBudget(settings.user_requests_per_minute)
    app.state.model_check = {"checked_at": 0.0, "ok": False}
    install_error_handlers(app)
    app.add_middleware(RequestContextMiddleware, max_body_bytes=settings.max_body_bytes)
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(chat.router)
    app.include_router(compat.router)
    return app


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
