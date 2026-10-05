"""Server configuration (DES-000 §5). Values come from the environment only."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore", frozen=True)

    app_env: Literal["production", "lab"] = "production"
    guardrail_enforced: bool = True

    # One pool per least-privilege login role (DES-002 §5).
    auth_database_url: str
    chat_database_url: str | None = None
    rules_database_url: str | None = None
    audit_reader_database_url: str | None = None

    # Guardrail inspection hard budget per stage (D-16) and optional registered secret fingerprints
    # (one SHA-256 hex per line) checked by RULE_CRITICAL_SECRET_DUMP.
    guardrail_budget_ms: float = 50.0
    secret_fingerprints_file: Path | None = None
    ruleset_poll_seconds: float = 5.0

    jwt_private_key_file: Path
    jwt_issuer: str = "ai-guardrail"
    jwt_audience: str = "ai-guardrail-api"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 7 * 24 * 3600
    client_token_ttl_seconds: int = 30 * 24 * 3600

    # Exact Origin values allowed for cookie-authenticated calls (refresh/logout).
    shop_origin: str = "https://shop.example.internal"
    ops_origin: str = "https://ops.example.internal"

    max_body_bytes: int = 262_144
    login_failure_limit: int = 10
    login_failure_window_seconds: int = 900

    ollama_base_url: str = "http://10.10.70.65:11434"
    ollama_model: str = "qwen3:8b"
    ollama_model_digest: str | None = None
    ollama_num_ctx: int = 8192
    ollama_queue_wait_seconds: float = 30.0

    # LLM safety judge (D-25) and alert fingerprints (D-26). The key only has to stay stable and secret;
    # it makes stored input fingerprints irreversible by dictionary guessing.
    judge_enabled: bool = True
    judge_timeout_seconds: float = 20.0
    input_fingerprint_key: str = ""

    @model_validator(mode="after")
    def _enforce_guardrail(self) -> Settings:
        # D-21: production can never run with the guardrail disabled.
        if self.app_env == "production" and not self.guardrail_enforced:
            raise ValueError("GUARDRAIL_ENFORCED must be true when APP_ENV=production")
        if self.app_env == "production" and not self.judge_enabled:
            raise ValueError("JUDGE_ENABLED must be true when APP_ENV=production")
        if self.app_env == "production" and len(self.input_fingerprint_key) < 32:
            raise ValueError("INPUT_FINGERPRINT_KEY must be set (>= 32 chars) when APP_ENV=production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
