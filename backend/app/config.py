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

    @model_validator(mode="after")
    def _enforce_guardrail(self) -> Settings:
        # D-21: production can never run with the guardrail disabled.
        if self.app_env == "production" and not self.guardrail_enforced:
            raise ValueError("GUARDRAIL_ENFORCED must be true when APP_ENV=production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
