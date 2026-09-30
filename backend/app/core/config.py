"""Application Configuration Module."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global system configuration settings loaded from environment variables."""

    # Project metadata
    PROJECT_NAME: str = "AI Security Guardrail Chatbot"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # Server settings
    BACKEND_PORT: int = 8000
    HOST: str = "0.0.0.0"

    # Security settings
    SECRET_KEY: str = "default-insecure-secret-key-change-in-production"
    MAX_INPUT_LENGTH: int = 2000
    MAX_OUTPUT_LENGTH: int = 4000
    ENABLE_HOT_RELOAD: bool = True

    # Database settings (PostgreSQL)
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "guardrail_admin"
    POSTGRES_PASSWORD: str = "change_me_securely"
    POSTGRES_DB: str = "guardrail_db"
    DATABASE_URL: str | None = None

    # Ollama / SLM Settings
    OLLAMA_BASE_URL: str = "http://host.docker.internal:11434"
    OLLAMA_MODEL: str = "qwen2.5:latest"
    OLLAMA_TIMEOUT_SECONDS: int = 15
    ENABLE_MOCK_FALLBACK: bool = True

    # Logging
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    def get_database_url(self) -> str:
        """Construct database connection URL if not explicitly provided."""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


settings = Settings()
