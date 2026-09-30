"""Application Configuration Module (애플리케이션 환경 설정 모듈).

이 모듈은 Pydantic Settings를 활용하여 시스템 전체에서 사용되는 설정값(포트, 보안 한도, DB 접속 정보, Ollama 연동값 등)을
.env 환경변수 파일 또는 기본값으로부터 안전하고 일관되게 로드하여 관리합니다.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """전역 시스템 설정 클래스 (Pydantic BaseSettings 상속).

    각 필드는 환경변수(.env)에 정의된 값이 있을 경우 해당 값을 우선 적용하며,
    없을 경우 지정된 기본값(Default)을 사용합니다.
    """

    # 1. 프로젝트 메타데이터 설정
    PROJECT_NAME: str = "AI Security Guardrail Chatbot"  # 프로젝트 이름
    VERSION: str = "1.0.0"                              # 시스템 버전
    ENVIRONMENT: str = "development"                     # 실행 환경 (development / production)
    DEBUG: bool = False                                 # 디버그 모드 여부
    API_V1_PREFIX: str = "/api/v1"                      # REST API 버전 1 기본 URL 접두사

    # 2. 서버 네트워크 설정
    BACKEND_PORT: int = 8000                            # 백엔드 서버 구동 포트
    HOST: str = "0.0.0.0"                               # 바인딩할 네트워크 인터페이스 (0.0.0.0은 모든 IP 허용)

    # 3. AI 보안 및 가드레일 제약 설정
    SECRET_KEY: str = "default-insecure-secret-key-change-in-production"  # JWT 서명 및 암호화에 사용되는 시크릿 키
    MAX_INPUT_LENGTH: int = 2000                        # 입력 프롬프트 최대 허용 글자 수 (DoS/버퍼 오버플로우 방지)
    MAX_OUTPUT_LENGTH: int = 4000                       # AI 생성 응답 최대 허용 글자 수
    ENABLE_HOT_RELOAD: bool = True                      # 보안 룰 수정 시 서버 재시작 없이 메모리 캐시 갱신 허용 여부

    # 4. 데이터베이스(PostgreSQL 16) 설정
    POSTGRES_HOST: str = "postgres"                     # 데이터베이스 호스트명 (Docker 컨테이너명 또는 IP)
    POSTGRES_PORT: int = 5432                           # 데이터베이스 포트
    POSTGRES_USER: str = "guardrail_admin"              # 데이터베이스 계정명
    POSTGRES_PASSWORD: str = "change_me_securely"       # 데이터베이스 비밀번호
    POSTGRES_DB: str = "guardrail_db"                   # 데이터베이스 데이터셋 이름
    DATABASE_URL: str | None = None                     # 전체 DB 접속 URL (직접 지정 시 우선 적용)

    # 5. 로컬 언어 모델 (Ollama SLM) 연동 설정
    OLLAMA_BASE_URL: str = "http://127.0.0.1:11434"     # Ollama API 기본 접속 URL
    OLLAMA_MODEL: str = "qwen2.5:7b"                    # 우선 사용할 SLM 모델명
    OLLAMA_TIMEOUT_SECONDS: int = 25                    # LLM 추론 타임아웃 제한 시간(초)
    ENABLE_MOCK_FALLBACK: bool = True                   # Ollama 오프라인 시 동적 문맥 추론 엔진으로 폴백 허용 여부

    # 6. 시스템 로깅 레벨
    LOG_LEVEL: str = "INFO"                             # 로그 레벨 (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    # Pydantic 설정: .env 파일 자동 로딩 및 대소문자 구분 규칙 정의
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    def get_database_url(self) -> str:
        """데이터베이스 비동기(asyncpg) 접속 URL 문자열을 생성하여 반환합니다.

        Returns:
            str: 'postgresql+asyncpg://user:password@host:port/db' 형식의 연결 URL
        """
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


# 어디서든 `from app.core.config import settings` 로 가져다 쓸 수 있는 싱글톤 인스턴스 생성
settings = Settings()
