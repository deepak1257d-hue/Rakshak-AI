import json
from urllib.parse import urlsplit
from pathlib import Path
from typing import Optional, List, Union

from pydantic import model_validator, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "AEGIS AI - Enterprise CTEM Platform"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 # 1 day
    CORS_ORIGINS: Union[List[str], str] = ["http://localhost:3000"]

    # Environment & Ownership Verification Lab Controls
    ENV: str = "development"
    DEV_LAB_HOSTS: List[str] = ["localhost", "127.0.0.1", "juice-shop.cyber.local"]
    LAB_MODE_ENABLED: bool = True

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./aegis.db"
    POSTGRES_CHECKPOINT_URL: Optional[str] = None

    # GitHub Integration
    GITHUB_TOKEN: Optional[str] = None
    GITHUB_API_URL: str = "https://api.github.com"

    # Security Scanner Binaries Path Overrides (Optional, defaults to system PATH lookup)
    ZAP_PATH: Optional[str] = None
    NUCLEI_PATH: Optional[str] = None
    TRIVY_PATH: Optional[str] = None
    NUCLEI_TEMPLATES_DIR: Optional[str] = None

    # Dual-LLM Simulation / Provider Settings
    OPENAI_API_KEY: Optional[str] = None
    LLM_PARSER_MODEL: str = "gpt-3.5-turbo"
    LLM_REASONING_MODEL: str = "gpt-4o"

    # Langfuse Tracing Configuration
    LANGFUSE_PUBLIC_KEY: Optional[str] = None
    LANGFUSE_SECRET_KEY: Optional[str] = None
    LANGFUSE_HOST: str = "http://localhost:3001"
    LANGFUSE_ENABLED: bool = False

    model_config = SettingsConfigDict(
        case_sensitive=True,
        extra="ignore",
        env_file=Path(__file__).resolve().parents[3] / ".env",
        env_file_encoding="utf-8",
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            v_clean = v.strip()
            if v_clean.startswith("[") and v_clean.endswith("]"):
                try:
                    parsed = json.loads(v_clean)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except Exception:
                    pass
            # Comma-separated strings
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return [str(origin).strip() for origin in v if str(origin).strip()]
        return ["http://localhost:3000"]

    @model_validator(mode="after")
    def validate_cors_origins_and_security(self):
        """
        Production CORS Security Guardrails:
        1. Wildcard '*' is strictly rejected in production when allow_credentials is True.
        2. Origins must be valid absolute HTTP/HTTPS URIs without path, query, or fragment.
        """
        env_lower = self.ENV.lower()
        cleaned = []
        for origin in self.CORS_ORIGINS:
            if origin == "*":
                if env_lower == "production":
                    raise ValueError(
                        "CORS SECURITY ERROR: Wildcard '*' origin is strictly forbidden in production "
                        "when credentials are enabled. Configure explicit frontend origins."
                    )
                cleaned.append("*")
                continue

            parsed = urlsplit(origin)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
                raise ValueError(
                    f"CORS CONFIGURATION ERROR: Invalid origin format '{origin}'. "
                    f"Expected exact format like 'https://example.com' or 'http://localhost:3000'."
                )
            if parsed.path and parsed.path != "/":
                raise ValueError(
                    f"CORS CONFIGURATION ERROR: Origin '{origin}' cannot contain a URL path. "
                    f"Use exact host scheme and netloc only."
                )
            if parsed.query or parsed.fragment:
                raise ValueError(
                    f"CORS CONFIGURATION ERROR: Origin '{origin}' cannot contain query parameters or fragments."
                )
            # Normalize to scheme://netloc without trailing slash
            cleaned.append(f"{parsed.scheme.lower()}://{parsed.netloc}")

        self.CORS_ORIGINS = cleaned
        return self

    @model_validator(mode="after")
    def validate_lab_mode_environment(self):
        """
        Critical security boundary: Lab mode and DEV_LAB_HOSTS bypasses
        are strictly forbidden when ENV != 'development'.
        """
        if self.ENV.lower() != "development":
            if self.LAB_MODE_ENABLED and len(self.DEV_LAB_HOSTS) > 0:
                raise ValueError(
                    f"CRITICAL SECURITY CONFIGURATION ERROR: Lab mode bypass is forbidden when "
                    f"ENV is '{self.ENV}'. ENV must be 'development' to enable DEV_LAB_HOSTS."
                )
        return self

settings = Settings()
