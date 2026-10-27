"""PromptShield System Configuration"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    PROJECT_NAME: str = "PromptShield LLM Security Gateway"
    VERSION: str = "0.1.0"

    PORT: int = 8080
    HOST: str = "0.0.0.0"

    SHIELD_API_KEY: str = "ps_live_master_key_secret_2026"
    UPSTREAM_LLM_URL: str = "https://api.openai.com/v1"
    UPSTREAM_API_KEY: Optional[str] = None

    # Security Thresholds
    INJECTION_RISK_THRESHOLD: float = 0.65
    BLOCK_ON_INJECTION: bool = True
    REDACT_PII: bool = True
    MAX_TOKEN_BUDGET_PER_REQUEST: int = 4096
    ENABLE_AUDIT_LOGS: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
