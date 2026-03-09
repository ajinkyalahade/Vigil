from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SC_",
        env_file=(".env", "backend/.env"),
        extra="ignore",
    )

    bind_host: str = "127.0.0.1"
    bind_port: int = 8000

    # Relative paths are resolved against the repo root in create_app().
    db_path: Path = Path("data/security-check.db")
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    api_token: str | None = None

    osv_api_base: str = "https://api.osv.dev"
    enable_deep_scans: bool = Field(default=False)

    # AI Resolution settings
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-4-5-20250929"
    anthropic_max_tokens: int = 4096
    anthropic_timeout_seconds: int = 30

    # Rate limiting for AI resolutions
    resolution_rate_limit: int = 10  # per minute
    resolution_daily_quota: int = 100

    # Feature flags
    disable_ai_resolution: bool = False
    ai_resolution_cache_ttl: int = 86400  # 24 hours in seconds

    # Agent execution settings
    execution_enabled: bool = True
    execution_step_timeout_seconds: int = 60


def get_settings() -> Settings:
    return Settings()
