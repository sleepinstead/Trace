"""Application settings, loaded from environment variables or .env."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR.parent / ".env",
        env_prefix="TRACE_",
        extra="ignore",
    )

    database_path: Path = BASE_DIR / "data" / "trace.sqlite"
    model_dir: Path = BASE_DIR / "app" / "ml" / "artifacts"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Active network analysis
    http_timeout: float = 8.0
    max_redirects: int = 10
    max_page_bytes: int = 512_000
    # Refuse to connect to private / loopback / link-local addresses (SSRF guard).
    allow_private_targets: bool = False
    user_agent: str = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0 Safari/537.36 Trace/1.0"
    )

    # Threat intelligence (all optional; a provider is enabled when its key is set)
    intel_cache_ttl_hours: int = 6
    virustotal_api_key: str | None = None
    google_safe_browsing_api_key: str | None = None
    urlhaus_auth_key: str | None = None
    phishtank_app_key: str | None = None
    phishtank_username: str = "trace"


@lru_cache
def get_settings() -> Settings:
    return Settings()
