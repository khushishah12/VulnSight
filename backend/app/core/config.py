"""Typed application settings loaded from environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Server-side configuration.

    Values come from environment variables or ``backend/.env``. Secrets must
    never be sent to the React application.
    """

    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "VulnSight API"
    app_version: str = "0.1.0"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    frontend_origins: str = (
        "http://localhost:5173,http://127.0.0.1:5173"
    )
    database_url: str = ""

    # Lean MVP safety controls. Only these hostnames may be scanned.
    # Keep this list narrow and explicit; do not use wildcards.
    scan_allowed_hosts: str = "127.0.0.1,localhost,::1"
    scan_max_targets: int = 10
    scan_allow_loopback_for_testing: bool = True

    # Scan execution mode: "placeholder" (lifecycle test) or "recon" (active reconnaissance)
    scan_executor_mode: str = "recon"

    # Reconnaissance safety and performance controls
    recon_request_timeout: float = 8.0
    recon_max_redirects: int = 5
    recon_max_endpoints_per_target: int = 50
    recon_rate_limit_delay: float = 0.05
    recon_user_agent: str = (
        "VulnSight-Recon/0.1.0 (+https://github.com/vulnsight)"
    )

    @property
    def cors_origins(self) -> list[str]:
        """Return the allowed browser origins as a clean list."""

        return [
            origin.strip()
            for origin in self.frontend_origins.split(",")
            if origin.strip()
        ]

    @property
    def allowed_target_hosts(self) -> list[str]:
        """Return normalized hostnames that scans may target."""

        return [
            host.strip().lower().rstrip(".")
            for host in self.scan_allowed_hosts.split(",")
            if host.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    """Create the settings object once per process."""

    return Settings()


settings = get_settings()
