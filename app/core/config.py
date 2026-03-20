"""
THREATSHIELD — app/core/config.py
Centralised settings loaded from .env
Compatible with pydantic-settings v2 + Python 3.13
"""

from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import Optional
from functools import lru_cache


class Settings(BaseSettings):
    # ── App ──────────────────────────────────────────────
    APP_NAME: str = "ThreatShield"
    APP_VERSION: str = "2.4.1"
    APP_ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "change-this-in-production-must-be-32-chars-min"

    # Store as plain str in .env, parsed to list by validator
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:4173,http://127.0.0.1:5173"

    # ── Database ─────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./threatshield.db"

    # ── Redis ────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── Rate Limiting ────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 30
    RATE_LIMIT_PER_HOUR: int = 200

    # ── File Upload ──────────────────────────────────────
    MAX_UPLOAD_SIZE_MB: int = 50
    UPLOAD_DIR: str = "./uploads"
    # Plain string in .env — parsed to list via property below
    ALLOWED_EXTENSIONS: str = ".apk,.exe,.pdf,.zip,.rar,.dmg,.msi,.js,.html,.bat,.sh,.ps1"

    # ── Timeouts ─────────────────────────────────────────
    URL_SCAN_TIMEOUT_SECONDS: int = 15
    FILE_SCAN_TIMEOUT_SECONDS: int = 30
    APK_SCAN_TIMEOUT_SECONDS: int = 45

    # ── External APIs ────────────────────────────────────
    VIRUSTOTAL_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    IPQS_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None

    # ── YARA ─────────────────────────────────────────────
    YARA_RULES_DIR: str = "./app/core/yara_rules"

    # ── JWT ──────────────────────────────────────────────
    JWT_SECRET: str = "change-this-jwt-secret"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    # ── Celery ───────────────────────────────────────────
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }

    # ── Computed list properties ──────────────────────────
    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    @property
    def allowed_extensions_list(self) -> list[str]:
        return [e.strip() for e in self.ALLOWED_EXTENSIONS.split(",") if e.strip()]

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def has_virustotal(self) -> bool:
        return bool(self.VIRUSTOTAL_API_KEY and self.VIRUSTOTAL_API_KEY.strip())

    @property
    def has_urlscan(self) -> bool:
        return bool(self.URLSCAN_API_KEY and self.URLSCAN_API_KEY.strip())

    @property
    def has_google_safebrowsing(self) -> bool:
        return bool(self.GOOGLE_SAFE_BROWSING_API_KEY and self.GOOGLE_SAFE_BROWSING_API_KEY.strip())

    @property
    def has_abuseipdb(self) -> bool:
        return bool(self.ABUSEIPDB_API_KEY and self.ABUSEIPDB_API_KEY.strip())


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

