"""Central configuration for OfferShield.

All values are environment driven. No secrets are hardcoded. The application
must remain fully functional when every optional API key is absent.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


class Config:
    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    MAX_UPLOAD_MB = _env_int("MAX_UPLOAD_MB", 5)
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024
    MAX_TEXT_CHARS = _env_int("MAX_TEXT_CHARS", 50_000)

    # Storage / privacy
    DATA_DIR = Path(os.getenv("DATA_DIR") or (BASE_DIR / "data"))
    DB_PATH = Path(os.getenv("DB_PATH") or (DATA_DIR / "offershield.sqlite3"))
    CASE_TTL_HOURS = _env_int("CASE_TTL_HOURS", 24)
    DOC_INDEX_TTL_DAYS = _env_int("DOC_INDEX_TTL_DAYS", 90)

    # Network intelligence
    NETWORK_CHECKS_ENABLED = _env_bool("NETWORK_CHECKS_ENABLED", True)
    DOMAIN_TIMEOUT = _env_int("DOMAIN_TIMEOUT", 6)
    RDAP_URL_TEMPLATE = os.getenv("RDAP_URL_TEMPLATE", "https://rdap.org/domain/{domain}")

    # Optional AI explanations (OpenAI-compatible)
    AI_API_KEY = os.getenv("AI_API_KEY", "").strip()
    AI_BASE_URL = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")
    AI_TIMEOUT = _env_int("AI_TIMEOUT", 30)

    # Optional reputation providers
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()

    # Upload rules
    ALLOWED_UPLOAD_EXTENSIONS = {"pdf"}
    PDF_MAGIC = b"%PDF-"

    @classmethod
    def snapshot(cls) -> dict:
        """Return a plain dict safe to pass into worker threads/tests."""
        keys = [
            "MAX_UPLOAD_MB",
            "MAX_TEXT_CHARS",
            "CASE_TTL_HOURS",
            "DOC_INDEX_TTL_DAYS",
            "NETWORK_CHECKS_ENABLED",
            "DOMAIN_TIMEOUT",
            "RDAP_URL_TEMPLATE",
            "AI_API_KEY",
            "AI_BASE_URL",
            "AI_MODEL",
            "AI_TIMEOUT",
            "VIRUSTOTAL_API_KEY",
            "SAFE_BROWSING_API_KEY",
            "DATA_DIR",
            "DB_PATH",
        ]
        return {key: getattr(cls, key) for key in keys}
