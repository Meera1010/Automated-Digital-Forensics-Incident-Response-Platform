"""
ADFIR Platform — Configuration System
======================================
Provides environment-specific configuration classes loaded by the Flask
application factory.  All sensitive values are read exclusively from
environment variables — never hardcoded here.

Usage:
    from backend.config import get_config
    cfg = get_config("development")
"""

import os
from datetime import timedelta


class BaseConfig:
    """
    Shared configuration values inherited by all environment configs.
    Override per-environment values in the subclasses below.
    """

    # ------------------------------------------------------------------
    # Application identity
    # ------------------------------------------------------------------
    APP_NAME: str = "ADFIR Platform"
    APP_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api/v1"

    # ------------------------------------------------------------------
    # Flask core
    # ------------------------------------------------------------------
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "insecure-dev-secret-change-me")
    DEBUG: bool = False
    TESTING: bool = False

    # ------------------------------------------------------------------
    # PostgreSQL / SQLAlchemy
    # ------------------------------------------------------------------
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        "postgresql://adfir_user:adfir_pass@localhost:5432/adfir_db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        # Validate connections before handing them back from the pool.
        "pool_pre_ping": True,
        # Recycle connections after 5 minutes to avoid stale handles.
        "pool_recycle": 300,
        # Keep at most 10 idle connections in the pool.
        "pool_size": 10,
        # Allow up to 5 overflow connections under load.
        "max_overflow": 5,
    }

    # ------------------------------------------------------------------
    # JWT Authentication
    # ------------------------------------------------------------------
    JWT_SECRET_KEY: str = os.environ.get(
        "JWT_SECRET_KEY", "insecure-jwt-secret-change-me"
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(hours=8)
    # Where to look for the token in incoming requests.
    JWT_TOKEN_LOCATION: list = ["headers"]
    JWT_HEADER_NAME: str = "Authorization"
    JWT_HEADER_TYPE: str = "Bearer"

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------
    # Parsed from a comma-separated env var so it works in all envs.
    CORS_ORIGINS: list = os.environ.get(
        "CORS_ORIGINS", "http://localhost:5000"
    ).split(",")

    # ------------------------------------------------------------------
    # Evidence Vault — Cryptography
    # ------------------------------------------------------------------
    # AES-256-GCM master key, hex-encoded (64 hex chars = 32 bytes).
    # The vault derives a unique per-artifact key from this master key.
    AES_MASTER_KEY: str = os.environ.get("AES_MASTER_KEY", "")

    # ------------------------------------------------------------------
    # File Storage Paths (relative to project root)
    # ------------------------------------------------------------------
    EVIDENCE_STORAGE_PATH: str = os.environ.get(
        "EVIDENCE_STORAGE_PATH", "data/evidence"
    )
    REPORTS_STORAGE_PATH: str = os.environ.get(
        "REPORTS_STORAGE_PATH", "data/reports"
    )
    LAB_DATA_PATH: str = os.environ.get("LAB_DATA_PATH", "data/lab")

    # ------------------------------------------------------------------
    # Detection Engine
    # ------------------------------------------------------------------
    # How often (in seconds) the scheduler polls for new unprocessed events.
    DETECTION_POLL_INTERVAL_SECONDS: int = int(
        os.environ.get("DETECTION_POLL_INTERVAL_SECONDS", "5")
    )
    # Time window (seconds) within which a new hit can join an open incident.
    CORRELATION_WINDOW_SECONDS: int = int(
        os.environ.get("CORRELATION_WINDOW_SECONDS", "1800")
    )
    # Maximum number of actions a single response playbook may contain.
    MAX_PLAYBOOK_ACTIONS: int = 10

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO").upper()


# ---------------------------------------------------------------------------


class DevelopmentConfig(BaseConfig):
    """
    Local development configuration.
    Debug mode on, verbose logging, permissive CORS.
    """

    DEBUG = True
    LOG_LEVEL = "DEBUG"

    # Accept any localhost origin during development.
    CORS_ORIGINS = ["http://localhost:5000", "http://127.0.0.1:5000"]

    # A deterministic AES key for development ONLY — never use in production.
    AES_MASTER_KEY: str = os.environ.get(
        "AES_MASTER_KEY",
        "dev0000000000000000000000000000000000000000000000000000000000000001",
    )


# ---------------------------------------------------------------------------


class TestingConfig(BaseConfig):
    """
    Test-suite configuration.
    Uses a separate test database and very short JWT expiry.
    """

    DEBUG = False
    TESTING = True

    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql://adfir_user:adfir_pass@localhost:5432/adfir_test_db",
    )

    # Fixed AES key for reproducible test vectors — not used outside tests.
    AES_MASTER_KEY = (
        "test0000000000000000000000000000000000000000000000000000000000001"
    )

    # Short-lived tokens so expiry tests run fast.
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)

    # Disable background scheduler during tests to avoid side effects.
    SCHEDULER_ENABLED: bool = False


# ---------------------------------------------------------------------------


class ProductionConfig(BaseConfig):
    """
    Production configuration.
    All secrets MUST be provided via environment variables.
    The application will refuse to start if any required variable is missing.
    """

    DEBUG = False
    TESTING = False

    # These will raise KeyError at import time if the vars are not set,
    # which is the desired fail-fast behaviour for production.
    SECRET_KEY: str = os.environ["SECRET_KEY"]
    JWT_SECRET_KEY: str = os.environ["JWT_SECRET_KEY"]
    AES_MASTER_KEY: str = os.environ["AES_MASTER_KEY"]
    SQLALCHEMY_DATABASE_URI: str = os.environ["DATABASE_URL"]


# ---------------------------------------------------------------------------
# Registry — used by create_app() to select the right config class.
# ---------------------------------------------------------------------------

_CONFIG_MAP: dict = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(env: str | None = None) -> type:
    """
    Return the configuration class for the given environment name.

    Args:
        env: One of 'development', 'testing', or 'production'.
             Falls back to the FLASK_ENV environment variable, then 'default'.

    Returns:
        A configuration class (not an instance).
    """
    env = env or os.environ.get("FLASK_ENV", "default")
    return _CONFIG_MAP.get(env, DevelopmentConfig)
