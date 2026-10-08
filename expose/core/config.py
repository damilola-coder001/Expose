"""Centralized configuration management and secret hygiene for Expose.

Enforces strict separation between server-side credentials and client-facing interfaces.
Backend secrets (database passwords, Redis connection strings, AI keys, S3 secrets)
are NEVER exposed to frontend clients or serialized into public API responses.
"""

import os
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExposeConfig(BaseModel):
    """Runtime server configuration with environment variable defaults."""

    # Core Services
    database_url: str = Field(
        default="postgres://expose:expose_secure_pass@localhost:5432/expose?sslmode=disable",
        description="PostgreSQL connection string"
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis queue & cache connection string"
    )
    ai_api_key: Optional[str] = Field(
        default=None,
        description="API key for grounded AI intelligence provider"
    )

    # Object Storage (Evidence captures, HAR files, screenshots)
    s3_endpoint: str = Field(default="http://localhost:9000")
    s3_access_key: str = Field(default="expose_s3_access")
    s3_secret_key: str = Field(default="expose_s3_secret")
    s3_bucket: str = Field(default="expose-evidence")
    s3_region: str = Field(default="us-east-1")

    # Worker Settings
    browser_worker_url: str = Field(default="http://localhost:3001")
    worker_max_memory_mb: int = Field(default=512)
    worker_cpu_quota: float = Field(default=1.0)

    # Abuse Prevention & Rate Limiting (Phase 18)
    rate_limit_per_minute: int = Field(default=10)
    rate_limit_per_hour: int = Field(default=60)
    target_cooldown_seconds: int = Field(default=30)
    max_concurrent_scans: int = Field(default=5)
    max_queue_depth: int = Field(default=50)
    scan_timeout_seconds: int = Field(default=45)
    allow_private: bool = Field(default=False)

    # Runtime Env
    env: str = Field(default="development")
    log_level: str = Field(default="info")
    port: int = Field(default=8000)
    host: str = Field(default="127.0.0.1")
    cors_allowed_origins: List[str] = Field(
        default=["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:3000"],
        description="Allowed origins for strict CORS policy"
    )

    @classmethod
    def load_from_env(cls) -> "ExposeConfig":
        """Loads configuration from environment variables with safe defaults."""
        runtime_env = os.getenv("ENV") or (
            "production" if (os.getenv("VERCEL") or os.getenv("VERCEL_ENV")) else "development"
        )
        raw_origins = os.getenv("CORS_ALLOWED_ORIGINS", "")
        if raw_origins:
            origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
        elif runtime_env.lower() in {"production", "prod"}:
            # The web UI and API share an origin in production. Defaulting to
            # no cross-origin access is safer than silently permitting every site.
            origins = []
        else:
            origins = [
                "http://localhost:8000",
                "http://127.0.0.1:8000",
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            ]
        return cls(
            database_url=os.getenv("DATABASE_URL", "postgres://expose:expose_secure_pass@localhost:5432/expose?sslmode=disable"),
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            ai_api_key=os.getenv("AI_API_KEY"),
            s3_endpoint=os.getenv("S3_ENDPOINT", "http://localhost:9000"),
            s3_access_key=os.getenv("S3_ACCESS_KEY", "expose_s3_access"),
            s3_secret_key=os.getenv("S3_SECRET_KEY", "expose_s3_secret"),
            s3_bucket=os.getenv("S3_BUCKET_NAME", "expose-evidence"),
            s3_region=os.getenv("S3_REGION", "us-east-1"),
            browser_worker_url=os.getenv("BROWSER_WORKER_URL", "http://localhost:3001"),
            worker_max_memory_mb=int(os.getenv("WORKER_MAX_MEMORY_MB", "512")),
            worker_cpu_quota=float(os.getenv("WORKER_CPU_QUOTA", "1.0")),
            rate_limit_per_minute=int(os.getenv("EXPOSE_RATE_LIMIT_PER_MINUTE", "10")),
            rate_limit_per_hour=int(os.getenv("EXPOSE_RATE_LIMIT_PER_HOUR", "60")),
            target_cooldown_seconds=int(os.getenv("EXPOSE_TARGET_COOLDOWN_SECONDS", "30")),
            max_concurrent_scans=int(os.getenv("EXPOSE_MAX_CONCURRENT_SCANS", "5")),
            max_queue_depth=int(os.getenv("EXPOSE_MAX_QUEUE_DEPTH", "50")),
            scan_timeout_seconds=int(os.getenv("EXPOSE_SCAN_TIMEOUT_SECONDS", "45")),
            allow_private=os.getenv("EXPOSE_ALLOW_PRIVATE", "false").lower() in ("1", "true", "yes"),
            env=runtime_env,
            log_level=os.getenv("LOG_LEVEL", "info"),
            port=int(os.getenv("PORT", "8000")),
            host=os.getenv("HOST", "127.0.0.1"),
            cors_allowed_origins=origins,
        )

    def get_client_safe_telemetry(self) -> Dict[str, Any]:
        """Returns non-sensitive metadata safe for public frontend telemetry.
        
        Guarantees that DATABASE_URL, REDIS_URL, AI_API_KEY, and S3 credentials
        are completely excluded.
        """
        return {
            "version": "1.0.0",
            "env": self.env,
            # Serverless functions cannot reliably retain the in-memory async
            # scan store between requests. The browser uses this flag to select
            # a same-request scan flow on Vercel.
            "serverless_runtime": bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV")),
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "scan_timeout_seconds": self.scan_timeout_seconds,
            "max_concurrent_scans": self.max_concurrent_scans,
            "target_cooldown_seconds": self.target_cooldown_seconds,
        }


# Singleton config instance
_CONFIG_INSTANCE: Optional[ExposeConfig] = None


def get_config() -> ExposeConfig:
    """Returns the cached global configuration instance."""
    global _CONFIG_INSTANCE
    if _CONFIG_INSTANCE is None:
        _CONFIG_INSTANCE = ExposeConfig.load_from_env()
    return _CONFIG_INSTANCE
