"""Unit tests for Phase 20 - SECRET MANAGEMENT and Phase 19 - WORKER ISOLATION."""

import os
from pathlib import Path
import pytest
import httpx

from expose.api.app import app
from expose.core.config import ExposeConfig, get_config
from expose.core.worker import EphemeralWorkerRunner, ScanJob, WorkerIsolationProfile


def test_env_example_exists_and_has_no_secrets():
    root = Path(__file__).parent.parent
    env_example = root / ".env.example"
    assert env_example.exists(), ".env.example must exist at repo root"

    content = env_example.read_text(encoding="utf-8")
    assert "DATABASE_URL=" in content
    assert "REDIS_URL=" in content
    assert "AI_API_KEY=" in content
    assert "S3_ENDPOINT=" in content
    assert "S3_ACCESS_KEY=" in content
    assert "S3_SECRET_KEY=" in content

    # Explanatory comment about Nuclei must be present
    assert "NOT Nuclei API keys" in content or "not Nuclei" in content.lower()

    # Placeholders only: no live production secrets
    assert "your_gemini_or_anthropic_api_key_here" in content
    assert "postgres://expose:expose_secure_pass@localhost:5432" in content


def test_gitignore_excludes_env_files():
    root = Path(__file__).parent.parent
    gitignore = root / ".gitignore"
    assert gitignore.exists(), ".gitignore must exist at repo root"

    content = gitignore.read_text(encoding="utf-8")
    assert ".env" in content
    assert "!.env.example" in content


def test_client_safe_telemetry_excludes_backend_secrets():
    config = ExposeConfig(
        database_url="postgres://super_secret_db:pass@10.0.0.1:5432/prod",
        redis_url="redis://:secret_redis_pass@10.0.0.2:6379",
        ai_api_key="AI_LIVE_SECRET_KEY_12345",
        s3_secret_key="S3_SUPER_SECRET_KEY_999",
    )

    telemetry = config.get_client_safe_telemetry()
    # Telemetry must NOT leak secrets to frontend clients
    assert "database_url" not in telemetry
    assert "redis_url" not in telemetry
    assert "ai_api_key" not in telemetry
    assert "s3_secret_key" not in telemetry
    assert "pass" not in str(telemetry)
    assert "AI_LIVE_SECRET_KEY_12345" not in str(telemetry)


@pytest.mark.asyncio
async def test_telemetry_api_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/config/telemetry")
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert "rate_limit_per_minute" in data
        assert "database_url" not in data
        assert "ai_api_key" not in data


def test_worker_isolation_profile():
    profile = WorkerIsolationProfile()
    # Workers must have:
    # 1. read-only root filesystem
    assert profile.read_only_filesystem is True
    # 2. no PostgreSQL credentials
    assert profile.has_postgres_access is False
    # 3. execution timeout & resource limits
    assert profile.execution_timeout_seconds <= 60
    assert profile.memory_limit_mb <= 512
    assert profile.cpu_limit <= 1.0
    # 4. drop capabilities / no-new-privileges
    assert profile.no_new_privileges is True
