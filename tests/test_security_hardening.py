"""Tests for security of Expose itself, defensive headers, and zero-trust input sanitization (Phase 22)."""

import pytest
from fastapi.testclient import TestClient

from expose.api.app import create_app
from expose.api.security_middleware import sanitize_target_url, sanitize_text
from expose.core.config import ExposeConfig


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_sanitize_text_strips_control_chars_and_escapes():
    # Null byte and escape characters
    raw = "Hello\x00World\x08<script>alert(1)</script>"
    clean = sanitize_text(raw)
    assert "\x00" not in clean
    assert "\x08" not in clean
    assert "<script>" not in clean
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in clean


def test_sanitize_target_url():
    # Traversal and control characters
    malicious = "https://example.com/../../secret\x00"
    cleaned = sanitize_target_url(malicious)
    assert "\x00" not in cleaned
    assert ".." not in cleaned
    assert "example.com" in cleaned


def test_security_headers_present_on_endpoints(client):
    response = client.get("/health")
    assert response.status_code == 200

    headers = response.headers
    # 1. X-Request-ID distributed tracing
    assert "x-request-id" in headers
    assert headers["x-request-id"].startswith("req_")

    # 2. Content-Security-Policy
    assert "content-security-policy" in headers
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "script-src 'self' 'unsafe-inline'" not in csp

    # 3. MIME sniffing defense
    assert headers.get("x-content-type-options") == "nosniff"

    # 4. Clickjacking defense
    assert headers.get("x-frame-options") == "DENY"

    # 5. HSTS
    assert "max-age=31536000" in headers.get("strict-transport-security", "")

    # 6. Permissions-Policy
    assert "geolocation=()" in headers.get("permissions-policy", "")
    assert "camera=()" in headers.get("permissions-policy", "")

    # 7. Sensitive API responses are never cacheable and remain isolated.
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert headers["cache-control"] == "no-store, max-age=0"


def test_invalid_request_id_is_replaced(client):
    response = client.get("/health", headers={"X-Request-ID": "bad\r\nheader"})
    assert response.status_code == 200
    assert response.headers["x-request-id"].startswith("req_")


def test_production_config_defaults_to_same_origin(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)

    config = ExposeConfig.load_from_env()

    assert config.env == "production"
    assert config.cors_allowed_origins == []


def test_audit_logging_on_mutating_requests(client, caplog):
    import logging
    caplog.set_level(logging.INFO)

    # Post invalid scan target to trigger 400
    res = client.post("/api/v1/scans", json={"target": "http://127.0.0.1"})
    
    # Audit log should record the mutating action
    audit_logs = [r.message for r in caplog.records if "AUDIT_LOG" in r.message]
    assert len(audit_logs) > 0
    assert any("POST /api/v1/scans" in log for log in audit_logs)
