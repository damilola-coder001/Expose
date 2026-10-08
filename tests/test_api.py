"""Integration tests for the Expose REST API."""

import pytest
import httpx
from expose.api.app import app
from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    ProbeStatus,
    ScanResult,
    Severity,
    TargetScope,
)
from expose.api.routes import SCAN_STORE


@pytest.fixture
def sample_scan_result():
    target = TargetScope(
        raw_target="https://test.local",
        normalized_url="https://test.local",
        scheme="https",
        host="test.local",
        port=443,
        resolved_ips=["127.0.0.1"],
        is_private=True,
        allow_private=True,
    )
    finding = Finding(
        id="EXP-1234567890AB",
        probe="http_headers",
        target="https://test.local",
        category=Category.TRANSPORT_SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        title="Sample High Finding",
        description="Sample description",
        remediation="Sample remediation",
        evidence=Evidence(
            type=EvidenceType.HTTP_EXCHANGE,
            summary="Test evidence summary",
            response={"status_code": 200, "headers": {"server": "test-srv"}}
        )
    )
    return ScanResult(
        scan_id="scn_test12345",
        target=target,
        duration_seconds=1.23,
        probe_statuses=[ProbeStatus(probe_name="http_headers", status="completed", duration_seconds=1.23)],
        findings=[finding]
    )


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "dns_posture" in data["probes_available"]


@pytest.mark.asyncio
async def test_get_scan_and_evidence(sample_scan_result):
    SCAN_STORE[sample_scan_result.scan_id] = sample_scan_result

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Fetch scan
        resp = await client.get(f"/api/v1/scans/{sample_scan_result.scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == sample_scan_result.scan_id
        assert len(data["findings"]) == 1

        # 2. Fetch specific evidence
        ev_resp = await client.get(
            f"/api/v1/scans/{sample_scan_result.scan_id}/evidence/{sample_scan_result.findings[0].id}"
        )
        assert ev_resp.status_code == 200
        ev_data = ev_resp.json()
        assert ev_data["finding_id"] == sample_scan_result.findings[0].id
        assert ev_data["evidence"]["summary"] == "Test evidence summary"


@pytest.mark.asyncio
async def test_ssrf_error_returns_400():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/scans", json={"target": "http://127.0.0.1", "allow_private": False})
        assert resp.status_code == 400
        assert "Safety Scope Error" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_serve_web_ui():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "Paste any website URL to receive an externally observable security assessment" in resp.text
        assert "EXPOSE" in resp.text


@pytest.mark.asyncio
async def test_scan_intelligence_endpoints(sample_scan_result):
    SCAN_STORE[sample_scan_result.scan_id] = sample_scan_result

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Enrich scan with AI intelligence
        resp = await client.post(f"/api/v1/scans/{sample_scan_result.scan_id}/intelligence")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ai_prioritization"] is not None
        assert len(data["findings"]) > 0
        assert data["findings"][0]["ai_intelligence"] is not None
        assert data["findings"][0]["ai_intelligence"]["explanation"] is not None

        # 2. Enrich a single finding with on-demand AI intelligence
        finding_id = sample_scan_result.findings[0].id
        f_resp = await client.post(f"/api/v1/scans/{sample_scan_result.scan_id}/findings/{finding_id}/intelligence")
        assert f_resp.status_code == 200
        f_data = f_resp.json()
        assert f_data["explanation"] is not None
        assert len(f_data["source_citations"]) >= 1
