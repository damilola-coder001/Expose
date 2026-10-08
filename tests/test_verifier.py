"""Unit and integration tests for Phase 15 - VERIFY FIX."""

import pytest
import httpx

from expose.api.app import app
from expose.api.routes import SCAN_STORE
from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    ObservationStatus,
    ProbeStatus,
    ScanResult,
    Severity,
    TargetScope,
    VerificationStatus,
)
from expose.core.scoring import calculate_score_card
from expose.core.verifier import FindingVerifier
from expose.probes import BaseProbe


class MockStillVulnerableProbe(BaseProbe):
    """Simulates a probe run where the weakness remains unfixed on the target."""
    @property
    def name(self) -> str:
        return "http_headers"

    @property
    def category(self) -> Category:
        return Category.BROWSER_SECURITY

    @property
    def description(self) -> str:
        return "Mock probe still vulnerable"

    async def execute(self, target: TargetScope) -> list[Finding]:
        return [
            Finding(
                id="EXP-CSP-FLAW",
                probe=self.name,
                target=target.normalized_url,
                category=Category.BROWSER_SECURITY,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                title="Missing Content-Security-Policy (CSP) Header",
                description="The target does not deliver a CSP header.",
                remediation="Configure CSP header",
                rule_id="RULE-CSP-01",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary="HTTP GET / returned 200 without Content-Security-Policy header",
                ),
            )
        ]


class MockFixedProbe(BaseProbe):
    """Simulates a probe run where the developer fixed the issue and CSP is now detected."""
    @property
    def name(self) -> str:
        return "http_headers"

    @property
    def category(self) -> Category:
        return Category.BROWSER_SECURITY

    @property
    def description(self) -> str:
        return "Mock probe fixed"

    async def execute(self, target: TargetScope) -> list[Finding]:
        return [
            Finding(
                id="EXP-CSP-FIXED",
                probe=self.name,
                target=target.normalized_url,
                category=Category.BROWSER_SECURITY,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.OBSERVED,
                title="Content-Security-Policy (CSP) Header Configured",
                description="The target delivers a valid Content-Security-Policy header.",
                remediation="",
                rule_id="RULE-CSP-01",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary="HTTP GET / returned Content-Security-Policy: default-src 'self'",
                ),
            )
        ]


def create_test_scan_with_finding() -> tuple[ScanResult, Finding]:
    target = TargetScope(
        raw_target="https://example.com",
        normalized_url="https://example.com",
        scheme="https",
        host="example.com",
        port=443,
        resolved_ips=["93.184.216.34"],
        is_private=False,
    )
    flaw = Finding(
        id="EXP-CSP-FLAW",
        probe="http_headers",
        target="https://example.com",
        category=Category.BROWSER_SECURITY,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        status=ObservationStatus.CONFIRMED,
        title="Missing Content-Security-Policy (CSP) Header",
        description="The target does not deliver a CSP header.",
        remediation="Configure CSP header",
        rule_id="RULE-CSP-01",
        evidence=Evidence(
            type=EvidenceType.HTTP_EXCHANGE,
            summary="Original scan: CSP header absent",
        ),
    )
    scan = ScanResult(
        scan_id="scn_verify_test",
        target=target,
        findings=[flaw],
        probe_statuses=[ProbeStatus(probe_name="http_headers", status="completed", duration_seconds=0.5)],
    )
    scan.score_card = calculate_score_card(scan.findings)
    return scan, flaw


@pytest.mark.asyncio
async def test_verify_fix_still_vulnerable():
    scan, flaw = create_test_scan_with_finding()
    score_initial = scan.score_card.overall_score

    # Use probe where flaw is still present
    verifier = FindingVerifier(custom_probes={"http_headers": MockStillVulnerableProbe()})
    result = await verifier.verify_finding(scan, flaw.id)

    # Must NOT mark fixed without empirical proof
    assert result.status == VerificationStatus.STILL_VULNERABLE
    assert result.score_delta == 0
    assert result.score_after == score_initial
    assert flaw.status == ObservationStatus.CONFIRMED
    assert "persists" in result.message.lower() or "flaw" in result.message.lower()


@pytest.mark.asyncio
async def test_verify_fix_successful_remediation():
    scan, flaw = create_test_scan_with_finding()
    score_initial = scan.score_card.overall_score

    # Use probe where issue has been fixed
    verifier = FindingVerifier(custom_probes={"http_headers": MockFixedProbe()})
    result = await verifier.verify_finding(scan, flaw.id)

    # Must be marked FIXED with fresh evidence and increased score
    assert result.status == VerificationStatus.FIXED
    assert result.score_after > score_initial
    assert result.score_delta > 0
    assert flaw.status == ObservationStatus.FIXED
    assert "default-src 'self'" in result.after_evidence.summary
    assert len(flaw.verification_history) == 1


@pytest.mark.asyncio
async def test_verify_fix_api_endpoint():
    scan, flaw = create_test_scan_with_finding()
    SCAN_STORE[scan.scan_id] = scan

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Nonexistent finding returns 404
        bad_resp = await client.post(f"/api/v1/scans/{scan.scan_id}/findings/NONEXISTENT/verify")
        assert bad_resp.status_code == 404

        # Nonexistent scan returns 404
        bad_scan = await client.post("/api/v1/scans/NONEXISTENT/findings/EXP-CSP-FLAW/verify")
        assert bad_scan.status_code == 404
