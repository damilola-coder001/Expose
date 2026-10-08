"""Integration tests for the scan orchestrator."""

import pytest
from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Severity,
    TargetScope,
)
from expose.core.orchestrator import ScanOrchestrator
from expose.probes.base import BaseProbe
from expose.probes.attack_surface_probe import AttackSurfaceProbe


class MockProbeA(BaseProbe):
    @property
    def name(self) -> str:
        return "mock_probe_a"
    @property
    def category(self) -> Category:
        return Category.TRANSPORT_SECURITY
    @property
    def description(self) -> str:
        return "Mock probe A"
    async def execute(self, target: TargetScope):
        return [
            self.create_finding(
                target=target,
                title="Mock Medium Finding",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                description="Test description",
                remediation="Test remediation",
                evidence=Evidence(type=EvidenceType.RAW_SOCKET, summary="Evidence proof A")
            )
        ]


class MockProbeB(BaseProbe):
    @property
    def name(self) -> str:
        return "mock_probe_b"
    @property
    def category(self) -> Category:
        return Category.CRYPTOGRAPHY
    @property
    def description(self) -> str:
        return "Mock probe B"
    async def execute(self, target: TargetScope):
        return [
            self.create_finding(
                target=target,
                title="Mock Critical Finding",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                description="Critical issue",
                remediation="Fix critical issue",
                evidence=Evidence(type=EvidenceType.CERTIFICATE_METADATA, summary="Evidence proof B")
            )
        ]


@pytest.mark.asyncio
async def test_orchestrator_execution_and_sorting():
    orchestrator = ScanOrchestrator(probes=[MockProbeA(), MockProbeB()])
    
    # Run scan with allow_private for test target
    result = await orchestrator.scan("http://127.0.0.1:8080", allow_private=True)

    assert result.scan_id.startswith("scn_")
    assert result.duration_seconds is not None
    assert len(result.probe_statuses) == 2
    assert all(ps.status == "completed" for ps in result.probe_statuses)
    
    # Verify findings sorting: CRITICAL should be first, followed by MEDIUM
    assert len(result.findings) == 2
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].title == "Mock Critical Finding"
    assert result.findings[1].severity == Severity.MEDIUM
    assert result.findings[1].title == "Mock Medium Finding"

    # Verify severity counts
    counts = result.severity_counts
    assert counts["CRITICAL"] == 1
    assert counts["MEDIUM"] == 1
    assert counts["HIGH"] == 0


class MockAttackSurfaceProbe(AttackSurfaceProbe):
    async def discover_attack_surface(self, target: TargetScope):
        from expose.core.attack_surface import AttackSurface, PageAsset, APIAsset
        surface = AttackSurface(
            target=target.normalized_url,
            exposure_summary="Mock 1 Page, 1 API",
            pages=[PageAsset(url="http://127.0.0.1:8080/", path="/", is_internal=True, discovered_via="mock")],
            apis=[APIAsset(path="/api/v1/health", method="GET", is_public=True)],
        )
        return [], surface


@pytest.mark.asyncio
async def test_orchestrator_populates_attack_surface():
    orchestrator = ScanOrchestrator(probes=[MockAttackSurfaceProbe()])
    result = await orchestrator.scan("http://127.0.0.1:8080", allow_private=True)

    assert result.attack_surface is not None
    assert result.attack_surface.exposure_summary == "Mock 1 Page, 1 API"
    assert len(result.attack_surface.pages) == 1
    assert len(result.attack_surface.apis) == 1
    assert result.attack_surface.apis[0].path == "/api/v1/health"
    assert result.score_card.score_version == "1.0"

