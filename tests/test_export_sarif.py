"""Tests for report export (sanitized JSON & OASIS SARIF v2.1.0) and CI/CD gates (Phases 25 & 26)."""

import json
from datetime import datetime, timezone
from click.testing import CliRunner
import pytest
from fastapi.testclient import TestClient

from expose.api.app import create_app
from expose.api.routes import SCAN_STORE
from expose.cli.main import scan_cmd
from expose.core.export import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    generate_sanitized_json_report,
    generate_sarif_report,
)
from expose.core.models import (
    Confidence,
    EvidenceType,
    Finding,
    FindingCategory,
    ObservationStatus,
    ScanResult,
    ScoreCard,
    Severity,
    TargetScope,
    TechnicalEvidence,
)
from expose.core.attack_surface import AttackSurface, PageAsset


@pytest.fixture
def mock_scan_result() -> ScanResult:
    target = TargetScope(
        raw_target="https://example.com",
        normalized_url="https://example.com/",
        host="example.com",
        resolved_ips=["93.184.216.34"],
        port=443,
        scheme="https",
        is_private=False,
    )
    finding1 = Finding(
        id="EXP-TLS-001",
        probe="tls_posture",
        target="example.com",
        title="Insecure TLS 1.0 Enabled",
        category=FindingCategory.TLS_POSTURE,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        description="Legacy TLS 1.0 protocol negotiation accepted.",
        remediation="Disable TLS 1.0 and 1.1 on load balancers.",
        evidence=TechnicalEvidence(
            type=EvidenceType.TLS_HANDSHAKE,
            summary="TLS 1.0 accepted",
            raw_data={"supported_protocols": ["TLSv1.0", "TLSv1.2", "TLSv1.3"]},
        ),
    )
    finding2 = Finding(
        id="EXP-HDR-001",
        probe="http_headers",
        target="example.com",
        title="Missing Content-Security-Policy",
        category=FindingCategory.HTTP_HEADERS,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        description="Content-Security-Policy header is absent.",
        remediation="Configure a strict CSP.",
        evidence=TechnicalEvidence(
            type=EvidenceType.HTTP_EXCHANGE,
            summary="Header absent in response",
            raw_data={"missing_header": "Content-Security-Policy"},
        ),
    )
    score_card = ScoreCard(
        overall_score=78,
        letter_grade="C",
    )
    return ScanResult(
        scan_id="scn_export_test",
        target=target,
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        duration_seconds=2.15,
        score_card=score_card,
        findings=[finding1, finding2],
    )


def test_generate_sanitized_json_report(mock_scan_result):
    report = generate_sanitized_json_report(mock_scan_result)

    assert report["report_type"] == "security_intelligence_report"
    assert report["scan_metadata"]["scan_id"] == "scn_export_test"
    assert report["summary"]["overall_score"] == 78
    assert report["summary"]["high"] == 1
    assert report["summary"]["medium"] == 1
    assert len(report["findings"]) == 2

    # Verify zero backend secret leakage
    serialized = json.dumps(report)
    for forbidden in ["postgres:", "redis://", "expose_s3_secret", "s3_access_key", "AI_API_KEY"]:
        assert forbidden not in serialized


def test_generate_sanitized_json_report_with_attack_surface(mock_scan_result):
    """JSON export must support the current AttackSurface model."""
    mock_scan_result.attack_surface = AttackSurface(
        target=mock_scan_result.target.normalized_url,
        pages=[PageAsset(url="https://example.com/", path="/", is_internal=True, discovered_via="test")],
    )

    report = generate_sanitized_json_report(mock_scan_result)

    assert report["attack_surface_summary"]["pages_count"] == 1
    assert report["attack_surface_summary"]["technologies"] == []


def test_generate_sarif_report(mock_scan_result):
    sarif = generate_sarif_report(mock_scan_result)

    assert sarif["$schema"] == SARIF_SCHEMA_URI
    assert sarif["version"] == SARIF_VERSION
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Expose"
    assert len(driver["rules"]) == 2

    results = sarif["runs"][0]["results"]
    assert len(results) == 2

    # High severity should be SARIF 'error'
    high_res = next(r for r in results if r["ruleId"] == "EXP-TLS-001")
    assert high_res["level"] == "error"
    assert "https://example.com/" in high_res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    # Medium severity should be SARIF 'warning'
    med_res = next(r for r in results if r["ruleId"] == "EXP-HDR-001")
    assert med_res["level"] == "warning"


def test_export_api_endpoints(mock_scan_result):
    app = create_app()
    client = TestClient(app)

    # Place mock scan in store
    SCAN_STORE["scn_export_test"] = mock_scan_result

    # 1. JSON Export
    json_res = client.get("/api/v1/scans/scn_export_test/export/json")
    assert json_res.status_code == 200
    data = json_res.json()
    assert data["scan_metadata"]["scan_id"] == "scn_export_test"
    assert "attachment" in json_res.headers.get("content-disposition", "")

    # 2. SARIF Export
    sarif_res = client.get("/api/v1/scans/scn_export_test/export/sarif")
    assert sarif_res.status_code == 200
    assert "application/sarif+json" in sarif_res.headers.get("content-type", "")
    sarif_data = sarif_res.json()
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "Expose"


def test_cli_sarif_and_min_score_options(tmp_path):
    runner = CliRunner()
    sarif_out = str(tmp_path / "test-report.sarif")

    # Target invalid loopback without --allow-private should fail safety (exit 2)
    res_fail = runner.invoke(scan_cmd, ["http://127.0.0.1", "--sarif", sarif_out])
    assert res_fail.exit_code == 2
