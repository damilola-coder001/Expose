"""Tests for continuous target monitoring, regression detection, and alert engine (Phase 27)."""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from expose.api.app import create_app
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
from expose.core.monitoring import (
    MonitoringFrequency,
    MonitoringSchedule,
    RegressionSeverity,
    detect_security_regression,
    get_monitoring_store,
)


def _make_scan(scan_id: str, score: int, findings: list) -> ScanResult:
    target = TargetScope(
        raw_target="https://monitored.example.com",
        normalized_url="https://monitored.example.com/",
        host="monitored.example.com",
        resolved_ips=["1.2.3.4"],
        port=443,
        scheme="https",
        is_private=False,
    )
    score_card = ScoreCard(
        overall_score=score,
        letter_grade="A" if score >= 90 else ("B" if score >= 75 else "D"),
    )
    return ScanResult(
        scan_id=scan_id,
        target=target,
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        duration_seconds=1.5,
        score_card=score_card,
        findings=findings,
    )


def test_detect_security_regression_score_drop():
    # Scan 1: Score 91
    scan1 = _make_scan("scn_prev", 91, [])

    # Scan 2: Score dropped to 68 due to a new High severity flaw
    finding_new = Finding(
        id="EXP-TLS-002",
        probe="tls_posture",
        target="monitored.example.com",
        title="TLS 1.0 Re-enabled",
        category=FindingCategory.TLS_POSTURE,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        description="Deprecated protocol active.",
        remediation="Disable TLS 1.0",
        evidence=TechnicalEvidence(
            type=EvidenceType.TLS_HANDSHAKE,
            summary="TLS 1.0 accepted",
            raw_data={},
        ),
    )
    scan2 = _make_scan("scn_curr", 68, [finding_new])

    alert = detect_security_regression(scan2, previous_scan=scan1)
    assert alert is not None
    assert alert.target_host == "monitored.example.com"
    assert alert.previous_score == 91
    assert alert.current_score == 68
    assert alert.score_delta == -23
    assert alert.severity in (RegressionSeverity.CRITICAL, RegressionSeverity.HIGH)
    assert "91 → 68 SECURITY REGRESSION" in alert.title
    assert "TLS 1.0 Re-enabled" in alert.new_high_findings


def test_no_regression_on_improvement_or_stability():
    # Scan 1: Score 75
    scan1 = _make_scan("scn_1", 75, [])
    # Scan 2: Score 88 (Improvement)
    scan2 = _make_scan("scn_2", 88, [])

    alert = detect_security_regression(scan2, previous_scan=scan1)
    assert alert is None


def test_regression_on_resurfacing_remediated_finding():
    # Previous scan had finding as REMEDIATED
    finding_fixed = Finding(
        id="EXP-HDR-001",
        probe="http_headers",
        target="monitored.example.com",
        title="Missing CSP Header",
        category=FindingCategory.HTTP_HEADERS,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        status=ObservationStatus.REMEDIATED,
        description="Resolved previously.",
        remediation="Strict CSP",
        evidence=TechnicalEvidence(
            type=EvidenceType.HTTP_EXCHANGE,
            summary="Header missing",
            raw_data={},
        ),
    )
    scan1 = _make_scan("scn_1", 85, [finding_fixed])

    # Current scan has finding reappear as CONFIRMED
    finding_broken = finding_fixed.model_copy(update={"status": ObservationStatus.CONFIRMED})
    scan2 = _make_scan("scn_2", 80, [finding_broken])

    alert = detect_security_regression(scan2, previous_scan=scan1)
    assert alert is not None
    assert "Missing CSP Header" in alert.resurfaced_findings


def test_monitoring_api_routes():
    app = create_app()
    client = TestClient(app)

    # 1. Configure schedule
    sched_payload = {
        "frequency": "daily",
        "enabled": True,
        "min_score_threshold": 85,
        "alert_on_new_high": True,
        "alert_on_regression": True,
    }
    post_res = client.post("/api/v1/targets/monitored.example.com/monitor", json=sched_payload)
    assert post_res.status_code == 200
    data = post_res.json()
    assert data["target_host"] == "monitored.example.com"
    assert data["frequency"] == "daily"
    assert data["min_score_threshold"] == 85

    # 2. Retrieve schedule
    get_res = client.get("/api/v1/targets/monitored.example.com/monitor")
    assert get_res.status_code == 200
    assert get_res.json()["min_score_threshold"] == 85

    # 3. List schedules
    list_res = client.get("/api/v1/monitoring/schedules")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1
