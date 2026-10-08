"""Unit and integration tests for Phase 16 - SECURITY HISTORY & DIFFS."""

from datetime import datetime, timezone
import pytest
import httpx

from expose.api.app import app
from expose.api.routes import SCAN_STORE
from expose.core.history import (
    FindingDiffType,
    TargetHistoryStore,
    get_history_store,
)
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
)
from expose.core.scoring import calculate_score_card


def create_finding(fid: str, title: str, severity: Severity, rule_id: str, status: ObservationStatus = ObservationStatus.CONFIRMED) -> Finding:
    return Finding(
        id=fid,
        probe="http_headers",
        target="https://myapp.com",
        category=Category.BROWSER_SECURITY,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        status=status,
        title=title,
        description=f"Desc for {title}",
        remediation="Fix it",
        rule_id=rule_id,
        evidence=Evidence(type=EvidenceType.HTTP_EXCHANGE, summary=f"Evidence for {title}"),
    )


def create_scan(scan_id: str, findings: list[Finding]) -> ScanResult:
    target = TargetScope(
        raw_target="https://myapp.com",
        normalized_url="https://myapp.com",
        scheme="https",
        host="myapp.com",
        port=443,
        resolved_ips=["1.2.3.4"],
    )
    s = ScanResult(
        scan_id=scan_id,
        target=target,
        findings=findings,
        probe_statuses=[ProbeStatus(probe_name="http_headers", status="completed", duration_seconds=0.2)],
    )
    s.score_card = calculate_score_card(s.findings)
    return s


def test_target_history_and_diff_computation():
    store = TargetHistoryStore()

    # Scan #1: Score 70 (2 flaws: CSP and HSTS missing)
    f_csp = create_finding("EXP-CSP", "Missing CSP", Severity.MEDIUM, "RULE-CSP")
    f_hsts = create_finding("EXP-HSTS", "Missing HSTS", Severity.HIGH, "RULE-HSTS")
    scan1 = create_scan("scn_001", [f_csp, f_hsts])
    store.record_scan(scan1)

    history = store.get_history("myapp.com")
    assert len(history) == 1
    assert history[0].scan_id == "scn_001"
    score1 = history[0].score

    # Baseline diff has all findings as NEW (+)
    baseline_diff = store.compute_diff(scan1)
    assert len(baseline_diff.new_findings) == 2
    assert len(baseline_diff.fixed_findings) == 0

    # Scan #2: HSTS fixed, CSP still present, new exposed admin endpoint
    f_admin = create_finding("EXP-ADMIN", "Exposed Admin Endpoint", Severity.HIGH, "RULE-ADMIN")
    scan2 = create_scan("scn_002", [f_csp, f_admin])
    store.record_scan(scan2)

    history2 = store.get_history("myapp.com")
    assert len(history2) == 2
    assert history2[1].scan_id == "scn_002"

    diff = store.compute_diff(scan2, previous_scan=scan1)
    assert diff.current_scan_id == "scn_002"
    assert diff.previous_scan_id == "scn_001"

    # Check diff types:
    # 1. HSTS missing was in scan1, absent in scan2 -> FIXED (✓)
    fixed_titles = [f.title for f in diff.fixed_findings]
    assert "Missing HSTS" in fixed_titles

    # 2. Exposed Admin is in scan2, absent in scan1 -> NEW (+)
    new_titles = [f.title for f in diff.new_findings]
    assert "Exposed Admin Endpoint" in new_titles

    # 3. Missing CSP is in both -> UNCHANGED
    unchanged_titles = [f.title for f in diff.unchanged_findings]
    assert "Missing CSP" in unchanged_titles


@pytest.mark.asyncio
async def test_history_and_diff_api_endpoints():
    store = get_history_store()
    f_csp = create_finding("EXP-CSP-API", "Missing CSP", Severity.MEDIUM, "RULE-CSP-API")
    scan = create_scan("scn_api_hist", [f_csp])
    store.record_scan(scan)
    SCAN_STORE[scan.scan_id] = scan

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # History endpoint
        resp = await client.get("/api/v1/targets/myapp.com/history")
        assert resp.status_code == 200
        hist_data = resp.json()
        assert len(hist_data) >= 1
        assert any(item["scan_id"] == "scn_api_hist" for item in hist_data)

        # Diff endpoint
        diff_resp = await client.get(f"/api/v1/scans/{scan.scan_id}/diff")
        assert diff_resp.status_code == 200
        diff_data = diff_resp.json()
        assert diff_data["target"] == "myapp.com"
        assert diff_data["current_scan_id"] == scan.scan_id
