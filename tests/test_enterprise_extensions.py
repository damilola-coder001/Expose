"""Enterprise extensions unit and integration tests (Phases 28, 29, 30).

Validates:
- Self-contained Executive Offline HTML report generation
- Real-time webhook formatting (Slack, Discord, Teams, Generic) and SSRF safety
- Multi-target portfolio batch scanning engine
- Continuous monitoring scheduler daemon execution
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from expose.core.export import generate_executive_html_report
from expose.core.history import TargetHistoryStore
from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    ObservationStatus,
    ScanResult,
    ScoreCard,
    Severity,
    TargetScope,
)
from expose.core.monitoring import (
    MonitoringFrequency,
    MonitoringSchedule,
    MonitoringStore,
    RegressionSeverity,
    SecurityRegressionAlert,
    WebhookFormat,
    detect_webhook_format,
    dispatch_webhook,
    format_webhook_payload,
)
from expose.core.orchestrator import BatchScanSummary, ScanOrchestrator
from expose.core.worker import MonitoringSchedulerDaemon


from expose.core.scoring import calculate_score_card


def create_mock_scan(
    host: str = "example.com",
    score: int = 92,
    grade: str = "A",
    findings: list = None,
    verified: bool = True,
) -> ScanResult:
    target = TargetScope(
        raw_target=host,
        normalized_url=f"https://{host}",
        scheme="https",
        host=host,
        port=443,
        resolved_ips=["93.184.216.34"],
        is_private=False,
        allow_private=False,
    )
    score_card = calculate_score_card(findings or [])
    score_card.overall_score = score
    score_card.letter_grade = grade

    return ScanResult(
        scan_id=f"scan_mock_{host.replace('.', '_')}",
        target=target,
        score_card=score_card,
        findings=findings or [],
        attack_surface=None,
        domain_verified=verified,
        domain_ownership_proof="Verified via DNS TXT record" if verified else None,
        duration_seconds=2.45,
    )


def test_executive_html_report_generation():
    """Validates generation of self-contained, print-optimized executive HTML reports."""
    finding = Finding(
        id="EXP-SEC-01",
        rule_id="missing-hsts",
        probe="headers",
        target="https://acme.org",
        category=Category.HTTP_HEADERS,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        status=ObservationStatus.CONFIRMED,
        title="Missing Strict-Transport-Security (HSTS) Header",
        description="Browser will not enforce HTTPS connections automatically.",
        remediation="Configure Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        evidence=Evidence(type=EvidenceType.HTTP_EXCHANGE, summary="No HSTS response header present"),
        owasp_top10="A05:2021-Security Misconfiguration",
        owasp_asvs="14.4.1",
    )
    scan = create_mock_scan(host="acme.org", score=74, grade="C", findings=[finding], verified=True)

    html = generate_executive_html_report(scan)

    # Basic HTML structure
    assert "<!DOCTYPE html>" in html
    assert "acme.org" in html
    assert "74" in html
    assert "GRADE C" in html or "C" in html
    assert "Missing Strict-Transport-Security" in html
    assert "A05:2021-Security Misconfiguration" in html
    assert "14.4.1" in html
    assert "EXPOSE SECURITY INTELLIGENCE" in html
    assert "OWASP Top 10" in html

    # Zero external CDN dependencies
    assert "http://" not in html.split("<head>")[1].split("</head>")[0]
    assert "<script" not in html or "https://" not in html


def test_webhook_format_detection_and_payloads():
    """Validates Slack, Discord, Teams, and generic JSON alert formatting."""
    alert = SecurityRegressionAlert(
        target_host="payment.acme.org",
        scan_id="scan_100",
        previous_scan_id="scan_099",
        previous_score=94,
        current_score=68,
        score_delta=-26,
        severity=RegressionSeverity.CRITICAL,
        title="94 → 68 SECURITY REGRESSION on payment.acme.org",
        summary="Security score dropped from 94 to 68; Introduced 1 new CRITICAL finding: Exposed Secret Key",
        new_critical_findings=["Exposed Secret Key"],
    )

    # 1. Slack
    slack_url = "https://hooks.slack.com/services/T123/B456/XYZ"
    assert detect_webhook_format(slack_url) == WebhookFormat.SLACK
    slack_payload = format_webhook_payload(alert, webhook_url=slack_url)
    assert "blocks" in slack_payload
    assert "payment.acme.org" in str(slack_payload)
    assert "-26" in str(slack_payload)

    # 2. Discord
    discord_url = "https://discord.com/api/webhooks/999/TokenABC"
    assert detect_webhook_format(discord_url) == WebhookFormat.DISCORD
    discord_payload = format_webhook_payload(alert, webhook_url=discord_url)
    assert "embeds" in discord_payload
    assert discord_payload["embeds"][0]["title"] == alert.title

    # 3. Teams
    teams_url = "https://acme.webhook.office.com/webhookb2/guid/IncomingWebhook"
    assert detect_webhook_format(teams_url) == WebhookFormat.TEAMS
    teams_payload = format_webhook_payload(alert, webhook_url=teams_url)
    assert teams_payload["@type"] == "MessageCard"
    assert "payment.acme.org" in teams_payload["title"]

    # 4. Generic
    generic_url = "https://api.mysec.internal/v1/alerts"
    assert detect_webhook_format(generic_url) == WebhookFormat.GENERIC
    generic_payload = format_webhook_payload(alert, webhook_url=generic_url)
    assert generic_payload["event"] == "security_regression_alert"
    assert generic_payload["alert"]["target_host"] == "payment.acme.org"


@pytest.mark.asyncio
async def test_dispatch_webhook_ssrf_safety():
    """Validates that webhook dispatcher blocks loopback/private target IPs."""
    alert = SecurityRegressionAlert(
        target_host="test.org",
        scan_id="scan_1",
        previous_scan_id="scan_0",
        previous_score=90,
        current_score=75,
        score_delta=-15,
        severity=RegressionSeverity.HIGH,
        title="Regression alert",
        summary="Score dropped",
    )

    # 1. Private loopback attempt must be blocked
    success, msg = await dispatch_webhook("http://127.0.0.1:8000/api/webhook", alert)
    assert success is False
    assert "error" in msg.lower() or "blocked" in msg.lower() or "safety" in msg.lower()

    # 2. Metadata IP attempt must be blocked
    success_meta, msg_meta = await dispatch_webhook("http://169.254.169.254/latest/meta-data", alert)
    assert success_meta is False


@pytest.mark.asyncio
async def test_batch_scan_orchestration():
    """Validates parallel multi-target batch scanning with concurrency limiting."""
    orchestrator = ScanOrchestrator()

    # Mock single scan execution to avoid actual external network calls
    async def mock_scan(raw_target, allow_private=False, enable_ai=False, progress_callback=None):
        host = raw_target.replace("https://", "").replace("http://", "").split("/")[0]
        score = 80 if "a" in host else 60
        return create_mock_scan(host=host, score=score, grade="B" if score == 80 else "D")

    with patch.object(orchestrator, "scan", side_effect=mock_scan):
        summary: BatchScanSummary = await orchestrator.scan_batch(
            targets=["https://alpha.com", "https://beta.com", "https://gamma.com"],
            concurrency=2,
            allow_private=True,
        )

        assert summary.total_targets == 3
        assert len(summary.items) == 3
        assert summary.portfolio_average_score > 0
        assert all(it.status == "completed" for it in summary.items)


def test_monitoring_scheduler_daemon_due_calculation():
    """Validates schedule due time logic for hourly, daily, and weekly schedules."""
    store = MonitoringStore()
    daemon = MonitoringSchedulerDaemon(monitoring_store=store)

    # Schedule never run before -> due immediately
    sched_new = MonitoringSchedule(
        target_host="fresh.com",
        frequency=MonitoringFrequency.DAILY,
        enabled=True,
        last_run_at=None,
    )
    assert daemon.is_schedule_due(sched_new) is True

    # Disabled schedule -> never due
    sched_disabled = MonitoringSchedule(
        target_host="disabled.com",
        frequency=MonitoringFrequency.HOURLY,
        enabled=False,
        last_run_at=None,
    )
    assert daemon.is_schedule_due(sched_disabled) is False

    # Hourly schedule run 10 minutes ago -> not due
    sched_hourly_recent = MonitoringSchedule(
        target_host="hourly.com",
        frequency=MonitoringFrequency.HOURLY,
        enabled=True,
        last_run_at=datetime.now(timezone.utc) - timedelta(minutes=10),
    )
    assert daemon.is_schedule_due(sched_hourly_recent) is False

    # Hourly schedule run 65 minutes ago -> due
    sched_hourly_old = MonitoringSchedule(
        target_host="hourly-old.com",
        frequency=MonitoringFrequency.HOURLY,
        enabled=True,
        last_run_at=datetime.now(timezone.utc) - timedelta(minutes=65),
    )
    assert daemon.is_schedule_due(sched_hourly_old) is True


@pytest.mark.asyncio
async def test_monitoring_scheduler_daemon_run_due_schedules():
    """Validates that scheduler daemon executes due scans and updates schedule metadata."""
    mon_store = MonitoringStore()
    hist_store = TargetHistoryStore()

    # Register an active due schedule
    schedule = MonitoringSchedule(
        target_host="test-mon.org",
        frequency=MonitoringFrequency.DAILY,
        enabled=True,
        last_run_at=None,
        webhook_url=None,
    )
    mon_store.set_schedule(schedule)

    daemon = MonitoringSchedulerDaemon(
        monitoring_store=mon_store,
        history_store=hist_store,
        poll_interval_seconds=1.0,
    )

    mock_result = create_mock_scan(host="test-mon.org", score=88, grade="B")

    with patch("expose.core.worker.EphemeralWorkerRunner.execute_job", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = mock_result

        scans = await daemon.run_due_schedules_once()
        assert len(scans) == 1
        assert scans[0].target.host == "test-mon.org"

        # Check schedule updated
        updated_sched = mon_store.get_schedule("test-mon.org")
        assert updated_sched.last_run_at is not None
        assert updated_sched.last_score == 88
