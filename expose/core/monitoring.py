"""Continuous target monitoring, regression detection, and alert engine for Expose (Phase 27).

Detects security regressions:
- Score drop threshold breaches (e.g. 91 -> 68 SECURITY REGRESSION)
- Introduction of new Critical or High severity findings
- Resurfacing of previously remediated findings
- TLS / SSL protocol degradation
"""

from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid
from pydantic import BaseModel, Field

from expose.core.history import SecurityDiff, get_history_store
from expose.core.models import ObservationStatus, ScanResult, Severity


class MonitoringFrequency(str, Enum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"


class RegressionSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MonitoringSchedule(BaseModel):
    """Configuration for automated continuous target monitoring."""
    id: str = Field(default_factory=lambda: f"mon_{uuid.uuid4().hex[:8]}")
    target_host: str
    frequency: MonitoringFrequency = MonitoringFrequency.DAILY
    enabled: bool = True
    min_score_threshold: int = Field(default=80, description="Alert if security score drops below this")
    alert_on_new_high: bool = True
    alert_on_regression: bool = True
    webhook_url: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_run_at: Optional[datetime] = None
    last_score: Optional[int] = None


class SecurityRegressionAlert(BaseModel):
    """Alert triggered when a target experiences a verifiable security regression."""
    alert_id: str = Field(default_factory=lambda: f"alt_{uuid.uuid4().hex[:8]}")
    target_host: str
    scan_id: str
    previous_scan_id: str
    previous_score: int
    current_score: int
    score_delta: int  # Negative number representing drop (e.g. -23)
    severity: RegressionSeverity
    title: str
    summary: str
    new_critical_findings: List[str] = Field(default_factory=list)
    new_high_findings: List[str] = Field(default_factory=list)
    resurfaced_findings: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def detect_security_regression(
    current_scan: ScanResult,
    previous_scan: Optional[ScanResult] = None,
    score_drop_tolerance: int = 5,
) -> Optional[SecurityRegressionAlert]:
    """Analyzes two sequential scans to detect verifiable security regressions.
    
    Triggered when:
    1. Score drops by more than `score_drop_tolerance` (e.g. 91 -> 68).
    2. New CRITICAL or HIGH findings appear.
    3. Any previously REMEDIATED finding reappears.
    """
    if previous_scan is None:
        # Check against history store if available
        history = get_history_store().get_history(current_scan.target.host)
        if len(history) >= 2:
            # Most recent before current
            prev_scan_id = history[1].scan_id
            # Retrieve from SCAN_STORE if available in memory
            from expose.api.routes import SCAN_STORE
            previous_scan = SCAN_STORE.get(prev_scan_id)

    if previous_scan is None:
        return None

    prev_score = previous_scan.score_card.overall_score
    curr_score = current_scan.score_card.overall_score
    score_delta = curr_score - prev_score

    # Compute diff between scans
    diff = get_history_store().compute_diff(current_scan, previous_scan=previous_scan)

    new_critical = []
    new_high = []
    resurfaced = []

    for item in diff.new_findings:
        sev = getattr(item, "severity_current", None) or getattr(item, "severity", None)
        if sev == Severity.CRITICAL:
            new_critical.append(item.title)
        elif sev == Severity.HIGH:
            new_high.append(item.title)

    # Check for resurfaced findings that were marked REMEDIATED / FIXED in previous scan
    prev_remediated_titles = {
        f.title for f in previous_scan.findings if f.status in (ObservationStatus.REMEDIATED, ObservationStatus.FIXED)
    }
    for f in current_scan.findings:
        if f.status == ObservationStatus.CONFIRMED and f.title in prev_remediated_titles:
            resurfaced.append(f.title)

    is_regression = False
    reasons = []

    if score_delta <= -score_drop_tolerance:
        is_regression = True
        reasons.append(f"Security score dropped from {prev_score} to {curr_score} (Δ {score_delta})")

    if new_critical:
        is_regression = True
        reasons.append(f"Introduced {len(new_critical)} new CRITICAL finding(s): {', '.join(new_critical[:2])}")

    if new_high:
        is_regression = True
        reasons.append(f"Introduced {len(new_high)} new HIGH finding(s): {', '.join(new_high[:2])}")

    if resurfaced:
        is_regression = True
        reasons.append(f"Resurfaced {len(resurfaced)} previously remediated finding(s): {', '.join(resurfaced[:2])}")

    if not is_regression:
        return None

    # Determine alert severity
    if new_critical or score_delta <= -20:
        alert_sev = RegressionSeverity.CRITICAL
    elif new_high or score_delta <= -10:
        alert_sev = RegressionSeverity.HIGH
    elif score_delta <= -5:
        alert_sev = RegressionSeverity.MEDIUM
    else:
        alert_sev = RegressionSeverity.LOW

    title = f"{prev_score} → {curr_score} SECURITY REGRESSION on {current_scan.target.host}"
    summary = "; ".join(reasons)

    return SecurityRegressionAlert(
        target_host=current_scan.target.host,
        scan_id=current_scan.scan_id,
        previous_scan_id=previous_scan.scan_id,
        previous_score=prev_score,
        current_score=curr_score,
        score_delta=score_delta,
        severity=alert_sev,
        title=title,
        summary=summary,
        new_critical_findings=new_critical,
        new_high_findings=new_high,
        resurfaced_findings=resurfaced,
    )


class MonitoringStore:
    """Manages monitoring schedules and alerts."""

    def __init__(self):
        self._schedules: Dict[str, MonitoringSchedule] = {}  # target_host -> schedule
        self._alerts: List[SecurityRegressionAlert] = []

    def set_schedule(self, schedule: MonitoringSchedule) -> MonitoringSchedule:
        self._schedules[schedule.target_host] = schedule
        return schedule

    def get_schedule(self, target_host: str) -> Optional[MonitoringSchedule]:
        return self._schedules.get(target_host)

    def list_schedules(self) -> List[MonitoringSchedule]:
        return list(self._schedules.values())

    def record_alert(self, alert: SecurityRegressionAlert) -> None:
        self._alerts.insert(0, alert)

    def get_alerts_for_target(self, target_host: str) -> List[SecurityRegressionAlert]:
        return [a for a in self._alerts if a.target_host == target_host]

    def get_latest_alert(self, target_host: str) -> Optional[SecurityRegressionAlert]:
        alerts = self.get_alerts_for_target(target_host)
        return alerts[0] if alerts else None


# Singleton instance
_MONITORING_STORE = MonitoringStore()


def get_monitoring_store() -> MonitoringStore:
    return _MONITORING_STORE


# ==============================================================================
# Phase 30: Real-Time Webhook Alert Dispatcher (Slack, Teams, Discord, Generic)
# ==============================================================================

class WebhookFormat(str, Enum):
    SLACK = "slack"
    DISCORD = "discord"
    TEAMS = "teams"
    GENERIC = "generic"


def detect_webhook_format(url: str) -> WebhookFormat:
    """Detects the target webhook provider from the URL structure."""
    lower = url.lower()
    if "hooks.slack.com" in lower:
        return WebhookFormat.SLACK
    if "discord.com/api/webhooks" in lower or "discordapp.com/api/webhooks" in lower:
        return WebhookFormat.DISCORD
    if "office.com" in lower or "webhook.office" in lower:
        return WebhookFormat.TEAMS
    return WebhookFormat.GENERIC


def format_webhook_payload(alert: SecurityRegressionAlert, fmt: Optional[WebhookFormat] = None, webhook_url: Optional[str] = None) -> Dict[str, Any]:
    """Formats the alert payload appropriately for Slack, Discord, Teams, or generic consumers."""
    target_format = fmt or (detect_webhook_format(webhook_url) if webhook_url else WebhookFormat.GENERIC)

    if target_format == WebhookFormat.SLACK:
        return {
            "text": f"🚨 *{alert.title}*",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 Security Alert: {alert.target_host}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Previous Score:*\n{alert.previous_score} / 100"},
                        {"type": "mrkdwn", "text": f"*Current Score:*\n{alert.current_score} / 100 ({alert.score_delta})"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{alert.severity.value.upper()}"},
                        {"type": "mrkdwn", "text": f"*Scan ID:*\n`{alert.scan_id}`"},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Summary:*\n{alert.summary}"}
                }
            ]
        }

    if target_format == WebhookFormat.DISCORD:
        color = 0xef4444 if alert.severity == RegressionSeverity.CRITICAL else 0xf97316
        return {
            "content": f"🚨 **Security Regression Alert: {alert.target_host}**",
            "embeds": [
                {
                    "title": alert.title,
                    "description": alert.summary,
                    "color": color,
                    "fields": [
                        {"name": "Previous Score", "value": f"{alert.previous_score}/100", "inline": True},
                        {"name": "Current Score", "value": f"{alert.current_score}/100 ({alert.score_delta})", "inline": True},
                        {"name": "Severity", "value": alert.severity.value.upper(), "inline": True},
                    ],
                    "footer": {"text": f"Scan ID: {alert.scan_id} | Expose Intelligence"}
                }
            ]
        }

    if target_format == WebhookFormat.TEAMS:
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": alert.title,
            "themeColor": "EF4444" if alert.severity == RegressionSeverity.CRITICAL else "F97316",
            "title": f"🚨 Security Regression: {alert.target_host}",
            "sections": [
                {
                    "activityTitle": alert.title,
                    "activitySubtitle": alert.summary,
                    "facts": [
                        {"name": "Previous Score", "value": f"{alert.previous_score}/100"},
                        {"name": "Current Score", "value": f"{alert.current_score}/100 ({alert.score_delta})"},
                        {"name": "Severity", "value": alert.severity.value.upper()},
                        {"name": "Scan ID", "value": alert.scan_id},
                    ]
                }
            ]
        }

    # Generic JSON format
    return {
        "event": "security_regression_alert",
        "alert": alert.model_dump(mode="json"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def dispatch_webhook(webhook_url: str, alert: SecurityRegressionAlert) -> Tuple[bool, str]:
    """Dispatches the alert payload to the target webhook URL with SSRF protection."""
    from expose.core.safety import create_safe_async_client

    payload = format_webhook_payload(alert, webhook_url=webhook_url)

    try:
        async with create_safe_async_client(allow_private=False, timeout=8.0) as client:
            res = await client.post(webhook_url, json=payload)
            if res.status_code in (200, 201, 204):
                return True, f"Delivered successfully (HTTP {res.status_code})"
            return False, f"Webhook endpoint returned HTTP {res.status_code}: {res.text[:100]}"
    except Exception as e:
        return False, f"Webhook delivery error: {str(e)}"

