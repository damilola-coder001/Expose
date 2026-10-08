"""Unit tests for Phase 18 - RATE LIMITING AND ABUSE PREVENTION."""

import pytest
import time
from expose.core.abuse_prevention import (
    AbuseGuard,
    AbusePreventionError,
)


def test_ip_rate_limiting_sliding_window():
    guard = AbuseGuard(rate_limit_per_minute=3, target_cooldown_seconds=0)

    # 3 allowed scans
    guard.check_and_acquire("192.0.2.1", "host-a.com")
    guard.release("192.0.2.1", "host-a.com")

    guard.check_and_acquire("192.0.2.1", "host-b.com")
    guard.release("192.0.2.1", "host-b.com")

    guard.check_and_acquire("192.0.2.1", "host-c.com")
    guard.release("192.0.2.1", "host-c.com")

    # 4th scan within minute is rejected with 429
    with pytest.raises(AbusePreventionError) as exc_info:
        guard.check_and_acquire("192.0.2.1", "host-d.com")
    assert exc_info.value.status_code == 429
    assert "rate limit reached" in str(exc_info.value).lower()


def test_target_cooldown_rate_limiting():
    guard = AbuseGuard(target_cooldown_seconds=30)

    # First scan against example.com succeeds
    guard.check_and_acquire("10.0.0.1", "target-cool.com")
    guard.release("10.0.0.1", "target-cool.com")

    # Immediate second scan against SAME target from any IP is blocked by cooldown
    with pytest.raises(AbusePreventionError) as exc_info:
        guard.check_and_acquire("10.0.0.2", "target-cool.com")
    assert exc_info.value.status_code == 429
    assert "cooldown" in str(exc_info.value).lower() or "recently" in str(exc_info.value).lower()


def test_per_ip_concurrency_limiting():
    guard = AbuseGuard(max_concurrent_per_ip=1, target_cooldown_seconds=0)

    # Start first scan and do NOT release slot yet
    guard.check_and_acquire("198.51.100.5", "host-one.com")

    # Concurrent attempt from same IP must be rejected
    with pytest.raises(AbusePreventionError) as exc_info:
        guard.check_and_acquire("198.51.100.5", "host-two.com")
    assert exc_info.value.status_code == 429
    assert "already have a scan running" in str(exc_info.value).lower()

    # Releasing unlocks subsequent scan
    guard.release("198.51.100.5", "host-one.com")
    guard.check_and_acquire("198.51.100.5", "host-two.com")
    guard.release("198.51.100.5", "host-two.com")


def test_restricted_public_tlds():
    guard = AbuseGuard()

    # .gov and .mil domains are restricted in public scanning
    with pytest.raises(AbusePreventionError) as exc_gov:
        guard.validate_target_restrictions("https://sensitive.gov", allow_private=False)
    assert exc_gov.value.status_code == 403
    assert "protected infrastructure" in str(exc_gov.value).lower()

    with pytest.raises(AbusePreventionError) as exc_mil:
        guard.validate_target_restrictions("defense.mil", allow_private=False)
    assert exc_mil.value.status_code == 403


def test_cloud_metadata_blocked():
    guard = AbuseGuard()

    # 169.254.169.254 blocked
    with pytest.raises(AbusePreventionError) as exc:
        guard.validate_target_restrictions("http://169.254.169.254", allow_private=False)
    assert exc.value.status_code == 403
