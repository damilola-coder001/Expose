"""Tests for operational observability, unified tracing, and structured logging (Phase 21)."""

import pytest
from expose.core.observability import (
    SCANNER_VERSION,
    RULES_VERSION,
    SCORE_VERSION,
    ScanTraceRecord,
    StructuredLogger,
    TraceRegistry,
    get_trace_registry,
)


def test_scan_trace_record_defaults():
    record = ScanTraceRecord(
        scan_id="scn_test_123",
        target="example.com",
    )
    assert record.scan_id == "scn_test_123"
    assert record.target == "example.com"
    assert record.status == "PENDING"
    assert record.scanner_version == SCANNER_VERSION
    assert record.rules_version == RULES_VERSION
    assert record.score_version == SCORE_VERSION
    assert record.worker_id == "worker-main"
    assert record.request_id.startswith("req_")


def test_trace_registry_lifecycle():
    registry = TraceRegistry()
    
    # 1. Start trace
    trace = registry.start_trace(
        scan_id="scn_abc1",
        target="https://target.local",
        request_id="req_custom_99",
        worker_id="worker-01"
    )
    assert trace.scan_id == "scn_abc1"
    assert trace.status == "RUNNING"
    assert trace.request_id == "req_custom_99"
    assert trace.worker_id == "worker-01"

    # 2. Complete trace
    completed = registry.complete_trace("scn_abc1", scanner_duration_ms=1450.5, queue_latency_ms=12.3)
    assert completed is not None
    assert completed.status == "COMPLETED"
    assert completed.scanner_duration_ms == 1450.5
    assert completed.queue_latency_ms == 12.3
    assert completed.duration_ms is not None
    assert completed.duration_ms >= 0

    # 3. Retrieve trace
    retrieved = registry.get_trace("scn_abc1")
    assert retrieved == completed


def test_trace_registry_failure():
    registry = TraceRegistry()
    registry.start_trace(scan_id="scn_fail", target="invalid-target")
    failed = registry.fail_trace("scn_fail", reason="Target host unreachable")
    
    assert failed is not None
    assert failed.status == "FAILED"
    assert failed.failure_reason == "Target host unreachable"
    assert failed.completed_at is not None


def test_structured_logger_emits_json(caplog):
    import logging
    caplog.set_level(logging.INFO)
    
    trace = ScanTraceRecord(
        scan_id="scn_log_test",
        target="https://api.test",
        status="RUNNING"
    )
    StructuredLogger.log_scan_event(trace, "test_event", {"extra_metric": 42})
    
    assert any("scn_log_test" in record.message for record in caplog.records)
    assert any("test_event" in record.message for record in caplog.records)
