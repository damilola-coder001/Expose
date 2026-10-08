"""Structured observability, unified tracing, and operational telemetry for Expose (Phase 21).

Provides end-to-end traceability for every scan:
- scan_id
- request_id
- worker_id
- target
- started_at / completed_at
- duration / scanner duration / queue latency
- scanner_version / rules_version / score_version
- status / failure reasons
"""

from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field

from expose import __version__

# Canonical versions
SCANNER_VERSION = __version__
RULES_VERSION = "2026.1"
SCORE_VERSION = "1.0"

logger = logging.getLogger("expose.observability")


class ScanTraceRecord(BaseModel):
    """Unified operational record tracking a scan through its lifecycle."""
    scan_id: str
    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:8]}")
    worker_id: str = Field(default="worker-main")
    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    scanner_duration_ms: Optional[float] = None
    queue_latency_ms: Optional[float] = None
    scanner_version: str = SCANNER_VERSION
    rules_version: str = RULES_VERSION
    score_version: str = SCORE_VERSION
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED, TIMED_OUT
    failure_reason: Optional[str] = None
    telemetry: Dict[str, Any] = Field(default_factory=dict)


class StructuredLogger:
    """Emits structured JSON logs for observability systems (Datadog, CloudWatch, Grafana)."""

    @staticmethod
    def log_scan_event(trace: ScanTraceRecord, event_type: str, details: Optional[Dict[str, Any]] = None) -> None:
        log_payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "scan_id": trace.scan_id,
            "request_id": trace.request_id,
            "worker_id": trace.worker_id,
            "target": trace.target,
            "status": trace.status,
            "duration_ms": trace.duration_ms,
            "scanner_version": trace.scanner_version,
            "score_version": trace.score_version,
            "details": details or {},
        }
        if trace.failure_reason:
            log_payload["failure_reason"] = trace.failure_reason
            logger.error("SCAN_TRACE: %s", json.dumps(log_payload))
        else:
            logger.info("SCAN_TRACE: %s", json.dumps(log_payload))

    @staticmethod
    def log_audit_event(action: str, client_ip: str, target: str, scan_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        audit_payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "audit_action": action,
            "client_ip": client_ip,
            "target": target,
            "scan_id": scan_id,
            "details": details or {},
        }
        logger.info("AUDIT_LOG: %s", json.dumps(audit_payload))


class TraceRegistry:
    """Maintains active and completed scan traces."""

    def __init__(self):
        self._traces: Dict[str, ScanTraceRecord] = {}

    def start_trace(
        self,
        scan_id: str,
        target: str,
        request_id: Optional[str] = None,
        worker_id: Optional[str] = None,
    ) -> ScanTraceRecord:
        trace = ScanTraceRecord(
            scan_id=scan_id,
            request_id=request_id or f"req_{uuid.uuid4().hex[:8]}",
            worker_id=worker_id or "worker-main",
            target=target,
            status="RUNNING",
        )
        self._traces[scan_id] = trace
        StructuredLogger.log_scan_event(trace, "scan_started")
        return trace

    def complete_trace(
        self,
        scan_id: str,
        scanner_duration_ms: Optional[float] = None,
        queue_latency_ms: Optional[float] = None,
    ) -> Optional[ScanTraceRecord]:
        trace = self._traces.get(scan_id)
        if not trace:
            return None
        trace.completed_at = datetime.now(timezone.utc)
        trace.duration_ms = (trace.completed_at - trace.started_at).total_seconds() * 1000.0
        trace.scanner_duration_ms = scanner_duration_ms or trace.duration_ms
        trace.queue_latency_ms = queue_latency_ms or 0.0
        trace.status = "COMPLETED"
        StructuredLogger.log_scan_event(trace, "scan_completed")
        return trace

    def fail_trace(self, scan_id: str, reason: str) -> Optional[ScanTraceRecord]:
        trace = self._traces.get(scan_id)
        if not trace:
            return None
        trace.completed_at = datetime.now(timezone.utc)
        trace.duration_ms = (trace.completed_at - trace.started_at).total_seconds() * 1000.0
        trace.status = "FAILED"
        trace.failure_reason = reason
        StructuredLogger.log_scan_event(trace, "scan_failed", {"error": reason})
        return trace

    def get_trace(self, scan_id: str) -> Optional[ScanTraceRecord]:
        return self._traces.get(scan_id)


# Global singleton instance
_GLOBAL_TRACE_REGISTRY = TraceRegistry()


def get_trace_registry() -> TraceRegistry:
    return _GLOBAL_TRACE_REGISTRY
