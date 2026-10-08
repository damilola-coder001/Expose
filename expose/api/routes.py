"""REST API route handlers for Expose.

Enforces:
- Public, zero-friction no-login scan experience (Phase 17)
- Actionable finding re-verification with empirical evidence and score recalculation (Phase 15)
- Target scan history tracking and continuous monitoring security diffs (Phase 16)
- Abuse prevention, IP & target rate limits, concurrency gates, and target restrictions (Phase 18)
- Safe configuration telemetry with zero backend secret leakage (Phase 20)
"""

import asyncio
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from expose.api.security_middleware import sanitize_target_url, sanitize_text
from expose.core.abuse_prevention import AbusePreventionError, get_abuse_guard
from expose.core.config import get_config
from expose.core.export import (
    generate_executive_html_report,
    generate_sanitized_json_report,
    generate_sarif_report,
)
from expose.core.history import ScanHistoryItem, SecurityDiff, get_history_store
from expose.core.models import Finding, ScanResult, Severity, VerificationResult
from expose.core.monitoring import (
    MonitoringFrequency,
    MonitoringSchedule,
    SecurityRegressionAlert,
    detect_security_regression,
    get_monitoring_store,
)
from expose.core.observability import ScanTraceRecord, get_trace_registry
from expose.core.orchestrator import BatchScanSummary, ScanOrchestrator
from expose.core.safety import SecurityScopeError, parse_and_validate_target
from expose.core.verifier import FindingVerifier
from expose.core.ownership import (
    DomainChallenge,
    DomainOwnershipRecord,
    VerificationMethod,
    get_ownership_verifier,
)

router = APIRouter()

# In-memory scan store (production-grade interfaces ready for database persistence)
SCAN_STORE: Dict[str, ScanResult] = {}
ACTIVE_SCANS: Dict[str, str] = {}  # scan_id -> status ("queued", "running", "failed")


class ScanEventHub:
    """Pub/Sub event broadcaster for real-time scan progress streaming (Phase 24)."""

    def __init__(self):
        self._listeners: Dict[str, List[asyncio.Queue]] = {}

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        if scan_id not in self._listeners:
            self._listeners[scan_id] = []
        self._listeners[scan_id].append(q)
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        if scan_id in self._listeners and q in self._listeners[scan_id]:
            self._listeners[scan_id].remove(q)
            if not self._listeners[scan_id]:
                del self._listeners[scan_id]

    async def broadcast(self, scan_id: str, stage: str, detail: str) -> None:
        if scan_id in self._listeners:
            payload = {
                "scan_id": scan_id,
                "stage": stage,
                "detail": detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            for q in list(self._listeners[scan_id]):
                await q.put(payload)


EVENT_HUB = ScanEventHub()


class ScanRequest(BaseModel):
    target: str = Field(description="URL or domain of the website to inspect")
    allow_private: bool = Field(default=False, description="Permit scanning private/loopback RFC1918 targets")
    enable_ai: bool = Field(default=False, description="Enable AI Security Intelligence and Grounded Research")
    authorized: Optional[bool] = Field(default=True, description="Consent confirmation")


class ScanStatusResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    error: Optional[str] = None


def _make_progress_callback(sid: str):
    def _cb(stage: str, detail: str):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(EVENT_HUB.broadcast(sid, stage, detail))
        except RuntimeError:
            pass
    return _cb


@router.post("/scans", response_model=ScanResult, status_code=status.HTTP_201_CREATED)
async def create_scan_sync(request: ScanRequest, raw_req: Request = None):
    """Executes a real security intelligence scan against the target and returns verified findings.
    
    Public and frictionless: no login required (Phase 17).
    Guarded by rate limits and abuse prevention (Phase 18).
    Traceable with operational observability (Phase 21).
    Streams real-time probe milestones (Phase 24).
    """
    request.target = sanitize_target_url(request.target)
    # Reject unsafe targets before acquiring a rate-limit or worker slot. This
    # keeps internal-address probing outside the scan pipeline entirely.
    try:
        parse_and_validate_target(request.target, allow_private=request.allow_private)
    except SecurityScopeError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Safety Scope Error: {str(e)}")

    abuse_guard = get_abuse_guard()
    client_ip = raw_req.client.host if (raw_req and raw_req.client) else "127.0.0.1"
    challenge_token = raw_req.headers.get("x-expose-challenge") if raw_req else None
    req_id = getattr(getattr(raw_req, "state", None), "request_id", None) or f"req_{uuid.uuid4().hex[:8]}"

    # 1. Target restriction check
    try:
        norm_host = abuse_guard.validate_target_restrictions(request.target, allow_private=request.allow_private)
    except AbusePreventionError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

    # 2. Rate limit and concurrency acquisition
    try:
        abuse_guard.check_and_acquire(client_ip, norm_host, challenge_token=challenge_token)
    except AbusePreventionError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
            headers={"Retry-After": str(e.retry_after)}
        )

    scan_id = f"scn_{uuid.uuid4().hex[:10]}"
    get_trace_registry().start_trace(scan_id=scan_id, target=request.target, request_id=req_id)
    orchestrator = ScanOrchestrator()

    try:
        result = await orchestrator.scan(
            request.target,
            allow_private=request.allow_private,
            enable_ai=request.enable_ai,
            progress_callback=_make_progress_callback(scan_id),
            scan_id=scan_id,
        )
        SCAN_STORE[result.scan_id] = result
        # Record in target historical timeline (Phase 16)
        get_history_store().record_scan(result)
        # Observability trace completion (Phase 21)
        get_trace_registry().complete_trace(scan_id, scanner_duration_ms=result.duration_seconds * 1000.0)
        # Continuous monitoring regression detection (Phase 27)
        alert = detect_security_regression(result)
        if alert:
            get_monitoring_store().record_alert(alert)
        return result
    except SecurityScopeError as e:
        get_trace_registry().fail_trace(scan_id, reason=f"Safety Scope Error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Safety Scope Error: {str(e)}"
        )
    except Exception as e:
        get_trace_registry().fail_trace(scan_id, reason=f"Scan execution failure: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan execution failure: {str(e)}"
        )
    finally:
        abuse_guard.release(client_ip, norm_host)


class BatchScanRequest(BaseModel):
    targets: List[str] = Field(..., description="List of target domains or URLs")
    authorized: bool = Field(default=True, description="Confirmation of authorization to scan targets")
    allow_private: bool = Field(default=False, description="Allow private / internal IPs")
    concurrency: int = Field(default=3, ge=1, le=5, description="Max concurrent scans")


@router.post("/scans/batch", response_model=BatchScanSummary, tags=["scans"])
async def create_batch_scan(req: BatchScanRequest):
    """Executes a batch security scan across multiple target domains (Phase 31)."""
    if not req.targets:
        raise HTTPException(status_code=400, detail="Target list cannot be empty")
    if len(req.targets) > 20:
        raise HTTPException(status_code=400, detail="Batch size limited to maximum 20 targets per request")

    orchestrator = ScanOrchestrator()
    summary = await orchestrator.scan_batch(
        targets=req.targets,
        concurrency=req.concurrency,
        allow_private=req.allow_private,
    )

    for r in summary.scans:
        SCAN_STORE[r.scan_id] = r
        get_history_store().record_scan(r)

    return summary



@router.post("/scans/async", response_model=ScanStatusResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan_async(request: ScanRequest, background_tasks: BackgroundTasks, raw_req: Request = None):
    """Initiates an asynchronous scan running in the background."""
    request.target = sanitize_target_url(request.target)
    # Apply the same SSRF scope guard before this request consumes an async
    # scan slot or is visible to the background executor.
    try:
        parse_and_validate_target(request.target, allow_private=request.allow_private)
    except SecurityScopeError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Safety Scope Error: {str(e)}")

    abuse_guard = get_abuse_guard()
    client_ip = raw_req.client.host if (raw_req and raw_req.client) else "127.0.0.1"
    challenge_token = raw_req.headers.get("x-expose-challenge") if raw_req else None
    req_id = getattr(getattr(raw_req, "state", None), "request_id", None) or f"req_{uuid.uuid4().hex[:8]}"

    try:
        norm_host = abuse_guard.validate_target_restrictions(request.target, allow_private=request.allow_private)
        abuse_guard.check_and_acquire(client_ip, norm_host, challenge_token=challenge_token)
    except AbusePreventionError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
            headers={"Retry-After": str(e.retry_after)}
        )

    scan_id = f"scn_{uuid.uuid4().hex[:10]}"
    get_trace_registry().start_trace(scan_id=scan_id, target=request.target, request_id=req_id)
    ACTIVE_SCANS[scan_id] = "queued"

    async def run_bg(sid: str, tgt: str, allow_priv: bool, ai: bool, c_ip: str, hst: str):
        ACTIVE_SCANS[sid] = "running"
        orchestrator = ScanOrchestrator()
        try:
            res = await orchestrator.scan(
                tgt,
                allow_private=allow_priv,
                enable_ai=ai,
                progress_callback=_make_progress_callback(sid),
                scan_id=sid,
            )
            res.scan_id = sid
            SCAN_STORE[sid] = res
            get_history_store().record_scan(res)
            get_trace_registry().complete_trace(sid, scanner_duration_ms=res.duration_seconds * 1000.0)
            alert = detect_security_regression(res)
            if alert:
                get_monitoring_store().record_alert(alert)
            ACTIVE_SCANS[sid] = "completed"
        except Exception as err:
            ACTIVE_SCANS[sid] = f"failed: {str(err)}"
            get_trace_registry().fail_trace(sid, reason=str(err))
        finally:
            abuse_guard.release(c_ip, hst)

    background_tasks.add_task(run_bg, scan_id, request.target, request.allow_private, request.enable_ai, client_ip, norm_host)

    return ScanStatusResponse(
        scan_id=scan_id,
        target=request.target,
        status="queued"
    )


@router.get("/scans", response_model=List[ScanResult])
async def list_scans():
    """Lists all stored scan results."""
    return list(SCAN_STORE.values())


@router.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    """Retrieves a specific scan result by ID."""
    if scan_id in SCAN_STORE:
        return SCAN_STORE[scan_id]
    if scan_id in ACTIVE_SCANS:
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail=f"Scan is currently {ACTIVE_SCANS[scan_id]}"
        )
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")


@router.get("/scans/{scan_id}/findings", response_model=List[Finding])
async def get_scan_findings(scan_id: str, severity: Optional[Severity] = Query(None)):
    """Retrieves findings for a scan, with optional severity filtering."""
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")
    findings = SCAN_STORE[scan_id].findings
    if severity:
        findings = [f for f in findings if f.severity == severity]
    return findings


@router.get("/scans/{scan_id}/evidence/{finding_id}")
async def get_finding_evidence(scan_id: str, finding_id: str):
    """Retrieves the exact verifiable technical evidence object for a specific finding."""
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")
    finding = next((f for f in SCAN_STORE[scan_id].findings if f.id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{finding_id}' not found")
    return {
        "finding_id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence": finding.evidence.model_dump()
    }


# ==============================================================================
# PHASE 15: VERIFY FIX ENDPOINT
# ==============================================================================

@router.post("/scans/{scan_id}/findings/{finding_id}/verify", response_model=VerificationResult)
async def verify_finding_fix(scan_id: str, finding_id: str):
    """Empirically verifies whether an actionable finding has been remediated (Phase 15).
    
    Executes only the relevant probe, captures fresh wire evidence, updates the finding state,
    and recalculates the deterministic security score.
    """
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")

    scan_result = SCAN_STORE[scan_id]
    verifier = FindingVerifier()

    try:
        result = await verifier.verify_finding(scan_result, finding_id)
        # Update historical record with verified score
        get_history_store().record_scan(scan_result)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification execution failure: {str(e)}"
        )


# ==============================================================================
# PHASE 16: SECURITY HISTORY & SECURITY DIFFS
# ==============================================================================

@router.get("/targets/{target_host}/history", response_model=List[ScanHistoryItem])
async def get_target_history(target_host: str):
    """Retrieves chronological scan history for a target host (Phase 16)."""
    return get_history_store().get_history(target_host)


@router.get("/scans/{scan_id}/diff", response_model=SecurityDiff)
async def get_scan_diff(scan_id: str, compare_to_scan_id: Optional[str] = Query(None)):
    """Computes continuous monitoring security diff between scans (Phase 16).
    
    Identifies:
    + NEW findings
    ✓ FIXED findings
    ~ CHANGED findings
    """
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")

    curr_scan = SCAN_STORE[scan_id]
    prev_scan: Optional[ScanResult] = None

    if compare_to_scan_id:
        if compare_to_scan_id not in SCAN_STORE:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Comparison scan '{compare_to_scan_id}' not found"
            )
        prev_scan = SCAN_STORE[compare_to_scan_id]

    diff = get_history_store().compute_diff(curr_scan, previous_scan=prev_scan)
    return diff


# ==============================================================================
# PHASE 20: SECRET HYGIENE & SAFE TELEMETRY
# ==============================================================================

@router.get("/config/telemetry")
async def get_safe_config_telemetry():
    """Returns safe runtime telemetry with zero backend secret leakage (Phase 20)."""
    return get_config().get_client_safe_telemetry()


# ==============================================================================
# AI INTELLIGENCE ENRICHMENT ENDPOINTS
# ==============================================================================

@router.post("/scans/{scan_id}/intelligence", response_model=ScanResult)
async def generate_scan_intelligence(scan_id: str):
    """Generates on-demand grounded AI intelligence and prioritization for all confirmed findings in a scan."""
    import asyncio
    from expose.core.models import ObservationStatus
    from expose.intelligence import get_research_provider

    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")

    scan_result = SCAN_STORE[scan_id]
    provider = get_research_provider()
    confirmed = [f for f in scan_result.findings if f.status == ObservationStatus.CONFIRMED]

    tech_context = {}
    if scan_result.attack_surface:
        surf = scan_result.attack_surface
        tech_context["pages_count"] = len(surf.pages)
        tech_context["apis_count"] = len(surf.apis)
        tech_context["scripts_count"] = len(surf.scripts)
        if surf.external_dependencies:
            tech_context["external_dependencies"] = [d.origin for d in surf.external_dependencies[:5]]

    async def enrich(f):
        try:
            f.ai_intelligence = await provider.analyze_finding(
                scan_result.target.host,
                f.model_dump(),
                tech_context=tech_context,
            )
        except Exception:
            pass

    if confirmed:
        await asyncio.gather(*(enrich(f) for f in confirmed))

    try:
        scan_result.ai_prioritization = await provider.prioritize_findings(
            scan_result.target.host,
            [f.model_dump() for f in confirmed],
            tech_context=tech_context,
        )
    except Exception:
        pass

    return scan_result


@router.post("/scans/{scan_id}/findings/{finding_id}/intelligence")
async def generate_finding_intelligence(scan_id: str, finding_id: str):
    """Generates on-demand grounded AI intelligence for a single specific finding."""
    from expose.intelligence import get_research_provider

    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")

    scan_result = SCAN_STORE[scan_id]
    finding = next((f for f in scan_result.findings if f.id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{finding_id}' not found")

    provider = get_research_provider()
    tech_context = {}
    if scan_result.attack_surface:
        surf = scan_result.attack_surface
        tech_context["pages_count"] = len(surf.pages)
        tech_context["apis_count"] = len(surf.apis)
        tech_context["scripts_count"] = len(surf.scripts)
        if surf.external_dependencies:
            tech_context["external_dependencies"] = [d.origin for d in surf.external_dependencies[:5]]

    report = await provider.analyze_finding(
        scan_result.target.host,
        finding.model_dump(),
        tech_context=tech_context,
    )
    finding.ai_intelligence = report
    return report


# ==============================================================================
# PHASE 21: OPERATIONAL OBSERVABILITY & TRACING
# ==============================================================================

@router.get("/scans/{scan_id}/trace", response_model=ScanTraceRecord)
async def get_scan_trace(scan_id: str):
    """Retrieves operational telemetry, timing, and version trace for a scan (Phase 21)."""
    trace = get_trace_registry().get_trace(scan_id)
    if not trace:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Trace for scan '{scan_id}' not found")
    return trace


# ==============================================================================
# PHASE 24: REAL-TIME PROBE MILESTONE STREAMING (SSE)
# ==============================================================================

@router.get("/scans/{scan_id}/events")
async def stream_scan_events(scan_id: str):
    """Streams real-time probe milestone events via Server-Sent Events (SSE) (Phase 24).
    
    Milestones:
    Connecting -> Fetching website -> Analyzing TLS -> Inspecting headers -> 
    Discovering assets -> Running security rules -> Validating findings -> 
    Calculating risk -> Generating intelligence -> Complete
    """
    q = EVENT_HUB.subscribe(scan_id)

    async def event_generator():
        try:
            # Yield initial connection confirmation
            init_data = json.dumps({"scan_id": scan_id, "stage": "Connecting", "detail": "Subscribed to scan event stream"})
            yield f"data: {init_data}\n\n"

            # If scan already completed, immediately emit complete
            if scan_id in SCAN_STORE:
                comp_data = json.dumps({"scan_id": scan_id, "stage": "Complete", "detail": "Scan completed and report ready"})
                yield f"event: complete\ndata: {comp_data}\n\n"
                return

            timeout_count = 0
            while True:
                try:
                    payload = await asyncio.wait_for(q.get(), timeout=1.0)
                    yield f"data: {json.dumps(payload)}\n\n"
                    if payload.get("stage") == "Complete":
                        yield f"event: complete\ndata: {json.dumps(payload)}\n\n"
                        break
                except asyncio.TimeoutError:
                    timeout_count += 1
                    yield ": keepalive\n\n"
                    if scan_id in SCAN_STORE:
                        comp_data = json.dumps({"scan_id": scan_id, "stage": "Complete", "detail": "Scan completed and report ready"})
                        yield f"event: complete\ndata: {comp_data}\n\n"
                        break
                    if timeout_count > 60:
                        break
        finally:
            EVENT_HUB.unsubscribe(scan_id, q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


# ==============================================================================
# PHASES 25 & 26: REPORT EXPORT (SANITIZED JSON & OASIS SARIF v2.1.0)
# ==============================================================================

@router.get("/scans/{scan_id}/export/json")
async def export_scan_json(scan_id: str):
    """Exports a shareable, sanitized JSON security report with zero secret leakage (Phase 25)."""
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")
    report = generate_sanitized_json_report(SCAN_STORE[scan_id])
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="expose-{scan_id}.json"'}
    )


@router.get("/scans/{scan_id}/export/sarif")
async def export_scan_sarif(scan_id: str):
    """Exports an OASIS SARIF v2.1.0 report for CI/CD and GitHub Code Scanning (Phase 26)."""
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")
    sarif = generate_sarif_report(SCAN_STORE[scan_id])
    return JSONResponse(
        content=sarif,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="expose-{scan_id}.sarif"'}
    )


@router.get("/scans/{scan_id}/export/html")
async def export_scan_html(scan_id: str):
    """Exports a self-contained, standalone executive HTML report (Phase 29)."""
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found")
    from fastapi.responses import HTMLResponse
    html_content = generate_executive_html_report(SCAN_STORE[scan_id])
    return HTMLResponse(
        content=html_content,
        headers={"Content-Disposition": f'attachment; filename="expose-{scan_id}.html"'}
    )



# ==============================================================================
# PHASE 27: CONTINUOUS MONITORING & SECURITY REGRESSION ALERTS
# ==============================================================================

class MonitorScheduleRequest(BaseModel):
    frequency: MonitoringFrequency = MonitoringFrequency.DAILY
    enabled: bool = True
    min_score_threshold: int = Field(default=80)
    alert_on_new_high: bool = True
    alert_on_regression: bool = True
    webhook_url: Optional[str] = None


@router.post("/targets/{target_host}/monitor", response_model=MonitoringSchedule)
async def configure_target_monitoring(target_host: str, req: MonitorScheduleRequest):
    """Configures continuous monitoring schedule for a target (Phase 27)."""
    clean_host = sanitize_text(target_host)
    store = get_monitoring_store()
    schedule = MonitoringSchedule(
        target_host=clean_host,
        frequency=req.frequency,
        enabled=req.enabled,
        min_score_threshold=req.min_score_threshold,
        alert_on_new_high=req.alert_on_new_high,
        alert_on_regression=req.alert_on_regression,
        webhook_url=req.webhook_url,
    )
    return store.set_schedule(schedule)


@router.get("/targets/{target_host}/monitor", response_model=Optional[MonitoringSchedule])
async def get_target_monitoring(target_host: str):
    """Retrieves continuous monitoring schedule for a target (Phase 27)."""
    clean_host = sanitize_text(target_host)
    sched = get_monitoring_store().get_schedule(clean_host)
    if not sched:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No monitoring schedule for '{clean_host}'")
    return sched


@router.get("/targets/{target_host}/regression", response_model=Optional[SecurityRegressionAlert])
async def get_target_regression_alert(target_host: str):
    """Retrieves the latest verified security regression alert for a target (Phase 27)."""
    clean_host = sanitize_text(target_host)
    alert = get_monitoring_store().get_latest_alert(clean_host)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No regression alerts for '{clean_host}'")
    return alert


@router.get("/monitoring/schedules", response_model=List[MonitoringSchedule])
async def list_monitoring_schedules():
    """Lists all active continuous monitoring schedules (Phase 27)."""
    return get_monitoring_store().list_schedules()


@router.get("/monitoring/alerts", response_model=List[SecurityRegressionAlert])
async def list_monitoring_alerts(target_host: Optional[str] = None):
    """Lists continuous monitoring security regression alerts (Phase 27)."""
    store = get_monitoring_store()
    if target_host:
        return store.get_alerts_for_target(sanitize_text(target_host))
    return store._alerts


class TestWebhookRequest(BaseModel):
    webhook_url: str = Field(..., description="Destination webhook URL")
    target_host: Optional[str] = Field(default="example.com", description="Target domain for sample alert")


@router.post("/monitoring/test-webhook", tags=["monitoring"])
async def test_webhook_delivery(req: TestWebhookRequest):
    """Sends a sample regression alert to verify webhook integration (Phase 30)."""
    from expose.core.monitoring import SecurityRegressionAlert, RegressionSeverity, dispatch_webhook

    sample_alert = SecurityRegressionAlert(
        target_host=req.target_host or "example.com",
        scan_id="scn_sample_test",
        previous_scan_id="scn_sample_prev",
        previous_score=92,
        current_score=78,
        score_delta=-14,
        severity=RegressionSeverity.HIGH,
        title=f"92 → 78 TEST SECURITY REGRESSION on {req.target_host}",
        summary="Sample verification alert dispatched via Expose Webhook Engine.",
        new_high_findings=["Missing Strict-Transport-Security Header"],
    )

    success, msg = await dispatch_webhook(req.webhook_url, sample_alert)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg, "alert_id": sample_alert.alert_id}



# =========================================================================
# Phase 28 / World Standard: Domain Ownership Verification (Proof-of-Control)
# =========================================================================

class DomainChallengeRequest(BaseModel):
    domain: str = Field(..., description="Target domain to generate challenge for")


class DomainVerifyRequest(BaseModel):
    domain: str = Field(..., description="Target domain to verify")
    method: str = Field(default="any", description="Verification method: 'dns_txt', 'http_well_known', or 'any'")


@router.post("/domains/challenge", response_model=DomainChallenge, tags=["domains"])
async def create_domain_challenge(req: DomainChallengeRequest):
    """Generates a cryptographic challenge token and setup instructions for domain ownership."""
    clean_domain = sanitize_text(req.domain)
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")
    verifier = get_ownership_verifier()
    return verifier.get_challenge(clean_domain)


@router.post("/domains/verify", tags=["domains"])
async def verify_domain_ownership(req: DomainVerifyRequest):
    """Executes DNS TXT or HTTP well-known verification check to prove ownership."""
    clean_domain = sanitize_text(req.domain)
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")
    verifier = get_ownership_verifier()
    method_enum = VerificationMethod.ANY
    if req.method == "dns_txt":
        method_enum = VerificationMethod.DNS_TXT
    elif req.method == "http_well_known":
        method_enum = VerificationMethod.HTTP_WELL_KNOWN

    verified, msg, record = await verifier.verify_domain(clean_domain, method=method_enum)
    if not verified:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "verified": False,
                "domain": clean_domain,
                "message": msg,
                "challenge": verifier.get_challenge(clean_domain).model_dump(),
            },
        )
    return {
        "verified": True,
        "domain": clean_domain,
        "message": msg,
        "record": record.model_dump() if record else None,
    }


@router.get("/domains/{domain}/status", tags=["domains"])
async def get_domain_status(domain: str):
    """Returns domain ownership verification status and expiration."""
    clean_domain = sanitize_text(domain)
    verifier = get_ownership_verifier()
    record = verifier.get_record(clean_domain)
    if not record:
        challenge = verifier.get_challenge(clean_domain)
        return {
            "domain": clean_domain,
            "verified": False,
            "challenge": challenge.model_dump(),
        }
    return {
        "domain": clean_domain,
        "verified": True,
        "record": record.model_dump(),
    }


# ==============================================================================
# Phase 32: Multi-Region Vantage Point Scans
# ==============================================================================

class MultiRegionScanRequest(BaseModel):
    target: str = Field(..., description="Target domain or URL to audit across global regions")


@router.post("/scans/multi-region", tags=["scans"])
async def scan_multi_region(req: MultiRegionScanRequest):
    """Audits target from global vantage points to detect GeoDNS differences and CDN latency."""
    from expose.core.multi_region import MultiRegionOrchestrator
    orchestrator = MultiRegionOrchestrator()
    comparison = await orchestrator.audit_target(req.target)
    return comparison.model_dump()


# ==============================================================================
# Phase 34: Live Threat Intelligence Feed Sync (CISA KEV)
# ==============================================================================

@router.get("/threat-intel/status", tags=["threat-intel"])
async def get_threat_intel_status():
    """Returns current CISA KEV threat intelligence catalog metrics and sync status."""
    from expose.intelligence.threat_intel import get_threat_intel
    store = get_threat_intel()
    return {
        "total_cve_count": store.total_count,
        "last_sync_time": store.last_sync_time.isoformat() if store.last_sync_time else None,
        "source": "US CISA Known Exploited Vulnerabilities Catalog",
    }


@router.post("/threat-intel/sync", tags=["threat-intel"])
async def sync_threat_intel():
    """Synchronizes live CISA KEV catalog feed."""
    from expose.intelligence.threat_intel import get_threat_intel
    store = get_threat_intel()
    success, message, count = await store.sync_live_feed()
    return {
        "success": success,
        "message": message,
        "total_cves": count,
    }


# ==============================================================================
# Phase 35: Expose Shield WAF & Adaptive Banning
# ==============================================================================

class UnbanRequest(BaseModel):
    identifier: str = Field(..., description="IP address or device fingerprint hash to unban")


@router.get("/shield/status", tags=["shield"])
async def get_shield_status():
    """Returns real-time Expose Shield WAF telemetry, active bans, and recent incidents."""
    from expose.shield.ban_manager import get_ban_manager
    manager = get_ban_manager()
    active_bans = [b.model_dump() for b in manager.list_active_bans()]
    telemetry = manager.get_telemetry().model_dump()
    return {
        "telemetry": telemetry,
        "active_bans": active_bans,
        "ban_threshold": manager.ban_threshold,
        "ban_duration_seconds": manager.default_ban_duration,
    }


@router.post("/shield/unban", tags=["shield"])
async def unban_identifier(req: UnbanRequest):
    """Manually removes an IP address or device fingerprint from active bans."""
    from expose.shield.ban_manager import get_ban_manager
    manager = get_ban_manager()
    success = manager.unban(req.identifier)
    return {
        "identifier": req.identifier,
        "unbanned": success,
        "message": f"Successfully unbanned {req.identifier}" if success else "Identifier was not actively banned.",
    }


