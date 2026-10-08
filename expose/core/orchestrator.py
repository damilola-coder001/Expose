"""Asynchronous scan orchestrator and probe execution engine for Expose."""

import asyncio
from datetime import datetime, timezone
import time
import uuid
from typing import Callable, List, Optional

from pydantic import BaseModel, Field

from expose.core.models import (
    Finding,
    ObservationStatus,
    ProbeStatus,
    ScanResult,
    ScoreCard,
    Severity,
    TargetScope,
)


class BatchScanItem(BaseModel):
    """Summarized status for an individual target in a batch scan."""
    target: str
    scan_id: Optional[str] = None
    score: Optional[int] = None
    letter_grade: str = "F"
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    duration_seconds: float = 0.0
    status: str = "completed"
    error: Optional[str] = None


class BatchScanSummary(BaseModel):
    """Portfolio-level summary across multiple scanned targets (Phase 31)."""
    total_targets: int
    successful_scans: int
    failed_scans: int
    portfolio_average_score: float
    total_findings: int
    total_critical: int
    total_high: int
    items: List[BatchScanItem] = Field(default_factory=list)
    scans: List[ScanResult] = Field(default_factory=list)

from expose.core.safety import parse_and_validate_target
from expose.core.scoring import calculate_score_card
from expose.intelligence import SecurityResearchProvider, get_research_provider
from expose.probes import (
    BaseProbe,
    CookieProbe,
    DNSProbe,
    HTTPHeadersProbe,
    MetadataProbe,
    TLSProbe,
    ClientSideProbe,
    NucleiProbe,
    AttackSurfaceProbe,
    WAFProbe,
    NmapProbe,
    NiktoProbe,
    OpenSCAPProbe,
    GVMProbe,
)


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

PROBE_MILESTONE_MAP = {
    "dns_posture": ("Connecting", "Resolving DNS and establishing transport security"),
    "tls_posture": ("Analyzing TLS", "Inspecting certificates, protocols, and cipher suites"),
    "http_headers": ("Inspecting headers", "Evaluating CSP, HSTS, and frame protections"),
    "cookie_security": ("Running security rules", "Auditing cookie attributes, flags, and scopes"),
    "security_metadata": ("Fetching website", "Retrieving root document and security metadata"),
    "client_side_security": ("Discovering assets", "Auditing client-side scripts and inline behaviors"),
    "nuclei_exposure_probe": ("Running security rules", "Testing active vulnerability rules and signatures"),
    "attack_surface_discovery": ("Discovering assets", "Enumerating exposed endpoints, routes, and forms"),
    "waf_and_edge_security": ("Analyzing Edge Security", "Fingerprinting reverse proxy and WAF edge layers"),
    "nmap_probe": ("Scanning ports", "Scanning host ports and discovering network transport services"),
    "nikto_probe": ("Auditing web server", "Auditing web server configurations, dangerous paths, and headers"),
    "openscap_probe": ("Evaluating compliance", "Auditing security baselines against CIS and SCAP hardening benchmarks"),
    "gvm_vulnerability_probe": ("Assessing vulnerabilities", "Running Greenbone NVT checks and CVE vulnerability correlation"),
}


class ScanOrchestrator:
    """Coordinates probe scheduling, concurrency management, and result aggregation."""

    def __init__(self, probes: Optional[List[BaseProbe]] = None, max_concurrency: int = 10):
        self.probes = probes or [
            DNSProbe(),
            TLSProbe(),
            HTTPHeadersProbe(),
            CookieProbe(),
            MetadataProbe(),
            ClientSideProbe(),
            NucleiProbe(),
            AttackSurfaceProbe(),
            WAFProbe(),
            NmapProbe(),
            NiktoProbe(),
            OpenSCAPProbe(),
            GVMProbe(),
        ]
        self.max_concurrency = max_concurrency

    async def scan(
        self,
        raw_target: str,
        allow_private: bool = False,
        enable_ai: bool = False,
        research_provider: Optional[SecurityResearchProvider] = None,
        progress_callback: Optional[Callable[[str, str], None]] = None,
        scan_id: Optional[str] = None,
    ) -> ScanResult:
        """Executes a full security intelligence scan against the target.
        
        Args:
            raw_target: URL or domain string.
            allow_private: Whether to allow private or loopback IP ranges.
            progress_callback: Optional callback receiving (probe_name, status).
            scan_id: Optional pre-allocated scan ID.
            
        Returns:
            ScanResult containing all verified findings, attack surface inventory, and audit trail.
        """
        # Validate target and enforce SSRF guard
        target_scope = parse_and_validate_target(raw_target, allow_private=allow_private)

        scan_id = scan_id or f"scn_{uuid.uuid4().hex[:10]}"
        start_time = datetime.now(timezone.utc)

        if progress_callback:
            progress_callback("Connecting", "Resolving DNS and establishing transport security...")

        all_findings: List[Finding] = []
        probe_statuses: List[ProbeStatus] = []
        attack_surface_holder = [None]

        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def run_single_probe(probe: BaseProbe) -> None:
            async with semaphore:
                if progress_callback:
                    milestone, detail = PROBE_MILESTONE_MAP.get(probe.name, (probe.name, "running"))
                    progress_callback(milestone, detail)
                t0 = time.perf_counter()
                try:
                    if isinstance(probe, AttackSurfaceProbe):
                        findings, surface = await asyncio.wait_for(probe.discover_attack_surface(target_scope), timeout=12.0)
                        attack_surface_holder[0] = surface
                    else:
                        findings = await asyncio.wait_for(probe.execute(target_scope), timeout=12.0)
                    elapsed = time.perf_counter() - t0
                    all_findings.extend(findings)
                    probe_statuses.append(
                        ProbeStatus(
                            probe_name=probe.name,
                            status="completed",
                            duration_seconds=round(elapsed, 3),
                        )
                    )
                    if progress_callback:
                        progress_callback(probe.name, "completed")
                except asyncio.TimeoutError:
                    elapsed = time.perf_counter() - t0
                    probe_statuses.append(
                        ProbeStatus(
                            probe_name=probe.name,
                            status="failed",
                            duration_seconds=round(elapsed, 3),
                            error_message="Probe timed out after 12.0 seconds",
                        )
                    )
                    if progress_callback:
                        progress_callback(probe.name, "failed")
                except Exception as e:
                    elapsed = time.perf_counter() - t0
                    probe_statuses.append(
                        ProbeStatus(
                            probe_name=probe.name,
                            status="failed",
                            duration_seconds=round(elapsed, 3),
                            error_message=str(e),
                        )
                    )
                    if progress_callback:
                        progress_callback(probe.name, "failed")

        # Execute all probes concurrently
        await asyncio.gather(*(run_single_probe(p) for p in self.probes))

        if progress_callback:
            progress_callback("Validating findings", "Analyzing evidence and eliminating false positives...")

        # Deduplicate findings by (id, category, title)
        unique_findings = []
        seen_keys = set()
        for f in all_findings:
            key = (f.id, f.category, f.title.strip().lower())
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)
        all_findings = unique_findings

        # Sort findings by severity then title
        all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.title))

        end_time = datetime.now(timezone.utc)
        total_duration = (end_time - start_time).total_seconds()

        if progress_callback:
            progress_callback("Calculating risk", "Evaluating exposure penalties and category scores...")

        # Collect header test matrix from http_headers probe
        header_matrix = []
        for p in self.probes:
            if hasattr(p, "last_matrix") and p.last_matrix:
                header_matrix = p.last_matrix
                break

        # Compute deterministic PageSpeed-style security scorecard (Phase 9 v1.0)
        score_card = calculate_score_card(all_findings, header_matrix=header_matrix)

        # AI Security Intelligence & Grounded Web Research (Phases 11 & 18)
        # Strictly post-processing: AI does NOT modify the deterministic score card or raw finding severities.
        ai_prioritization = None
        if enable_ai or research_provider:
            if progress_callback:
                progress_callback("Generating intelligence", "Synthesizing grounded AI insights and remediation ranking...")
            provider = research_provider or get_research_provider()
            confirmed_findings = [f for f in all_findings if f.status == ObservationStatus.CONFIRMED]
            tech_context = {}
            if attack_surface_holder[0]:
                surf = attack_surface_holder[0]
                tech_context["pages_count"] = len(surf.pages)
                tech_context["apis_count"] = len(surf.apis)
                tech_context["scripts_count"] = len(surf.scripts)
                if surf.external_dependencies:
                    tech_context["external_dependencies"] = [d.origin for d in surf.external_dependencies[:5]]

            # Enrich findings with AI intelligence
            async def enrich_finding(finding: Finding):
                try:
                    finding.ai_intelligence = await provider.analyze_finding(
                        target_scope.host,
                        finding.model_dump(),
                        tech_context=tech_context,
                    )
                except Exception:
                    pass

            if confirmed_findings:
                await asyncio.gather(*(enrich_finding(f) for f in confirmed_findings))

            try:
                ai_prioritization = await provider.prioritize_findings(
                    target_scope.host,
                    [f.model_dump() for f in confirmed_findings],
                    tech_context=tech_context,
                )
            except Exception:
                pass

        if progress_callback:
            progress_callback("Complete", "Scan finalized and scorecard ready.")

        return ScanResult(
            scan_id=scan_id,
            target=target_scope,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=round(total_duration, 3),
            score_card=score_card,
            attack_surface=attack_surface_holder[0],
            header_test_matrix=header_matrix,
            probe_statuses=probe_statuses,
            findings=all_findings,
            ai_prioritization=ai_prioritization,
        )

    async def scan_batch(
        self,
        targets: List[str],
        concurrency: int = 3,
        allow_private: bool = False,
        enable_ai: bool = False,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> BatchScanSummary:
        """Executes scans across a list of target URLs concurrently with rate limiting (Phase 31)."""
        sem = asyncio.Semaphore(max(1, concurrency))
        completed = 0
        total = len(targets)
        items: List[BatchScanItem] = []
        scans: List[ScanResult] = []

        async def _run_single(tgt: str) -> Optional[ScanResult]:
            nonlocal completed
            start_t = time.time()
            async with sem:
                try:
                    res = await self.scan(
                        raw_target=tgt,
                        allow_private=allow_private,
                        enable_ai=enable_ai,
                    )
                    dur = time.time() - start_t
                    completed += 1
                    if progress_callback:
                        progress_callback(tgt, completed, total)

                    score = res.score_card.overall_score if res.score_card else 0
                    grade = res.score_card.letter_grade if res.score_card else "F"
                    crit = sum(1 for f in res.findings if f.severity == Severity.CRITICAL and f.status == ObservationStatus.CONFIRMED)
                    high = sum(1 for f in res.findings if f.severity == Severity.HIGH and f.status == ObservationStatus.CONFIRMED)
                    total_f = len(res.findings)

                    item = BatchScanItem(
                        target=res.target.host,
                        scan_id=res.scan_id,
                        score=score,
                        letter_grade=grade,
                        findings_count=total_f,
                        critical_count=crit,
                        high_count=high,
                        duration_seconds=round(dur, 2),
                        status="completed",
                    )
                    items.append(item)
                    scans.append(res)
                    return res
                except Exception as e:
                    dur = time.time() - start_t
                    completed += 1
                    if progress_callback:
                        progress_callback(tgt, completed, total)
                    item = BatchScanItem(
                        target=tgt,
                        score=None,
                        letter_grade="-",
                        status="failed",
                        error=str(e),
                        duration_seconds=round(dur, 2),
                    )
                    items.append(item)
                    return None

        tasks = [_run_single(t) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=False)

        successful = len(scans)
        failed = len(targets) - successful
        avg_score = (
            round(sum(s.score_card.overall_score for s in scans if s.score_card) / successful, 1)
            if successful > 0
            else 0.0
        )
        tot_findings = sum(it.findings_count for it in items)
        tot_crit = sum(it.critical_count for it in items)
        tot_high = sum(it.high_count for it in items)

        return BatchScanSummary(
            total_targets=total,
            successful_scans=successful,
            failed_scans=failed,
            portfolio_average_score=avg_score,
            total_findings=tot_findings,
            total_critical=tot_crit,
            total_high=tot_high,
            items=items,
            scans=scans,
        )



