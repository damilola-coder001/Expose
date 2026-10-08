"""Finding verification engine for Expose (Phase 15 - VERIFY FIX).

Implements targeted, evidence-based re-verification of actionable findings.
A finding is NEVER marked fixed merely because a button was clicked.
Verification requires fresh empirical wire evidence.
"""

import asyncio
from datetime import datetime, timezone
import time
from typing import Dict, List, Optional, Type
import uuid

from expose.core.models import (
    Evidence,
    EvidenceType,
    Finding,
    ObservationStatus,
    ScanResult,
    TargetScope,
    VerificationResult,
    VerificationStatus,
)
from expose.core.scoring import calculate_score_card
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
    NmapProbe,
    NiktoProbe,
    OpenSCAPProbe,
    GVMProbe,
)


# Registry mapping probe identifiers to probe classes
PROBE_REGISTRY: Dict[str, Type[BaseProbe]] = {
    "http_headers": HTTPHeadersProbe,
    "http": HTTPHeadersProbe,
    "tls": TLSProbe,
    "dns": DNSProbe,
    "cookies": CookieProbe,
    "cookie": CookieProbe,
    "metadata": MetadataProbe,
    "clientside": ClientSideProbe,
    "client_side": ClientSideProbe,
    "nuclei": NucleiProbe,
    "attack_surface": AttackSurfaceProbe,
    "nmap": NmapProbe,
    "nmap_probe": NmapProbe,
    "nikto": NiktoProbe,
    "nikto_probe": NiktoProbe,
    "openscap": OpenSCAPProbe,
    "oscap": OpenSCAPProbe,
    "openscap_probe": OpenSCAPProbe,
    "gvm": GVMProbe,
    "openvas": GVMProbe,
    "gvm_probe": GVMProbe,
    "gvm_vulnerability_probe": GVMProbe,
}


class FindingVerifier:
    """Coordinates targeted probe execution to empirically verify whether a finding has been fixed."""

    def __init__(self, custom_probes: Optional[Dict[str, BaseProbe]] = None):
        self.custom_probes = custom_probes or {}

    def get_probe_for_finding(self, finding: Finding) -> BaseProbe:
        """Resolves the precise single probe responsible for this finding."""
        probe_key = finding.probe.lower().strip()
        if probe_key in self.custom_probes:
            return self.custom_probes[probe_key]
        
        probe_cls = PROBE_REGISTRY.get(probe_key)
        if probe_cls:
            return probe_cls()

        # Fuzzy match on category or title
        if "tls" in probe_key or "cert" in finding.title.lower():
            return TLSProbe()
        if "cookie" in probe_key or "cookie" in finding.title.lower():
            return CookieProbe()
        if "dns" in probe_key:
            return DNSProbe()
        if "metadata" in probe_key or "security.txt" in finding.title.lower() or "robots" in finding.title.lower():
            return MetadataProbe()

        # Default to HTTPHeadersProbe
        return HTTPHeadersProbe()

    async def verify_finding(
        self,
        scan_result: ScanResult,
        finding_id: str,
        timeout: float = 15.0,
    ) -> VerificationResult:
        """Executes a targeted verification job against the target for a specific finding.
        
        Workflow:
        1. Identify the targeted finding and record baseline score and evidence.
        2. Execute ONLY the relevant probe against the target.
        3. Compare new evidence against the finding's flaw signature.
        4. Determine if the flaw remains or has been resolved.
        5. Update the finding state and recalculate the deterministic security score.
        """
        finding = next((f for f in scan_result.findings if f.id == finding_id), None)
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found in scan '{scan_result.scan_id}'")

        score_before = scan_result.score_card.overall_score if scan_result.score_card else 100
        before_summary = finding.evidence.summary if finding.evidence else "No prior evidence"

        # Resolve single relevant probe
        probe = self.get_probe_for_finding(finding)

        # Execute only relevant probe
        fresh_findings: List[Finding] = []
        try:
            if isinstance(probe, AttackSurfaceProbe):
                fresh_findings, _ = await asyncio.wait_for(
                    probe.discover_attack_surface(scan_result.target),
                    timeout=timeout
                )
            else:
                fresh_findings = await asyncio.wait_for(
                    probe.execute(scan_result.target),
                    timeout=timeout
                )
        except Exception as e:
            # Verification failed due to connectivity / probe execution error
            res = VerificationResult(
                verification_id=f"vrf_{uuid.uuid4().hex[:8]}",
                scan_id=scan_result.scan_id,
                finding_id=finding.id,
                status=VerificationStatus.FAILED,
                message=f"Verification check failed to execute: {str(e)}",
                score_before=score_before,
                score_after=score_before,
                score_delta=0,
                before_evidence_summary=before_summary,
                after_evidence=None,
            )
            finding.verification_history.append(res)
            return res

        # Compare evidence: Does the confirmed flaw still trigger?
        # A finding is still present if fresh_findings contains a CONFIRMED flaw
        # matching rule_id, or title, or id.
        still_present_finding: Optional[Finding] = None
        positive_evidence: Optional[Evidence] = None

        for ff in fresh_findings:
            if ff.status == ObservationStatus.CONFIRMED:
                # Match by rule_id if available
                if finding.rule_id and ff.rule_id and finding.rule_id == ff.rule_id:
                    still_present_finding = ff
                    break
                # Match by exact title
                if finding.title.lower().strip() == ff.title.lower().strip():
                    still_present_finding = ff
                    break
            elif ff.status == ObservationStatus.OBSERVED:
                # Potential positive proof that a defense is now enabled
                if finding.rule_id and ff.rule_id and finding.rule_id == ff.rule_id:
                    positive_evidence = ff.evidence
                elif finding.category == ff.category:
                    positive_evidence = ff.evidence

        if still_present_finding is not None:
            # Flaw is STILL present on the target
            finding.status = ObservationStatus.CONFIRMED
            finding.evidence = still_present_finding.evidence  # Update with latest proof
            res = VerificationResult(
                verification_id=f"vrf_{uuid.uuid4().hex[:8]}",
                scan_id=scan_result.scan_id,
                finding_id=finding.id,
                status=VerificationStatus.STILL_VULNERABLE,
                message=(
                    f"Verification complete: Flaw persists on target host '{scan_result.target.host}'. "
                    f"Fresh empirical check re-confirmed the issue: {still_present_finding.evidence.summary}"
                ),
                score_before=score_before,
                score_after=score_before,
                score_delta=0,
                before_evidence_summary=before_summary,
                after_evidence=still_present_finding.evidence,
            )
            finding.verification_history.append(res)
            return res

        # Flaw is NOT found! It has been FIXED with fresh empirical proof
        finding.status = ObservationStatus.FIXED

        if not positive_evidence:
            # Construct verified fix evidence from successful probe execution
            positive_evidence = Evidence(
                type=finding.evidence.type,
                summary=(
                    f"Target '{scan_result.target.host}' verified remediated. "
                    f"Prior condition '{finding.title}' is no longer triggered on the wire."
                ),
                timestamp=datetime.now(timezone.utc),
            )

        # Update finding evidence to reflect positive verification
        finding.evidence = positive_evidence

        # Recalculate deterministic score card
        new_card = calculate_score_card(scan_result.findings, header_matrix=scan_result.header_test_matrix)
        scan_result.score_card = new_card
        score_after = new_card.overall_score
        score_delta = score_after - score_before

        res = VerificationResult(
            verification_id=f"vrf_{uuid.uuid4().hex[:8]}",
            scan_id=scan_result.scan_id,
            finding_id=finding.id,
            status=VerificationStatus.FIXED,
            message=(
                f"Fix verified with fresh empirical evidence! '{finding.title}' has been successfully remediated. "
                f"Score updated from {score_before} to {score_after} (+{score_delta} points)."
            ),
            score_before=score_before,
            score_after=score_after,
            score_delta=score_delta,
            before_evidence_summary=before_summary,
            after_evidence=positive_evidence,
        )
        finding.verification_history.append(res)
        return res
