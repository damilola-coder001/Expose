"""Base probe interface and utilities for Expose security analyzers."""

from abc import ABC, abstractmethod
import hashlib
from typing import List, Optional
from datetime import datetime, timezone

from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    ObservationStatus,
    Severity,
    TargetScope,
)
from expose.core.standards import resolve_standards_mapping


class BaseProbe(ABC):
    """Abstract base class for all security intelligence probes."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the probe."""
        pass

    @property
    @abstractmethod
    def category(self) -> Category:
        """Primary category of findings produced by this probe."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what the probe assesses."""
        pass

    @abstractmethod
    async def execute(self, target: TargetScope) -> List[Finding]:
        """Runs the probe against the target and returns verified findings."""
        pass

    def get_http_client(
        self,
        target: TargetScope,
        verify: bool = False,
        follow_redirects: bool = True,
        timeout: float = 8.0,
        **kwargs,
    ):
        """Returns a safe httpx.AsyncClient with socket-level anti-DNS-rebinding protection."""
        from expose.core.safety import create_safe_async_client

        return create_safe_async_client(
            target=target,
            verify=verify,
            follow_redirects=follow_redirects,
            timeout=timeout,
            **kwargs,
        )

    def create_finding(
        self,
        target: TargetScope,
        title: str,
        severity: Severity,
        confidence: Confidence,
        description: str,
        remediation: str,
        evidence: Evidence,
        status: ObservationStatus = ObservationStatus.CONFIRMED,
        impact_explanation: Optional[str] = None,
        verification_command: Optional[str] = None,
        category: Optional[Category] = None,
        rule_id: Optional[str] = None,
        owasp_top10: Optional[str] = None,
        owasp_asvs: Optional[str] = None,
        cwe_id: Optional[str] = None,
        cve_id: Optional[str] = None,
    ) -> Finding:
        """Constructs a deterministic finding model with attached evidence, standards mapping, and verification command."""
        # Create a stable deterministic ID based on probe name, target host, title, and CWE
        hash_input = f"{self.name}:{target.host}:{title}:{cwe_id or ''}"
        finding_id = f"EXP-{hashlib.sha256(hash_input.encode()).hexdigest()[:12].upper()}"

        # Resolve authoritative standards (OWASP Top 10:2025 and OWASP ASVS 5.0) if not explicitly supplied
        if not owasp_top10 or not owasp_asvs:
            std_mapping = resolve_standards_mapping(
                rule_id=rule_id,
                title=title,
                cwe_id=cwe_id,
                cve_id=cve_id,
                is_observation=(status != ObservationStatus.CONFIRMED),
            )
            if std_mapping:
                owasp_top10 = owasp_top10 or std_mapping.owasp_top10
                owasp_asvs = owasp_asvs or std_mapping.owasp_asvs
                cwe_id = cwe_id or std_mapping.cwe_id
                cve_id = cve_id or std_mapping.cve_id

        return Finding(
            id=finding_id,
            probe=self.name,
            target=target.normalized_url,
            category=category or self.category,
            severity=severity,
            confidence=confidence,
            status=status,
            title=title,
            description=description,
            impact_explanation=impact_explanation,
            remediation=remediation,
            verification_command=verification_command,
            rule_id=rule_id,
            owasp_top10=owasp_top10,
            owasp_asvs=owasp_asvs,
            cwe_id=cwe_id,
            cve_id=cve_id,
            evidence=evidence,
            timestamp=datetime.now(timezone.utc),
        )
