"""Core domain models and typed schemas for the Expose security intelligence platform.

Enforces strict evidence capture, empirical observation taxonomy, deterministic scoring,
and explicit assessment boundary declarations.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator

from .attack_surface import AttackSurface
from expose.intelligence.provider import AIIntelligenceReport, AIPrioritizationReport


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"        # Direct mathematical / cryptographic / protocol proof
    LIKELY = "LIKELY"              # Strongly evidenced behavior with high certainty
    POTENTIAL = "POTENTIAL"        # Theoretical weakness or banner-indicated possibility
    INFORMATIONAL = "INFORMATIONAL"# Neutral observation or architectural discovery


class ObservationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"        # Direct verified flaw, vulnerability, or misconfiguration
    OBSERVED = "OBSERVED"          # Neutral or positive empirical observation (e.g. TLS 1.3 negotiated)
    INFERRED = "INFERRED"          # Corroborated inference with explicit confidence rating
    NOT_ASSESSED = "NOT_ASSESSED"  # Explicitly outside the scope of an external unauthenticated scan
    FIXED = "FIXED"                # Remediated weakness verified with new empirical evidence
    REMEDIATED = "FIXED"           # Alias for FIXED


class VerificationStatus(str, Enum):
    FIXED = "FIXED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    FAILED = "FAILED"


class HeaderTestStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"


class HeaderTestResult(BaseModel):
    id: str = Field(description="Deterministic identifier for this header test (e.g. 'content-security-policy')")
    name: str = Field(description="Human readable name of the test (e.g. 'Content Security Policy')")
    header_name: Optional[str] = Field(default=None, description="HTTP header assessed, if applicable")
    status: HeaderTestStatus = Field(description="Evaluation verdict: PASS, WARN, FAIL, or INFO")
    score_modifier: int = Field(description="Point deduction or bonus applied to the base score (-25, -20, -5, +5, 0)")
    observed_value: Optional[str] = Field(default=None, description="Actual value observed on the wire")
    expected_value: str = Field(description="Target standard value or directive requirement")
    description: str = Field(description="Why this security control is necessary")
    advice: str = Field(description="Actionable remediation advice")
    doc_url: str = Field(description="Authoritative MDN / W3C documentation link")


class Category(str, Enum):
    # Phase 9 Canonical Categories
    TRANSPORT_SECURITY = "TRANSPORT_SECURITY"
    BROWSER_SECURITY = "BROWSER_SECURITY"
    COOKIE_SESSION_SECURITY = "COOKIE_SESSION_SECURITY"
    CONFIGURATION = "CONFIGURATION"
    ATTACK_SURFACE = "ATTACK_SURFACE"
    INFORMATION_EXPOSURE = "INFORMATION_EXPOSURE"
    API_SECURITY = "API_SECURITY"
    THIRD_PARTY_RESOURCES = "THIRD_PARTY_RESOURCES"
    AUTHENTICATION = "AUTHENTICATION"

    # Compatibility aliases
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    TLS_POSTURE = "TRANSPORT_SECURITY"
    COOKIE_SECURITY = "COOKIE_SESSION_SECURITY"
    HTTP_HEADERS = "BROWSER_SECURITY"
    DNS_CONFIGURATION = "DNS_CONFIGURATION"
    EMAIL_SECURITY = "EMAIL_SECURITY"
    SECURITY_METADATA = "SECURITY_METADATA"
    NETWORK_POSTURE = "NETWORK_POSTURE"
    CLIENT_SIDE_SECURITY = "CLIENT_SIDE_SECURITY"
    EXTERNAL_EXPOSURE = "EXTERNAL_EXPOSURE"
    INFORMATION_DISCLOSURE = "INFORMATION_EXPOSURE"


FindingCategory = Category


class EvidenceType(str, Enum):
    HTTP_EXCHANGE = "HTTP_EXCHANGE"
    DNS_RECORD = "DNS_RECORD"
    TLS_HANDSHAKE = "TLS_HANDSHAKE"
    CERTIFICATE_METADATA = "CERTIFICATE_METADATA"
    RAW_SOCKET = "RAW_SOCKET"
    SECURITY_TXT = "SECURITY_TXT"
    SOURCE_MAP = "SOURCE_MAP"
    CLIENT_CONFIG = "CLIENT_CONFIG"
    NUCLEI_MATCH = "NUCLEI_MATCH"
    SCRIPT_REFERENCE = "SCRIPT_REFERENCE"
    DOM_CONTENT = "DOM_CONTENT"
    NMAP_OUTPUT = "NMAP_OUTPUT"
    NIKTO_OUTPUT = "NIKTO_OUTPUT"
    SCAP_RESULT = "SCAP_RESULT"
    GVM_RESULT = "GVM_RESULT"


class Evidence(BaseModel):
    type: EvidenceType
    summary: str = Field(description="Brief summary of what the evidence proves")
    request: Optional[Dict[str, Any]] = Field(default=None, description="HTTP request details if applicable")
    response: Optional[Dict[str, Any]] = Field(default=None, description="HTTP response details if applicable")
    raw_data: Optional[Dict[str, Any]] = Field(default=None, description="Arbitrary verifiable proof (DNS answers, TLS cert dict, etc.)")
    matched_data: Optional[str] = Field(default=None, description="Specific matched string or snippet from target")
    command: Optional[str] = Field(default=None, description="CLI command to reproduce the evidence")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


TechnicalEvidence = Evidence


class VerificationResult(BaseModel):
    verification_id: str = Field(description="Unique identifier for this verification attempt")
    scan_id: str = Field(description="Associated scan ID")
    finding_id: str = Field(description="Associated finding ID")
    status: VerificationStatus = Field(description="Verification verdict: FIXED, STILL_VULNERABLE, or FAILED")
    message: str = Field(description="Human-readable explanation of the empirical verification result")
    score_before: int = Field(description="Security score before verification")
    score_after: int = Field(description="Security score after verification")
    score_delta: int = Field(description="Point change (positive when fixed)")
    before_evidence_summary: str = Field(description="Summary of prior flaw evidence")
    after_evidence: Optional[Evidence] = Field(default=None, description="Fresh empirical wire evidence captured during verification")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RiskAssessment(BaseModel):
    posture_summary: str
    critical_risks: List[str] = Field(default_factory=list)
    positive_notes: List[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str = Field(description="Unique deterministic identifier for this finding")
    probe: str = Field(description="Identifier of probe that created this finding")
    target: str = Field(description="Target host or URL")
    category: Category
    severity: Severity
    confidence: Confidence
    status: ObservationStatus = Field(
        default=ObservationStatus.CONFIRMED,
        description="Observation taxonomy: CONFIRMED flaw, OBSERVED property, INFERRED pattern, or FIXED"
    )
    title: str
    description: str
    impact_explanation: Optional[str] = Field(
        default=None,
        description="Authoritative technical context explaining why this observation matters and its risk"
    )
    remediation: str
    verification_command: Optional[str] = Field(
        default=None,
        description="Independent reproducible CLI command (curl, openssl, dig) to verify this observation"
    )
    rule_id: Optional[str] = Field(default=None, description="Identifier of the rule or check producing this finding")
    owasp_top10: Optional[str] = Field(default=None, description="OWASP Top 10:2025 risk taxonomy mapping")
    owasp_asvs: Optional[str] = Field(default=None, description="OWASP ASVS 5.0.0 technical verification control mapping")
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    ai_intelligence: Optional[AIIntelligenceReport] = Field(default=None, description="AI security intelligence report")
    evidence: Evidence
    verification_history: List[VerificationResult] = Field(
        default_factory=list,
        description="Historical log of empirical verification attempts"
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # UI compatibility aliases & fields
    impact: Optional[str] = None
    recommendation: Optional[Dict[str, Any]] = None
    verification: Optional[Dict[str, Any]] = None
    cwe: Optional[str] = None
    cve: Optional[str] = None

    @model_validator(mode="after")
    def populate_compat_fields(self):
        if not self.impact:
            self.impact = self.impact_explanation or self.description
        if not self.recommendation:
            self.recommendation = {
                "summary": self.title,
                "remediation": self.remediation,
                "config_snippet": None,
            }
        if not self.verification and self.verification_command:
            tool = "curl"
            if "openssl" in self.verification_command:
                tool = "openssl"
            elif "dig" in self.verification_command:
                tool = "dig"
            self.verification = {
                "command": self.verification_command,
                "tool": tool,
                "description": f"CLI command to independently verify {self.title}",
            }
        if not self.cwe and self.cwe_id:
            self.cwe = self.cwe_id
        if not self.cve and self.cve_id:
            self.cve = self.cve_id
        return self


class NotAssessedArea(BaseModel):
    area: str = Field(description="Name of the security domain not evaluated")
    reason: str = Field(description="Why this cannot be evaluated in an unauthenticated external scan")
    explanation: str = Field(description="What would be required for full assessment")


class CategoryScore(BaseModel):
    category_name: str
    score: int = Field(ge=0, le=100)
    weight_percentage: int
    findings_count: int
    confirmed_issues_count: int


class ScoreCard(BaseModel):
    score_version: str = "1.0"
    overall_score: int = Field(ge=0, le=100, description="Overall Security Posture Score (0-100)")
    letter_grade: str = Field(description="Letter grade: A+, A, B, C, D, or F")
    score_philosophy: str = Field(
        default="This score reflects the externally observable security controls and findings assessed by Expose. The score is not a guarantee that a website is secure.",
        description="Core philosophy statement clarifying score context and non-guarantee (Rule 36)"
    )
    category_scores: Dict[str, CategoryScore] = Field(default_factory=dict)
    confirmed_flaws_count: int = 0
    observed_properties_count: int = 0
    not_assessed_boundaries: List[NotAssessedArea] = Field(default_factory=list)
    header_test_matrix: List[HeaderTestResult] = Field(
        default_factory=list,
        description="Mozilla HTTP Observatory deterministic header evaluation test matrix"
    )

    @property
    def score_display(self) -> str:
        """Standardized non-misleading score representation: 'Security Score: 84/100'."""
        return f"{self.overall_score} / 100"


class TargetScope(BaseModel):
    raw_target: str
    normalized_url: str
    scheme: str
    host: str
    port: int
    resolved_ips: List[str] = Field(default_factory=list)
    is_private: bool = False
    allow_private: bool = False


class ProbeStatus(BaseModel):
    probe_name: str
    status: str  # "completed", "failed", "skipped"
    duration_seconds: float
    error_message: Optional[str] = None


class ScanResult(BaseModel):
    scan_id: str
    target: TargetScope
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    score_card: Optional[ScoreCard] = None
    attack_surface: Optional[AttackSurface] = None
    header_test_matrix: List[HeaderTestResult] = Field(default_factory=list)
    probe_statuses: List[ProbeStatus] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    ai_prioritization: Optional[AIPrioritizationReport] = Field(default=None, description="Holistic AI remediation roadmap")

    # UI compatibility aliases & fields
    id: Optional[str] = None
    target_id: Optional[str] = None
    raw_target: Optional[str] = None
    normalized_url: Optional[str] = None
    status: str = "COMPLETED"
    risk_assessment: Optional[RiskAssessment] = None
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    domain_verified: bool = False
    domain_ownership_proof: Optional[str] = None

    @model_validator(mode="after")
    def populate_scan_compat_fields(self):
        if not self.id:
            self.id = self.scan_id
        if not self.target_id and self.target:
            self.target_id = self.target.host
        if not self.raw_target and self.target:
            self.raw_target = self.target.raw_target
        if not self.normalized_url and self.target:
            self.normalized_url = self.target.normalized_url

        if self.target and not self.domain_verified:
            try:
                from expose.core.ownership import get_ownership_verifier
                record = get_ownership_verifier().get_record(self.target.host)
                if record and record.verified:
                    self.domain_verified = True
                    self.domain_ownership_proof = record.proof
            except Exception:
                pass

        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.status == ObservationStatus.CONFIRMED:
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        self.severity_counts = counts

        if not self.risk_assessment and self.score_card:
            criticals = []
            positives = []
            for f in self.findings:
                if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.status == ObservationStatus.CONFIRMED:
                    criticals.append(f"{f.title}: {f.impact or f.description}")
                elif f.severity == Severity.INFO and f.status == ObservationStatus.OBSERVED:
                    positives.append(f.title)

            summary = (
                f"Observed security posture scored at {self.score_card.overall_score}/100 (Grade {self.score_card.letter_grade}). "
                f"Verified {self.score_card.confirmed_flaws_count} confirmed flaws and {self.score_card.observed_properties_count} positive security controls."
            )
            if not criticals:
                summary += " No critical or high-severity vulnerabilities were externally observable."
            else:
                summary += f" {len(criticals)} urgent issues require remediation."

            self.risk_assessment = RiskAssessment(
                posture_summary=summary,
                critical_risks=criticals,
                positive_notes=positives,
            )
        return self
