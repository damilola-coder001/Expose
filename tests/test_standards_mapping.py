"""Unit tests for Phase 10 — OWASP / Security Standards Mapping.

Validates that empirical findings map correctly to:
- OWASP Top 10:2025
- OWASP ASVS 5.0 (5.0.0 release)
- CWE
- Unforced mappings for neutral or informational observations.
"""

from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    ObservationStatus,
    Severity,
    TargetScope,
)
from expose.core.standards import (
    OWASP_TOP_10_2025,
    STANDARDS_CATALOG,
    resolve_standards_mapping,
)
from expose.probes.http_headers_probe import HTTPHeadersProbe
from expose.probes.tls_probe import TLSProbe
from expose.probes.cookie_probe import CookieProbe


def test_owasp_top_10_2025_taxonomy_coverage():
    """Validates that all OWASP Top 10:2025 categories are defined."""
    assert len(OWASP_TOP_10_2025) == 10
    assert OWASP_TOP_10_2025["A01:2025"] == "A01:2025 - Broken Access Control"
    assert OWASP_TOP_10_2025["A02:2025"] == "A02:2025 - Cryptographic Failures"
    assert OWASP_TOP_10_2025["A05:2025"] == "A05:2025 - Security Misconfiguration"
    assert OWASP_TOP_10_2025["A07:2025"] == "A07:2025 - Identification and Authentication Failures"
    assert OWASP_TOP_10_2025["A08:2025"] == "A08:2025 - Software and Data Integrity Failures"
    assert OWASP_TOP_10_2025["A10:2025"] == "A10:2025 - Server-Side Request Forgery (SSRF)"


def test_hsts_mapping():
    """HSTS missing should map to OWASP Top 10:2025 A05, ASVS V9.2.1, and CWE-319."""
    mapping = resolve_standards_mapping(rule_id="EXP-HSTS-MISSING")
    assert mapping is not None
    assert mapping.owasp_top10 == "A05:2025 - Security Misconfiguration"
    assert mapping.owasp_asvs == "V9.2.1"
    assert mapping.cwe_id == "CWE-319"


def test_csp_mapping():
    """CSP missing should map to OWASP Top 10:2025 A05, ASVS V14.4.1, and CWE-693."""
    mapping = resolve_standards_mapping(rule_id="EXP-CSP-MISSING")
    assert mapping is not None
    assert mapping.owasp_top10 == "A05:2025 - Security Misconfiguration"
    assert mapping.owasp_asvs == "V14.4.1"
    assert mapping.cwe_id == "CWE-693"


def test_cookie_security_mapping():
    """Insecure cookie should map to A07:2025 and ASVS V3.4."""
    mapping = resolve_standards_mapping(rule_id="EXP-COOKIE-NO-SECURE")
    assert mapping is not None
    assert mapping.owasp_top10 == "A07:2025 - Identification and Authentication Failures"
    assert mapping.owasp_asvs == "V3.4.1"
    assert mapping.cwe_id == "CWE-614"


def test_subresource_integrity_mapping():
    """Missing SRI should map to A08:2025 Software & Data Integrity Failures and ASVS V14.4.7."""
    mapping = resolve_standards_mapping(rule_id="EXP-SRI-MISSING")
    assert mapping is not None
    assert mapping.owasp_top10 == "A08:2025 - Software and Data Integrity Failures"
    assert mapping.owasp_asvs == "V14.4.7"
    assert mapping.cwe_id == "CWE-353"


def test_tls_expired_mapping():
    """Expired TLS certificate should map to A02:2025 Cryptographic Failures and ASVS V9.1.3."""
    mapping = resolve_standards_mapping(rule_id="EXP-TLS-EXPIRED")
    assert mapping is not None
    assert mapping.owasp_top10 == "A02:2025 - Cryptographic Failures"
    assert mapping.owasp_asvs == "V9.1.3"
    assert mapping.cwe_id == "CWE-295"


def test_do_not_force_mapping_on_neutral_observations():
    """Strict Rule: Do not force mappings where they do not make sense (e.g. neutral observations)."""
    mapping = resolve_standards_mapping(
        title="TLS 1.3 Negotiated Successfully",
        is_observation=True,
    )
    assert mapping is None

    mapping_inventory = resolve_standards_mapping(
        title="Discovered Public Web Page",
        is_observation=True,
    )
    assert mapping_inventory is None


def test_base_probe_automatically_populates_standards():
    """Verify that BaseProbe.create_finding automatically resolves OWASP and ASVS mappings."""
    probe = HTTPHeadersProbe()
    target = TargetScope(
        raw_target="https://example.com",
        normalized_url="https://example.com",
        scheme="https",
        host="example.com",
        port=443,
    )
    evidence = Evidence(
        type=EvidenceType.HTTP_EXCHANGE,
        summary="Strict-Transport-Security header missing from response.",
    )

    finding = probe.create_finding(
        target=target,
        title="Strict-Transport-Security Header Missing",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        status=ObservationStatus.CONFIRMED,
        description="Missing HSTS header.",
        remediation="Add Strict-Transport-Security header.",
        evidence=evidence,
        rule_id="EXP-HSTS-MISSING",
        category=Category.TRANSPORT_SECURITY,
    )

    assert finding.owasp_top10 == "A05:2025 - Security Misconfiguration"
    assert finding.owasp_asvs == "V9.2.1"
    assert finding.cwe_id == "CWE-319"


def test_base_probe_omits_standards_for_observed_status():
    """Verify that BaseProbe.create_finding does not force standards on OBSERVED technical properties."""
    probe = TLSProbe()
    target = TargetScope(
        raw_target="https://example.com",
        normalized_url="https://example.com",
        scheme="https",
        host="example.com",
        port=443,
    )
    evidence = Evidence(
        type=EvidenceType.TLS_HANDSHAKE,
        summary="TLS 1.3 negotiated with strong cipher suite.",
    )

    finding = probe.create_finding(
        target=target,
        title="TLS 1.3 Negotiated with Modern Forward Secrecy",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        status=ObservationStatus.OBSERVED,
        description="Positive cryptographic control observed.",
        remediation="Maintain current configuration.",
        evidence=evidence,
        category=Category.TRANSPORT_SECURITY,
    )

    # Must be unmapped
    assert finding.owasp_top10 is None
    assert finding.owasp_asvs is None
