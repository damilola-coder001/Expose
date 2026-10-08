"""Tests for Live Threat Intelligence and CISA KEV Exploitation Engine (Phase 34)."""

import pytest

from expose.core.models import Severity
from expose.intelligence.threat_intel import (
    ThreatIntelCorrelator,
    ThreatIntelStore,
    get_threat_intel,
)


def test_threat_intel_store_lookup():
    """Validates KEV store querying and indexing."""
    store = get_threat_intel()
    assert store.total_count >= 5

    # Look up by CVE
    log4j = store.get_cve("CVE-2021-44228")
    assert log4j is not None
    assert "Log4j" in log4j.product
    assert log4j.known_ransomware_campaign_use == "Known"

    # Search by product
    apache_vulns = store.search_by_product("Apache")
    assert len(apache_vulns) >= 2


def test_threat_intel_software_banner_correlation():
    """Validates correlating detected server banners against active KEV exploits."""
    correlator = ThreatIntelCorrelator()

    # Apache 2.4.49 banner matches CVE-2021-41773
    banner = "Apache/2.4.49 (Unix) OpenSSL/1.1.1"
    findings = correlator.correlate_software_banner(banner, target_url="https://vulnerable.corp")

    assert len(findings) >= 1
    kev_finding = next((f for f in findings if "CVE-2021-41773" in f.title), None)
    assert kev_finding is not None
    assert kev_finding.severity == Severity.CRITICAL
    assert "Path Traversal" in kev_finding.description
    assert "CISA Directive Action" in kev_finding.remediation
    assert "CWE-1395" in kev_finding.cwe_id


def test_threat_intel_no_match_for_clean_banner():
    """Validates clean banners produce zero false positives."""
    correlator = ThreatIntelCorrelator()
    banner = "nginx/1.24.0 (Ubuntu)"
    findings = correlator.correlate_software_banner(banner, target_url="https://clean.corp")
    assert len(findings) == 0
