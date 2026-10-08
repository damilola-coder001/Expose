"""Unit tests for integrated enterprise scanners: Nmap, Nikto, OpenSCAP, and GVM."""

import pytest
from unittest.mock import AsyncMock, patch
from expose.core.models import Category, Confidence, ObservationStatus, Severity, TargetScope
from expose.probes import NmapProbe, NiktoProbe, OpenSCAPProbe, GVMProbe
from expose.core.verifier import PROBE_REGISTRY


@pytest.fixture
def target_scope():
    return TargetScope(
        raw_target="https://example.com",
        normalized_url="https://example.com",
        scheme="https",
        host="example.com",
        port=443,
        resolved_ips=["93.184.216.34"],
        is_private=False,
        allow_private=False,
    )


def test_probe_registry_contains_new_scanners():
    """Verify that Nmap, Nikto, OpenSCAP, and GVM are registered in PROBE_REGISTRY."""
    assert "nmap" in PROBE_REGISTRY
    assert "nikto" in PROBE_REGISTRY
    assert "openscap" in PROBE_REGISTRY
    assert "gvm" in PROBE_REGISTRY
    assert PROBE_REGISTRY["nmap"] == NmapProbe
    assert PROBE_REGISTRY["nikto"] == NiktoProbe
    assert PROBE_REGISTRY["openscap"] == OpenSCAPProbe
    assert PROBE_REGISTRY["gvm"] == GVMProbe


# --- NMAP PROBE TESTS ---

def test_nmap_xml_parsing(target_scope):
    probe = NmapProbe()
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap -sV -p 80,3306 example.com">
      <host>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="nginx" version="1.18.0"/>
          </port>
          <port protocol="tcp" portid="3306">
            <state state="open"/>
            <service name="mysql" product="MySQL" version="8.0.25"/>
          </port>
          <port protocol="tcp" portid="22">
            <state state="closed"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    findings = probe._parse_nmap_xml(sample_xml, target_scope)
    assert len(findings) == 2

    # Verify open HTTP port is recorded as INFO / OBSERVED
    http_finding = next(f for f in findings if "80" in f.title)
    assert http_finding.severity == Severity.INFO
    assert http_finding.status == ObservationStatus.OBSERVED

    # Verify exposed database port 3306 is recorded as CRITICAL / CONFIRMED
    db_finding = next(f for f in findings if "3306" in f.title)
    assert db_finding.severity == Severity.CRITICAL
    assert db_finding.status == ObservationStatus.CONFIRMED
    assert db_finding.cwe_id == "CWE-284"


@pytest.mark.asyncio
async def test_nmap_async_tcp_scan_identifies_open_ports(target_scope, monkeypatch):
    probe = NmapProbe()

    # Mock asyncio.open_connection to simulate open ports 443 and 6379 (Redis)
    async def mock_open_connection(host, port, **kwargs):
        if port in (443, 6379):
            mock_writer = AsyncMock()
            mock_writer.close = lambda: None
            mock_writer.wait_closed = AsyncMock()
            return AsyncMock(), mock_writer
        raise ConnectionRefusedError()

    monkeypatch.setattr("asyncio.open_connection", mock_open_connection)

    findings = await probe._execute_async_tcp_scan(target_scope)
    redis_finding = next((f for f in findings if "Redis" in f.title), None)
    assert redis_finding is not None
    assert redis_finding.severity == Severity.CRITICAL
    assert redis_finding.confidence == Confidence.CONFIRMED


# --- NIKTO PROBE TESTS ---

@pytest.mark.asyncio
async def test_nikto_detects_server_version_and_missing_clickjacking(target_scope, monkeypatch):
    probe = NiktoProbe()

    class MockResponse:
        def __init__(self, url):
            self.status_code = 200
            self.headers = {
                "server": "Apache/2.4.41 (Ubuntu)",
                "x-powered-by": "PHP/7.4.3",
            }
            self.text = "<html><body>Welcome</body></html>"

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, **kwargs):
            return MockResponse(url)
        async def options(self, url, **kwargs):
            resp = MockResponse(url)
            resp.headers = {"allow": "GET, POST, OPTIONS, TRACE"}
            return resp

    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: MockClient())

    findings = await probe._execute_native_nikto_checks(target_scope)
    
    # Verify server banner finding
    server_finding = next((f for f in findings if "Server Version Disclosed" in f.title), None)
    assert server_finding is not None
    assert server_finding.severity == Severity.LOW
    assert "Apache/2.4.41" in server_finding.title

    # Verify HTTP TRACE finding
    trace_finding = next((f for f in findings if "HTTP TRACE" in f.title), None)
    assert trace_finding is not None
    assert trace_finding.severity == Severity.MEDIUM
    assert trace_finding.cwe_id == "CWE-693"

    # Verify missing clickjacking finding
    clickjack_finding = next((f for f in findings if "Anti-Clickjacking" in f.title), None)
    assert clickjack_finding is not None
    assert clickjack_finding.cwe_id == "CWE-1021"


# --- OPENSCAP PROBE TESTS ---

@pytest.mark.asyncio
async def test_openscap_evaluates_cis_baseline_rules(target_scope, monkeypatch):
    probe = OpenSCAPProbe()

    # Mock legacy TLS check returning True (deprecated protocol active)
    monkeypatch.setattr(probe, "_check_legacy_tls_support", AsyncMock(return_value=True))

    class MockResponse:
        status_code = 200
        headers = {
            "server": "nginx",
            # Missing HSTS, missing X-Content-Type-Options, missing CSP
        }
        text = "<html>OK</html>"

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: MockClient())

    findings = await probe._execute_scap_baseline_evaluation(target_scope)

    # Verify SCAP rule for deprecated TLS
    tls_scap = next((f for f in findings if "EXP-SCAP-TLS-DEPRECATED" in f.rule_id), None)
    assert tls_scap is not None
    assert tls_scap.severity == Severity.HIGH
    assert tls_scap.cwe_id == "CWE-326"

    # Verify SCAP rule for HSTS
    hsts_scap = next((f for f in findings if "EXP-SCAP-HSTS-MISSING" in f.rule_id), None)
    assert hsts_scap is not None
    assert hsts_scap.severity == Severity.MEDIUM


# --- GVM PROBE TESTS ---

def test_gvm_gmp_xml_parsing(target_scope):
    probe = GVMProbe()
    sample_gmp_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <get_results_response status="200" status_text="OK">
      <result id="res_1">
        <name>Apache Log4j Remote Code Execution</name>
        <description>Apache Log4j is vulnerable to JNDI injection (Log4Shell).</description>
        <threat>High</threat>
        <nvt oid="1.3.6.1.4.1.25623.1.0.147205">
          <cve>CVE-2021-44228</cve>
        </nvt>
      </result>
    </get_results_response>
    """
    findings = probe._parse_gmp_results(sample_gmp_xml, target_scope)
    assert len(findings) == 1
    f = findings[0]
    assert "Log4j" in f.title
    assert f.severity == Severity.HIGH
    assert f.cve_id == "CVE-2021-44228"
    assert "1.3.6.1.4.1.25623" in f.rule_id


@pytest.mark.asyncio
async def test_gvm_correlates_cve_from_vulnerable_banner(target_scope, monkeypatch):
    probe = GVMProbe()

    class MockResponse:
        status_code = 200
        headers = {
            "server": "Apache/2.4.49 (Unix)",
            "x-powered-by": "PHP/7.2.10",
        }
        text = "<html><script src='/js/jquery-1.12.4.min.js'></script></html>"

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: MockClient())

    findings = await probe._execute_cve_correlation(target_scope)

    # Should detect Apache 2.4.49 path traversal (CVE-2021-41773)
    apache_cve = next((f for f in findings if f.cve_id == "CVE-2021-41773"), None)
    assert apache_cve is not None
    assert apache_cve.severity == Severity.CRITICAL

    # Should detect EOL PHP (CVE-2021-21703)
    php_cve = next((f for f in findings if f.cve_id == "CVE-2021-21703"), None)
    assert php_cve is not None
    assert php_cve.severity == Severity.HIGH

    # Should detect vulnerable jQuery (CVE-2020-11022)
    jq_cve = next((f for f in findings if f.cve_id == "CVE-2020-11022"), None)
    assert jq_cve is not None
    assert jq_cve.severity == Severity.MEDIUM
