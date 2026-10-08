"""Comprehensive unit tests for deep security probes and detection engines.

Validates deep TLS cipher suite testing, DNS takeover detection, DOM XSS sink inspection,
postMessage listener analysis, expanded Nuclei templates, and WAF fingerprinting.
"""

import pytest
import dns.exception
from expose.core.models import (
    Category,
    Confidence,
    ObservationStatus,
    Severity,
    TargetScope,
)
from expose.probes.tls_probe import TLSProbe
from expose.probes.dns_probe import DNSProbe
from expose.probes.clientside_probe import ClientSideProbe
from expose.probes.nuclei_probe import NucleiProbe
from expose.probes.waf_probe import WAFProbe
from expose.probes.nmap_probe import NmapProbe


@pytest.fixture
def dummy_target():
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


# 1. WAF & Edge Security Probe Tests
@pytest.mark.asyncio
async def test_waf_probe_detects_cloudflare(dummy_target, monkeypatch):
    probe = WAFProbe()

    class MockResponse:
        def __init__(self):
            self.status_code = 200
            self.headers = {
                "server": "cloudflare",
                "cf-ray": "8c123456789-LHR",
                "cf-cache-status": "DYNAMIC",
            }

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    titles = [f.title for f in findings]
    assert any("Edge Web Application Firewall Detected (Cloudflare)" in t for t in titles)
    waf_finding = next(f for f in findings if "Cloudflare" in f.title)
    assert waf_finding.severity == Severity.INFO
    assert waf_finding.status == ObservationStatus.OBSERVED
    assert waf_finding.category == Category.CONFIGURATION


@pytest.mark.asyncio
async def test_waf_probe_detects_no_waf(dummy_target, monkeypatch):
    probe = WAFProbe()

    class MockResponse:
        def __init__(self):
            self.status_code = 200
            self.headers = {
                "server": "Apache/2.4.41 (Ubuntu)",
                "content-type": "text/html",
            }

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    titles = [f.title for f in findings]
    assert any("No Edge WAF or Cloud Reverse Proxy Detected" in t for t in titles)
    no_waf = next(f for f in findings if "No Edge WAF" in f.title)
    assert no_waf.severity == Severity.LOW
    assert no_waf.status == ObservationStatus.CONFIRMED


@pytest.mark.asyncio
async def test_waf_probe_reports_edge_challenge_as_scope_boundary(dummy_target, monkeypatch):
    probe = WAFProbe()

    class MockResponse:
        status_code = 403
        headers = {"server": "Vercel", "x-vercel-mitigated": "challenge"}

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    assert len(findings) == 1
    assert findings[0].title == "Edge Security Challenge Intercepted Automated Assessment"
    assert findings[0].status == ObservationStatus.OBSERVED


@pytest.mark.asyncio
async def test_public_edge_and_dns_controls_are_skipped_for_private_targets():
    private_target = TargetScope(
        raw_target="http://127.0.0.1:8000",
        normalized_url="http://127.0.0.1:8000",
        scheme="http",
        host="127.0.0.1",
        port=8000,
        resolved_ips=["127.0.0.1"],
        is_private=True,
        allow_private=True,
    )

    assert await DNSProbe().execute(private_target) == []
    assert await WAFProbe().execute(private_target) == []


def test_private_port_scan_does_not_claim_public_exposure():
    private_target = TargetScope(
        raw_target="http://127.0.0.1:8000",
        normalized_url="http://127.0.0.1:8000",
        scheme="http",
        host="127.0.0.1",
        port=8000,
        resolved_ips=["127.0.0.1"],
        is_private=True,
        allow_private=True,
    )

    finding = NmapProbe()._create_port_finding(private_target, 445, "tcp", "SMB", "SMB", False)

    assert finding.severity == Severity.INFO
    assert finding.status == ObservationStatus.OBSERVED
    assert "Non-Public SMB" in finding.title


@pytest.mark.asyncio
async def test_dns_timeout_does_not_create_missing_record_findings(dummy_target, monkeypatch):
    probe = DNSProbe()

    def unavailable(*args, **kwargs):
        raise dns.exception.Timeout

    monkeypatch.setattr("dns.resolver.Resolver.resolve", unavailable)

    assert await probe.execute(dummy_target) == []


def test_zone_transfer_check_handles_unavailable_nameservers(dummy_target, monkeypatch):
    probe = DNSProbe()
    monkeypatch.setattr(probe, "_query_records", lambda *args: None)

    assert probe._check_zone_transfer(dummy_target, object(), "example.com") == []


# 2. Client-Side DOM XSS & postMessage Tests
@pytest.mark.asyncio
async def test_clientside_probe_detects_dom_sinks_and_postmessage(dummy_target, monkeypatch):
    probe = ClientSideProbe()

    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>App</title></head>
    <body>
        <script>
            // Unsafe postMessage listener
            window.addEventListener("message", function(e) {
                eval(e.data);
            });

            // Dangerous DOM Sink
            document.getElementById("output").innerHTML = location.search;

            // Insecure Token storage
            localStorage.setItem("jwt", "eyJhbGciOiJIUzI1Ni...");
        </script>
    </body>
    </html>
    """

    class MockResponse:
        def __init__(self):
            self.status_code = 200
            self.text = html_content

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    titles = [f.title for f in findings]

    assert any("Insecure Cross-Window postMessage Listener" in t for t in titles)
    assert any("Potential DOM-Based XSS Sink" in t for t in titles)
    assert any("Sensitive Authentication Token Stored in localStorage" in t for t in titles)

    pm_finding = next(f for f in findings if "postMessage" in f.title)
    assert pm_finding.severity == Severity.HIGH
    assert pm_finding.confidence == Confidence.CONFIRMED


# 3. Expanded Nuclei Templates Tests
@pytest.mark.asyncio
async def test_nuclei_probe_detects_actuator_and_sql_dump(dummy_target, monkeypatch):
    probe = NucleiProbe()

    class MockResponse:
        def __init__(self, url, status_code=200, text=""):
            self.url = url
            self.status_code = status_code
            self.text = text

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            if "/actuator/env" in url:
                return MockResponse(url, 200, '{"activeProfiles":["prod"],"propertySources":[]}')
            if "/dump.sql" in url:
                return MockResponse(url, 200, "CREATE TABLE users (id INT, password VARCHAR(255));")
            if "/phpinfo.php" in url:
                return MockResponse(url, 200, "PHP Version 8.1.2 - Configuration")
            return MockResponse(url, 404, "Not found")

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    titles = [f.title for f in findings]

    assert any("Spring Boot Actuator Environment" in t for t in titles)
    assert any("Database SQL Dump (dump.sql) Exposed" in t for t in titles)
    assert any("PHPInfo Diagnostic Page" in t for t in titles)

    sql_finding = next(f for f in findings if "dump.sql" in f.title)
    assert sql_finding.severity == Severity.CRITICAL
    assert sql_finding.status == ObservationStatus.CONFIRMED


# 4. DNS Dangling CNAME & Subdomain Takeover Test
@pytest.mark.asyncio
async def test_dns_subdomain_takeover_detection(dummy_target, monkeypatch):
    probe = DNSProbe()

    def mock_query_records(resolver, qname, rtype):
        if rtype == "CNAME":
            return ["my-site.github.io."]
        if rtype == "CAA":
            return ["0 issue \"letsencrypt.org\""]
        if rtype == "TXT" and "_dmarc" not in qname:
            return ["v=spf1 include:_spf.google.com -all"]
        if rtype == "TXT" and "_dmarc" in qname:
            return ["v=DMARC1; p=reject;"]
        return []

    monkeypatch.setattr(probe, "_query_records", mock_query_records)
    monkeypatch.setattr(probe, "_check_dnssec", lambda *args: True)

    class MockResponse:
        def __init__(self):
            self.status_code = 404
            self.text = "404 There isn't a GitHub Pages site here."

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    titles = [f.title for f in findings]

    assert any("Potential Subdomain Takeover: Dangling CNAME to GitHub Pages" in t for t in titles)
    takeover_finding = next(f for f in findings if "Subdomain Takeover" in f.title)
    assert takeover_finding.severity == Severity.HIGH
    assert takeover_finding.category == Category.DNS_CONFIGURATION
