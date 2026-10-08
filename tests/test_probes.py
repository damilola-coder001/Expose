"""Unit tests for Expose security intelligence probes."""

import pytest
import httpx
from expose.core.models import Category, Confidence, ObservationStatus, Severity, TargetScope
from expose.probes import ClientSideProbe, CookieProbe, DNSProbe, HTTPHeadersProbe, MetadataProbe, NucleiProbe, TLSProbe
from expose.probes.nikto_probe import NiktoProbe
from expose.probes.openscap_probe import OpenSCAPProbe


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


def test_dmarc_parsing():
    probe = DNSProbe()
    record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com; sp=reject"
    tags = probe._parse_dmarc_tags(record)
    assert tags["v"] == "DMARC1"
    assert tags["p"] == "none"
    assert tags["rua"] == "mailto:dmarc@example.com"
    assert tags["sp"] == "reject"


def test_dmarc_parsing_whitespace_resilience():
    probe = DNSProbe()
    record = "  v=DMARC1 ;   p = quarantine ; pct = 100  "
    tags = probe._parse_dmarc_tags(record)
    assert tags["v"] == "DMARC1"
    assert tags["p"] == "quarantine"
    assert tags["pct"] == "100"


@pytest.mark.asyncio
async def test_metadata_probe_does_not_report_missing_security_txt_when_unreachable(dummy_target, monkeypatch):
    probe = MetadataProbe()

    class UnreachableClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, *args, **kwargs):
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: UnreachableClient())

    findings = await probe.execute(dummy_target)
    assert not any("security.txt" in finding.title for finding in findings)


@pytest.mark.asyncio
async def test_header_compliance_probes_do_not_score_forbidden_challenge_pages(dummy_target, monkeypatch):
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

    nikto_findings = await NiktoProbe()._execute_native_nikto_checks(dummy_target)
    openscap_findings = await OpenSCAPProbe().execute(dummy_target)

    assert not any("Clickjacking" in finding.title for finding in nikto_findings)
    assert not any("HSTS" in finding.title or "Content Security Policy" in finding.title for finding in openscap_findings)


@pytest.mark.asyncio
async def test_http_headers_probe_does_not_score_forbidden_challenge_pages(dummy_target, monkeypatch):
    class MockResponse:
        status_code = 403
        headers = {"server": "Vercel", "x-vercel-mitigated": "challenge"}
        text = "challenge"

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await HTTPHeadersProbe().execute(dummy_target)
    header_titles = [finding.title for finding in findings]
    assert not any("Missing Content-Security-Policy" in title for title in header_titles)
    assert not any("Missing HTTP Strict Transport Security" in title for title in header_titles)
    assert not any("Missing Clickjacking Defense" in title for title in header_titles)


@pytest.mark.asyncio
async def test_cookie_probe_detects_insecure_flags(dummy_target, monkeypatch):
    probe = CookieProbe()

    class MockResponse:
        def __init__(self):
            self.headers = MockHeaders([
                ("set-cookie", "session_id=abc123xyz; Path=/; SameSite=Lax"),  # Missing Secure & HttpOnly
                ("set-cookie", "pref=dark; Path=/; Secure; HttpOnly; SameSite=None"),
                ("set-cookie", "tracker=999; Path=/; SameSite=None"),  # SameSite=None without Secure
            ])

    class MockHeaders:
        def __init__(self, items):
            self._items = items
        def get_list(self, key):
            if key.lower() == "set-cookie":
                return [v for k, v in self._items if k.lower() == "set-cookie"]
            return []

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    titles = [f.title for f in findings]

    assert any("Missing 'Secure' Attribute on 'session_id'" in t for t in titles)
    assert any("Missing 'HttpOnly' Attribute on 'session_id'" in t for t in titles)
    assert any("SameSite=None Without Secure on 'tracker'" in t for t in titles)

    # Verify evidence structure
    for f in findings:
        assert f.evidence is not None
        assert f.evidence.summary != ""
        assert f.evidence.response is not None
        assert "set_cookie" in f.evidence.response


@pytest.mark.asyncio
async def test_http_headers_probe_detects_missing_protections(dummy_target, monkeypatch):
    probe = HTTPHeadersProbe()

    class MockResponse:
        def __init__(self, status_code=200, headers=None, url="https://example.com"):
            self.status_code = status_code
            self.headers = headers or {}
            self.url = url

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            # Return plain headers without HSTS, CSP, XFO, XCTO, but with disclosing Server
            return MockResponse(
                status_code=200,
                headers={
                    "server": "Apache/2.4.41 (Ubuntu)",
                    "x-powered-by": "PHP/8.1.2",
                    "content-type": "text/html; charset=utf-8",
                },
                url=url
            )

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    titles = [f.title for f in findings]

    assert any("Missing HTTP Strict Transport Security (HSTS)" in t for t in titles)
    assert any("Missing Content-Security-Policy (CSP)" in t for t in titles)
    assert any("Missing Clickjacking Defense" in t for t in titles)
    assert any("Missing or Ineffective X-Content-Type-Options" in t for t in titles)
    assert any("Technology Version Disclosure via 'server' Header" in t for t in titles)
    assert any("Technology Version Disclosure via 'x-powered-by' Header" in t for t in titles)

    # Verify every finding has verified evidence
    for f in findings:
        assert f.evidence is not None
        assert f.evidence.summary != ""
        assert f.confidence.value == "CONFIRMED"


@pytest.mark.asyncio
async def test_metadata_probe_security_txt_and_robots(dummy_target, monkeypatch):
    probe = MetadataProbe()

    class MockResponse:
        def __init__(self, text="", status_code=200, headers=None):
            self.text = text
            self.status_code = status_code
            self.headers = headers or {"content-type": "text/plain"}

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            if "robots.txt" in url:
                return MockResponse(
                    text="User-agent: *\nDisallow: /admin\nDisallow: /private/api\nDisallow: /config\n",
                    status_code=200
                )
            if "security.txt" in url:
                # Return security.txt with Contact but expired date
                return MockResponse(
                    text="Contact: mailto:security@example.com\nExpires: 2020-01-01T00:00:00.000Z\n",
                    status_code=200
                )
            return MockResponse(status_code=404)

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    titles = [f.title for f in findings]

    assert any("Sensitive Internal Path Disclosure in robots.txt" in t for t in titles)
    assert any("Expired RFC 9116 security.txt Policy" in t for t in titles)


def test_tls_certificate_parsing(dummy_target):
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    probe = TLSProbe()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "wrong-domain.com"),
    ])
    # Build certificate that expired yesterday
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=30))
        .not_valid_after(now - datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("wrong-domain.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cn = probe._get_common_name(cert.subject)
    assert cn == "wrong-domain.com"
    sans = probe._get_san_names(cert)
    assert sans == ["wrong-domain.com"]


@pytest.mark.asyncio
async def test_client_side_probe_sri_and_insecure_forms(dummy_target, monkeypatch):
    probe = ClientSideProbe()

    sample_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <!-- External script without SRI -->
        <script src="https://cdn.example-tracker.com/analytics.js"></script>
    </head>
    <body>
        <!-- Insecure password form submitting to plain HTTP -->
        <form action="http://insecure.example.com/login" method="POST">
            <input type="password" name="pwd" />
            <button type="submit">Login</button>
        </form>

        <!-- Password form using GET -->
        <form action="/auth" method="GET">
            <input type="password" name="password" />
        </form>

        <!-- Referenced API endpoint in script -->
        <script>
            const endpoint = "/api/v1/user/profile";
        </script>
    </body>
    </html>
    """

    class MockResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            return MockResponse(sample_html, 200)
        async def head(self, url, *args, **kwargs):
            return MockResponse("", 404)

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    titles = [f.title for f in findings]

    # Verify SRI finding
    assert any("Missing Subresource Integrity" in t for t in titles)
    # Verify insecure form findings
    assert any("Insecure Password Form Submission Over Plain HTTP" in t for t in titles)
    assert any("Password Submitted via HTTP GET Method" in t for t in titles)
    # Verify API discovery finding
    assert any("Public API Endpoints Referenced in Client-Side Code" in t for t in titles)

    # Verify that API endpoint reference is strictly marked INFORMATIONAL (not vulnerability claim)
    api_finding = next(f for f in findings if "Public API Endpoints" in f.title)
    assert api_finding.severity == Severity.INFO
    assert api_finding.confidence == Confidence.INFORMATIONAL
    assert api_finding.status == ObservationStatus.OBSERVED


@pytest.mark.asyncio
async def test_nuclei_probe_git_and_env_exposure(dummy_target, monkeypatch):
    probe = NucleiProbe()

    class MockResponse:
        def __init__(self, text, status_code):
            self.text = text
            self.status_code = status_code

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            if url.endswith("/.git/config"):
                return MockResponse("[core]\nrepositoryformatversion = 0\nfilemode = false", 200)
            if url.endswith("/.env"):
                return MockResponse("DATABASE_URL=postgres://user:pass@db:5432/prod\nSECRET_KEY=123", 200)
            return MockResponse("Not found", 404)

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    titles = [f.title for f in findings]

    assert any("Git Configuration (.git/config) File Exposed" in t for t in titles)
    assert any("Environment (.env) Configuration File Exposed" in t for t in titles)

    for f in findings:
        assert f.confidence == Confidence.CONFIRMED
        assert f.status == ObservationStatus.CONFIRMED
        assert f.category == Category.EXTERNAL_EXPOSURE
        assert f.verification_command is not None


@pytest.mark.asyncio
async def test_cookie_probe_detects_suspicious_domain_scope(dummy_target, monkeypatch):
    probe = CookieProbe()

    class MockResponse:
        def __init__(self):
            self.headers = MockHeaders([
                ("set-cookie", "session=s1; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax"),
            ])

    class MockHeaders:
        def __init__(self, items):
            self._items = items
        def get_list(self, key):
            return [v for k, v in self._items if k.lower() == key.lower()]

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    # Target host is 'app.example.com', cookie domain is '.example.com' (superdomain scope)
    from expose.core.models import TargetScope
    subdomain_target = TargetScope(
        raw_target="https://app.example.com",
        normalized_url="https://app.example.com",
        scheme="https",
        host="app.example.com",
        port=443,
        resolved_ips=["93.184.216.34"],
        is_private=False
    )

    findings = await probe.execute(subdomain_target)
    titles = [f.title for f in findings]
    assert any("Suspicious Cookie Scope: Broad Domain Scope on 'session'" in t for t in titles)
    cookie_finding = next(f for f in findings if "Suspicious Cookie Scope" in f.title)
    assert cookie_finding.confidence == Confidence.CONFIRMED
    assert cookie_finding.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_http_options_probe_advertised_trace_potential_confidence(dummy_target, monkeypatch):
    """Verifies Phase 5 requirement: Do not use severity as a substitute for confidence.
    Advertised OPTIONS TRACE must be Confidence.POTENTIAL, never CONFIRMED."""
    probe = HTTPHeadersProbe()

    class MockResponse:
        def __init__(self, status_code=200, headers=None, text=""):
            self.status_code = status_code
            self.headers = headers or {}
            self.text = text
            self.url = "https://example.com"

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            return MockResponse(
                headers={
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-content-type-options": "nosniff",
                    "x-frame-options": "DENY",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "camera=()",
                },
                text="<html><body>Hello secure site</body></html>"
            )
        async def options(self, url, *args, **kwargs):
            return MockResponse(
                headers={"allow": "GET, POST, OPTIONS, TRACE"}
            )

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    trace_finding = next((f for f in findings if "TRACE" in f.title), None)
    assert trace_finding is not None
    # Crucial Phase 5 assertion:
    assert trace_finding.confidence == Confidence.POTENTIAL
    assert trace_finding.severity == Severity.LOW
    assert "OPTIONS" in trace_finding.evidence.summary


@pytest.mark.asyncio
async def test_mixed_content_detection_on_https(dummy_target, monkeypatch):
    probe = HTTPHeadersProbe()

    class MockResponse:
        def __init__(self, status_code=200, headers=None, text=""):
            self.status_code = status_code
            self.headers = headers or {}
            self.text = text
            self.url = "https://example.com"

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            return MockResponse(
                headers={
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-content-type-options": "nosniff",
                    "x-frame-options": "DENY",
                },
                text='<html><head><script src="http://cdn.insecure.com/analytics.js"></script></head><body></body></html>'
            )
        async def options(self, url, *args, **kwargs):
            return MockResponse(headers={"allow": "GET, POST"})

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(dummy_target)
    mixed_finding = next((f for f in findings if "Active Mixed Content" in f.title), None)
    assert mixed_finding is not None
    assert mixed_finding.severity == Severity.HIGH
    assert mixed_finding.confidence == Confidence.CONFIRMED
    assert "http://cdn.insecure.com/analytics.js" in mixed_finding.description
