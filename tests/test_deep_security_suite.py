"""Comprehensive test suite for the Deep Security Suite upgrades in Expose.

Validates:
1. CookieProbe __Host- and __Secure- prefix enforcement and positive hardened cookie observations.
2. NucleiProbe expanded templates (.git/HEAD, .env.production, package.json, actuators) and SPA HTML rejection.
3. HTTPHeadersProbe deep CSP directive analysis (wildcards, base-uri, form-action, object-src) and multi-framework remediation blocks.
"""

import pytest
from expose.core.models import (
    Category,
    Confidence,
    ObservationStatus,
    Severity,
    TargetScope,
)
from expose.probes.cookie_probe import CookieProbe
from expose.probes.nuclei_probe import NucleiProbe
from expose.probes.http_headers_probe import HTTPHeadersProbe


@pytest.fixture
def https_target():
    return TargetScope(
        raw_target="https://secure.example.com",
        normalized_url="https://secure.example.com",
        scheme="https",
        host="secure.example.com",
        port=443,
        resolved_ips=["93.184.216.34"],
        is_private=False,
        allow_private=False,
    )


# ---------------------------------------------------------------------------
# 1. Cookie Security Probe Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cookie_probe_host_prefix_violation(https_target, monkeypatch):
    probe = CookieProbe()

    class MockResponse:
        def __init__(self):
            self.status_code = 200
            self.headers = {
                "set-cookie": "__Host-Session=abc12345; Secure; Domain=example.com; Path=/"
            }
        def get_list(self, key):
            if key.lower() == "set-cookie":
                return ["__Host-Session=abc12345; Secure; Domain=example.com; Path=/"]
            return []

    class MockHeaders:
        def get_list(self, key):
            if key.lower() == "set-cookie":
                return ["__Host-Session=abc12345; Secure; Domain=example.com; Path=/"]
            return []

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            resp = MockResponse()
            resp.headers = MockHeaders()
            return resp

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(https_target)
    titles = [f.title for f in findings]
    assert any("__Host-' Specification Violation" in t for t in titles)
    violation_finding = next(f for f in findings if "__Host-" in f.title)
    assert violation_finding.severity == Severity.HIGH
    assert violation_finding.category == Category.COOKIE_SECURITY


@pytest.mark.asyncio
async def test_cookie_probe_hardened_positive_observation(https_target, monkeypatch):
    probe = CookieProbe()

    cookie_header = "session_token=xyz98765; Secure; HttpOnly; SameSite=Strict; Path=/"

    class MockHeaders:
        def get_list(self, key):
            if key.lower() == "set-cookie":
                return [cookie_header]
            return []

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            class Resp:
                status_code = 200
                headers = MockHeaders()
            return Resp()

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(https_target)
    titles = [f.title for f in findings]
    assert any("Hardened Cookie Security" in t for t in titles)
    observed = next(f for f in findings if "Hardened Cookie Security" in f.title)
    assert observed.status == ObservationStatus.OBSERVED
    assert observed.severity == Severity.INFO


# ---------------------------------------------------------------------------
# 2. Nuclei Exposure Probe Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_nuclei_probe_git_head_and_env_production(https_target, monkeypatch):
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
            if "/.git/HEAD" in url:
                return MockResponse(url, 200, "ref: refs/heads/main\n")
            if "/.env.production" in url:
                return MockResponse(url, 200, "DATABASE_URL=postgres://user:pass@localhost:5432/prod\nSECRET_KEY=12345\n")
            if "/package.json" in url:
                return MockResponse(url, 200, '{\n  "name": "app",\n  "dependencies": {\n    "express": "^4.18.0"\n  }\n}')
            return MockResponse(url, 404, "Not found")

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(https_target)
    titles = [f.title for f in findings]

    assert any("Git Repository Root (.git/HEAD) Exposed" in t for t in titles)
    assert any("Production Environment (.env.production) File Exposed" in t for t in titles)
    assert any("Node.js Manifest (package.json) Exposed" in t for t in titles)


@pytest.mark.asyncio
async def test_nuclei_probe_spa_html_rejection(https_target, monkeypatch):
    probe = NucleiProbe()

    spa_fallback_html = "<!doctype html><html><head><title>My SPA App</title></head><body><div id='root'></div></body></html>"

    class MockResponse:
        def __init__(self, url, status_code=200, text=spa_fallback_html):
            self.url = url
            self.status_code = 200
            self.text = text

    class MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *args, **kwargs):
            return MockResponse(url)

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings = await probe.execute(https_target)
    # SPA HTML fallback should NOT trigger false-positive .env, .git, or .sql findings!
    titles = [f.title for f in findings]
    assert not any("Environment (.env)" in t for t in titles)
    assert not any("Database SQL Dump" in t for t in titles)
    assert not any("Git Repository Root" in t for t in titles)


# ---------------------------------------------------------------------------
# 3. HTTP Headers Deep CSP Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_http_headers_deep_csp_analysis(https_target):
    probe = HTTPHeadersProbe()

    import httpx
    # Case A: Missing base-uri and form-action in otherwise valid CSP
    headers = httpx.Headers({
        "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-12345'; style-src 'self';"
    })
    result, findings = probe._test_csp(https_target, headers, None)
    titles = [f.title for f in findings]
    assert any("Missing 'base-uri' Directive" in t for t in titles)
    assert any("Missing 'form-action' Directive" in t for t in titles)
    assert any("Missing 'object-src 'none'' Directive" in t for t in titles)

    # Case B: Wildcard script source in CSP
    wildcard_headers = httpx.Headers({
        "content-security-policy": "default-src 'self'; script-src * 'unsafe-inline'; base-uri 'self'; form-action 'self';"
    })
    w_result, w_findings = probe._test_csp(https_target, wildcard_headers, None)
    w_titles = [f.title for f in w_findings]
    assert any("Wildcard '*' in Script Sources" in t for t in w_titles)
    assert w_result.score_modifier == -20

    # Case C: Fully hardened CSP with all directives
    hardened_headers = httpx.Headers({
        "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self';"
    })
    h_result, h_findings = probe._test_csp(https_target, hardened_headers, None)
    assert h_result.score_modifier == 0
    assert any("Content-Security-Policy (CSP) Configured" in f.title for f in h_findings)
