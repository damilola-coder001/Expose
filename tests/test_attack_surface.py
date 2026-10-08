"""Unit tests for Phase 8 Attack Surface Discovery Probe and Asset Models."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch

from expose.core.models import (
    Category,
    Confidence,
    ObservationStatus,
    Severity,
    TargetScope,
)
from expose.probes.attack_surface_probe import AttackSurfaceProbe


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


SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Portal</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter">
    <link rel="icon" href="/favicon.ico">
</head>
<body>
    <nav>
        <a href="/dashboard">Dashboard</a>
        <a href="/pricing">Pricing</a>
        <a href="https://analytics.mixpanel.com/track">Analytics Link</a>
    </nav>
    <main>
        <img src="/assets/logo.png" alt="Logo">
        <form action="/auth/login" method="POST">
            <input type="text" name="user_email">
            <input type="password" name="password">
            <button type="submit">Log in</button>
        </form>
    </main>
    <script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"></script>
    <script src="/static/bundle.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"></script>
    <script>
        const endpoint = "/api/v1/telemetry";
        const orders = "/api/v2/orders";
    </script>
</body>
</html>
"""

SAMPLE_ROBOTS = """
User-agent: *
Disallow: /admin/
Disallow: /internal/debug
Allow: /public/
Sitemap: https://example.com/sitemap.xml
"""

SAMPLE_SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
   <url>
      <loc>https://example.com/docs</loc>
   </url>
   <url>
      <loc>https://example.com/status</loc>
   </url>
</urlset>
"""


@pytest.mark.asyncio
async def test_attack_surface_discovery_full_pipeline(dummy_target, monkeypatch):
    probe = AttackSurfaceProbe()

    async def mock_get(self, url, *args, **kwargs):
        url_str = str(url)
        if url_str.endswith("/robots.txt"):
            return httpx.Response(
                200,
                text=SAMPLE_ROBOTS,
                request=httpx.Request("GET", url_str),
            )
        elif url_str.endswith("/sitemap.xml"):
            return httpx.Response(
                200,
                text=SAMPLE_SITEMAP,
                request=httpx.Request("GET", url_str),
            )
        else:
            return httpx.Response(
                200,
                text=SAMPLE_HTML,
                request=httpx.Request("GET", "https://example.com"),
            )

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_get)

    findings, surface = await probe.discover_attack_surface(dummy_target)

    # 1. Target & Summary
    assert surface.target == "https://example.com"
    assert "Website exposes" in surface.exposure_summary
    assert "Page(s)" in surface.exposure_summary

    # 2. Pages Discovery
    page_urls = [p.url for p in surface.pages]
    assert any("/dashboard" in u for u in page_urls)
    assert any("/pricing" in u for u in page_urls)
    assert any("/docs" in u for u in page_urls)  # from sitemap
    assert any("/status" in u for u in page_urls)  # from sitemap

    # 3. API References
    api_paths = [a.path for a in surface.apis]
    assert "/api/v1/telemetry" in api_paths
    assert "/api/v2/orders" in api_paths

    # 4. Form Asset & Sensitive Input
    assert len(surface.forms) == 1
    form = surface.forms[0]
    assert form.method == "POST"
    assert "/auth/login" in form.action
    assert form.has_password is True
    assert form.is_secure_action is True
    input_names = [i.name for i in form.inputs]
    assert "user_email" in input_names
    assert "password" in input_names
    pw_input = next(i for i in form.inputs if i.name == "password")
    assert pw_input.is_sensitive is True

    # 5. Scripts and SRI
    assert len(surface.scripts) == 2
    cdn_script = next(s for s in surface.scripts if "jsdelivr" in s.url)
    assert cdn_script.is_external is True
    assert cdn_script.cdn_provider == "jsDelivr"
    assert cdn_script.has_sri is False

    local_script = next(s for s in surface.scripts if "bundle.js" in s.url)
    assert local_script.is_external is False
    assert local_script.has_sri is True
    assert local_script.sri_hash is not None

    # 6. Static Assets
    asset_types = [a.asset_type for a in surface.assets]
    assert "stylesheet" in asset_types
    assert "image" in asset_types

    # 7. Robots.txt and Sensitive Path Finding
    assert surface.robots_txt is not None
    assert surface.robots_txt.is_present is True
    assert "/admin/" in surface.robots_txt.disallowed_paths
    assert "/internal/debug" in surface.robots_txt.disallowed_paths

    # Finding generated for robots.txt sensitive path disclosure
    robots_findings = [f for f in findings if f.category == Category.INFORMATION_EXPOSURE]
    assert len(robots_findings) >= 1
    rf = robots_findings[0]
    assert "Sensitive Paths Disclosed in robots.txt" in rf.title
    assert rf.severity == Severity.LOW
    assert rf.confidence == Confidence.CONFIRMED

    # 8. External Dependencies Classification
    ext_origins = {d.origin: d for d in surface.external_dependencies}
    assert "fonts.googleapis.com" in ext_origins
    assert ext_origins["fonts.googleapis.com"].category == "Fonts"
    assert "cdn.jsdelivr.net" in ext_origins
    assert ext_origins["cdn.jsdelivr.net"].category == "CDN"
    assert "analytics.mixpanel.com" in ext_origins
    assert ext_origins["analytics.mixpanel.com"].category == "Analytics"

    # 9. Neutral Attack Surface Inventory Finding
    catalog_findings = [f for f in findings if f.category == Category.ATTACK_SURFACE]
    assert len(catalog_findings) >= 1
    cf = catalog_findings[0]
    assert cf.title == "Public Attack Surface Inventory Completed"
    assert cf.severity == Severity.INFO
    assert cf.confidence == Confidence.INFORMATIONAL
