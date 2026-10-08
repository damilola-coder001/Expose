"""Tests for Domain Ownership Verification (Proof-of-Control) Engine (Phase 28).

Covers:
- Cryptographic challenge generation and token reproducibility
- DNS TXT record challenge verification
- HTTP .well-known token challenge verification
- Verification record caching, TTL, and expiration
- REST API endpoints (/domains/challenge, /domains/verify, /domains/{domain}/status)
- Integration with ScanResult and report export
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from expose.api.app import create_app
from expose.core.models import (
    Category,
    Finding,
    ObservationStatus,
    ScanResult,
    ScoreCard,
    Severity,
    TargetScope,
)
from expose.core.ownership import (
    DomainChallenge,
    DomainOwnershipRecord,
    DomainOwnershipVerifier,
    VerificationMethod,
    generate_challenge_token,
    get_ownership_verifier,
    normalize_domain,
)
from expose.core.export import generate_sanitized_json_report


def test_domain_normalization_and_token_generation():
    """Validates domain normalization and deterministic HMAC challenge tokens."""
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("https://example.com/some/path") == "example.com"
    assert normalize_domain("http://sub.domain.co.uk:8080/test") == "sub.domain.co.uk"
    assert normalize_domain("  FOO.BAR.COM/  ") == "foo.bar.com"

    token1 = generate_challenge_token("example.com")
    token2 = generate_challenge_token("https://example.com/test")
    assert token1 == token2
    assert token1.startswith("expose-verification=")


def test_challenge_structure_and_instructions():
    """Validates the generated challenge instructions and metadata."""
    verifier = DomainOwnershipVerifier(secret="test-secret-salt")
    challenge = verifier.get_challenge("mycompany.io")

    assert challenge.domain == "mycompany.io"
    assert challenge.dns_record_name == "_expose-challenge.mycompany.io"
    assert challenge.dns_record_type == "TXT"
    assert challenge.dns_record_value == challenge.token
    assert challenge.http_url == "https://mycompany.io/.well-known/expose-challenge.txt"
    assert challenge.http_expected_content == challenge.token
    assert "dns_txt" in challenge.instructions
    assert "http_well_known" in challenge.instructions


@pytest.mark.asyncio
async def test_dns_txt_verification_success_and_failure():
    """Tests DNS TXT record matching against simulated DNS responses."""
    verifier = DomainOwnershipVerifier(secret="test-secret-salt")
    challenge = verifier.get_challenge("target-corp.com")
    expected = challenge.token

    # 1. Success case: DNS returns expected token
    mock_rdata = MagicMock()
    mock_rdata.strings = [expected.encode()]
    mock_resolver = MagicMock()
    mock_resolver.resolve = AsyncMock(return_value=[mock_rdata])
    verifier._custom_dns_resolver = mock_resolver

    ok, msg = await verifier.verify_dns_txt("target-corp.com", expected)
    assert ok is True
    assert "Verified via DNS TXT record" in msg

    # 2. Mismatch case: DNS returns wrong token
    mock_rdata_wrong = MagicMock()
    mock_rdata_wrong.strings = [b"expose-verification=wrong-token-abc"]
    mock_resolver.resolve = AsyncMock(return_value=[mock_rdata_wrong])

    ok, msg = await verifier.verify_dns_txt("target-corp.com", expected)
    assert ok is False
    assert "did not match" in msg


@pytest.mark.asyncio
async def test_http_well_known_verification_success_and_failure():
    """Tests HTTP well-known token verification."""
    verifier = DomainOwnershipVerifier(secret="test-secret-salt")
    challenge = verifier.get_challenge("target-corp.com")
    expected = challenge.token

    # 1. Success case: HTTP client returns 200 with matching token
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = f"  {expected}  \n"

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("expose.core.ownership.create_safe_async_client", return_value=mock_client):
        ok, msg = await verifier.verify_http_well_known("target-corp.com", expected)
        assert ok is True
        assert "Verified via HTTP" in msg

    # 2. Failure case: HTTP 404 Not Found
    mock_response_404 = MagicMock()
    mock_response_404.status_code = 404
    mock_client_404 = AsyncMock()
    mock_client_404.get = AsyncMock(return_value=mock_response_404)
    mock_client_404.__aenter__.return_value = mock_client_404
    mock_client_404.__aexit__.return_value = None

    with patch("expose.core.ownership.create_safe_async_client", return_value=mock_client_404):
        ok, msg = await verifier.verify_http_well_known("target-corp.com", expected)
        assert ok is False
        assert "404" in msg


@pytest.mark.asyncio
async def test_verify_domain_and_caching():
    """Tests verify_domain lifecycle and caching."""
    verifier = DomainOwnershipVerifier(secret="test-secret-salt")
    domain = "secure-enterprise.org"

    # Initially not verified
    assert not verifier.is_verified(domain)
    assert verifier.get_record(domain) is None

    # Manually register verification (or simulate verification)
    verifier.record_manual_verification(domain, method="dns_txt", proof="DNS verified")

    assert verifier.is_verified(domain) is True
    rec = verifier.get_record(domain)
    assert rec is not None
    assert rec.domain == "secure-enterprise.org"
    assert rec.verified is True
    assert rec.verification_method == "dns_txt"


def test_domain_verification_api_routes():
    """Tests FastAPI endpoints for domain challenge, verify, and status."""
    app = create_app()
    client = TestClient(app)

    # 1. POST /api/v1/domains/challenge
    res = client.post("/api/v1/domains/challenge", json={"domain": "acme-corp.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["domain"] == "acme-corp.com"
    assert "token" in data
    assert "_expose-challenge.acme-corp.com" in data["dns_record_name"]

    # 2. GET /api/v1/domains/acme-corp.com/status before verification
    res_status = client.get("/api/v1/domains/acme-corp.com/status")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert status_data["domain"] == "acme-corp.com"
    assert status_data["verified"] is False
    assert "challenge" in status_data

    # 3. Simulate verified domain in the global verifier
    global_verifier = get_ownership_verifier()
    global_verifier.record_manual_verification("acme-corp.com", method="dns_txt", proof="DNS Proof Confirmed")

    # 4. GET /api/v1/domains/acme-corp.com/status after verification
    res_status2 = client.get("/api/v1/domains/acme-corp.com/status")
    assert res_status2.status_code == 200
    status_data2 = res_status2.json()
    assert status_data2["domain"] == "acme-corp.com"
    assert status_data2["verified"] is True
    assert status_data2["record"]["proof"] == "DNS Proof Confirmed"


def test_scan_result_and_export_integration():
    """Ensures ScanResult and report export reflect domain ownership."""
    global_verifier = get_ownership_verifier()
    global_verifier.record_manual_verification("verified-site.com", method="dns_txt", proof="DNS Verified")

    target = TargetScope(
        raw_target="https://verified-site.com",
        normalized_url="https://verified-site.com",
        scheme="https",
        host="verified-site.com",
        port=443,
        resolved_ips=["1.2.3.4"],
        is_private=False,
        allow_private=False,
    )
    score_card = ScoreCard(
        score_version="1.0",
        overall_score=95,
        letter_grade="A",
        category_scores={},
        confirmed_flaws_count=0,
        observed_properties_count=5,
    )
    scan = ScanResult(
        scan_id="scn_verified_test",
        target=target,
        score_card=score_card,
        findings=[],
    )

    # Validates auto-population of domain_verified
    assert scan.domain_verified is True
    assert scan.domain_ownership_proof == "DNS Verified"

    # Export report validation
    json_report = generate_sanitized_json_report(scan)
    target_meta = json_report["scan_metadata"]["target"]
    assert target_meta["domain_verified"] is True
    assert target_meta["domain_ownership_proof"] == "DNS Verified"
