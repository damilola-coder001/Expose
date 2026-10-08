"""Unit tests for target validation and SSRF safety guard."""

import pytest
from expose.core.safety import (
    is_ip_private,
    parse_and_validate_target,
    SecurityScopeError,
)


def test_private_ip_detection():
    # Loopback
    assert is_ip_private("127.0.0.1") is True
    assert is_ip_private("127.0.0.254") is True
    assert is_ip_private("::1") is True

    # IPv4-mapped IPv6 unmasking
    assert is_ip_private("::ffff:127.0.0.1") is True
    assert is_ip_private("::ffff:10.0.0.1") is True
    assert is_ip_private("::ffff:192.168.1.50") is True

    # Carrier-grade NAT / Benchmark / Reserved
    assert is_ip_private("100.64.0.1") is True
    assert is_ip_private("198.18.0.1") is True
    assert is_ip_private("100.100.100.200") is True

    # RFC 1918 Private
    assert is_ip_private("10.0.0.1") is True
    assert is_ip_private("192.168.1.1") is True
    assert is_ip_private("172.16.0.5") is True
    assert is_ip_private("172.31.255.254") is True

    # Link-local / Cloud metadata
    assert is_ip_private("169.254.169.254") is True

    # Public IPs
    assert is_ip_private("8.8.8.8") is False
    assert is_ip_private("1.1.1.1") is False
    assert is_ip_private("93.184.216.34") is False


def test_ssrf_guard_blocks_localhost_by_default():
    with pytest.raises(SecurityScopeError) as excinfo:
        parse_and_validate_target("http://127.0.0.1:8080", allow_private=False)
    assert "SSRF Safety Guard" in str(excinfo.value)
    assert "127.0.0.1" in str(excinfo.value)


def test_ssrf_guard_blocks_metadata_hostnames():
    with pytest.raises(SecurityScopeError) as excinfo:
        parse_and_validate_target("http://metadata.google.internal", allow_private=False)
    assert "internal or cloud metadata" in str(excinfo.value)

    with pytest.raises(SecurityScopeError) as excinfo:
        parse_and_validate_target("http://myapp.local", allow_private=False)
    assert "internal or cloud metadata" in str(excinfo.value)


def test_redirect_validation_blocks_ssrf_hops():
    from expose.core.safety import validate_redirect_target
    # Valid external redirect
    assert validate_redirect_target("https://example.com/login") == "https://example.com/login"

    # Reject non-http
    with pytest.raises(SecurityScopeError) as exc:
        validate_redirect_target("file:///etc/passwd")
    assert "Insecure redirect scheme" in str(exc.value)

    # Reject redirect to metadata hostname
    with pytest.raises(SecurityScopeError) as exc:
        validate_redirect_target("http://metadata.google.internal/computeMetadata/v1/")
    assert "SSRF Safety Guard" in str(exc.value)


def test_ssrf_guard_allows_localhost_when_flag_enabled():
    scope = parse_and_validate_target("http://127.0.0.1:8080", allow_private=True)
    assert scope.host == "127.0.0.1"
    assert scope.port == 8080
    assert scope.scheme == "http"
    assert scope.is_private is True
    assert scope.allow_private is True


def test_target_normalization():
    scope = parse_and_validate_target("http://127.0.0.1:9000/some/path?param=1", allow_private=True)
    assert scope.normalized_url == "http://127.0.0.1:9000"
    assert scope.host == "127.0.0.1"
    assert scope.port == 9000
    assert scope.scheme == "http"


def test_empty_target_fails():
    with pytest.raises(SecurityScopeError):
        parse_and_validate_target("")
