"""Tests for socket-level anti-DNS-rebinding and TOCTOU defense (Phase 28).

Verifies that all HTTP probe requests are guarded against DNS rebinding attacks,
such that if an attacker-controlled hostname resolves to a public IP initially but
swaps to a loopback, RFC1918, or cloud metadata IP at TCP connect time, the connection
is immediately terminated at the socket layer.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import httpx

from expose.core.models import TargetScope
from expose.core.safety import (
    SSRFSafeAsyncTransport,
    SSRFSafeNetworkBackend,
    SecurityScopeError,
    create_safe_async_client,
    is_ip_private,
    is_restricted_hostname,
)
from expose.probes import BaseProbe
from expose.core.models import Category, Finding


class DummyProbe(BaseProbe):
    @property
    def name(self) -> str:
        return "dummy_test_probe"

    @property
    def category(self) -> Category:
        return Category.CONFIGURATION

    @property
    def description(self) -> str:
        return "Dummy probe for testing client factory"

    async def execute(self, target: TargetScope) -> list[Finding]:
        return []


def test_restricted_ip_and_hostname_helpers():
    """Validates cloud metadata and private IP detection helpers."""
    assert is_ip_private("127.0.0.1")
    assert is_ip_private("169.254.169.254")
    assert is_ip_private("10.0.0.1")
    assert is_ip_private("192.168.1.1")
    assert is_ip_private("172.16.0.1")
    assert is_ip_private("::1")
    assert not is_ip_private("8.8.8.8")
    assert not is_ip_private("1.1.1.1")
    assert not is_ip_private("93.184.216.34")

    assert is_restricted_hostname("metadata.google.internal")
    assert is_restricted_hostname("169.254.169.254")
    assert is_restricted_hostname("test.local")
    assert is_restricted_hostname("corp.internal")
    assert not is_restricted_hostname("example.com")
    assert not is_restricted_hostname("google.com")


@pytest.mark.asyncio
async def test_ssrf_safe_backend_blocks_restricted_hosts():
    """Ensures SSRFSafeNetworkBackend directly blocks restricted hostnames before connecting."""
    backend = SSRFSafeNetworkBackend(allow_private=False)
    with pytest.raises(SecurityScopeError, match="SSRF Safety Guard"):
        await backend.connect_tcp("metadata.google.internal", 80)


@pytest.mark.asyncio
async def test_anti_rebinding_socket_layer_blocks_private_ip():
    """Simulates attempting connection to localhost: when allow_private=False, connection is blocked."""
    backend = SSRFSafeNetworkBackend(allow_private=False)
    with pytest.raises(SecurityScopeError, match="SSRF Safety Guard"):
        await backend.connect_tcp("127.0.0.1", 80)

    # Test DNS rebinding simulation: hostname is public, but socket establishes to metadata IP 169.254.169.254
    mock_socket = MagicMock()
    mock_socket.getpeername.return_value = ("169.254.169.254", 80)
    mock_stream = MagicMock()
    mock_stream._raw_socket = mock_socket
    mock_stream.aclose = AsyncMock()

    with patch("httpcore._backends.anyio.AnyIOBackend.connect_tcp", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = mock_stream
        with pytest.raises(SecurityScopeError, match="Anti-DNS-Rebinding Guard"):
            await backend.connect_tcp("attacker-rebound.com", 80)
        assert mock_stream.aclose.called


@pytest.mark.asyncio
async def test_create_safe_async_client_factory():
    """Tests the factory helper create_safe_async_client respects target scope."""
    target_public = TargetScope(
        raw_target="https://example.com",
        normalized_url="https://example.com",
        scheme="https",
        host="example.com",
        port=443,
        resolved_ips=["93.184.216.34"],
        is_private=False,
        allow_private=False,
    )
    client = create_safe_async_client(target=target_public)
    assert isinstance(client._transport, SSRFSafeAsyncTransport)
    assert client._transport.allow_private is False
    await client.aclose()

    target_private = TargetScope(
        raw_target="http://localhost:8000",
        normalized_url="http://localhost:8000",
        scheme="http",
        host="localhost",
        port=8000,
        resolved_ips=["127.0.0.1"],
        is_private=True,
        allow_private=True,
    )
    client_priv = create_safe_async_client(target=target_private)
    assert client_priv._transport.allow_private is True
    await client_priv.aclose()


@pytest.mark.asyncio
async def test_base_probe_get_http_client():
    """Ensures BaseProbe.get_http_client returns the hardened anti-rebinding client."""
    probe = DummyProbe()
    target = TargetScope(
        raw_target="https://example.com",
        normalized_url="https://example.com",
        scheme="https",
        host="example.com",
        port=443,
        resolved_ips=["93.184.216.34"],
        is_private=False,
        allow_private=False,
    )
    client = probe.get_http_client(target)
    assert isinstance(client._transport, SSRFSafeAsyncTransport)
    await client.aclose()
