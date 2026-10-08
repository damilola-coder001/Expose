"""Tests for Multi-Region Distributed Egress and Global Vantage Point Probing (Phase 32)."""

import asyncio
from unittest.mock import AsyncMock, patch
import pytest

from expose.core.multi_region import (
    MultiRegionComparison,
    MultiRegionOrchestrator,
    RegionCode,
    RegionalObservation,
    VantagePoint,
)


@pytest.mark.asyncio
async def test_multi_region_probe_execution():
    """Validates multi-region parallel probing and GeoDNS posture variance detection."""
    vps = [
        VantagePoint(
            region=RegionCode.US_EAST,
            name="US East (Virginia)",
            location="Ashburn, VA",
            latitude=39.0,
            longitude=-77.0,
        ),
        VantagePoint(
            region=RegionCode.EU_CENTRAL,
            name="EU Central (Frankfurt)",
            location="Frankfurt, DE",
            latitude=50.1,
            longitude=8.6,
        ),
        VantagePoint(
            region=RegionCode.AP_SOUTHEAST,
            name="AP Southeast (Singapore)",
            location="Singapore, SG",
            latitude=1.3,
            longitude=103.8,
        ),
    ]

    orchestrator = MultiRegionOrchestrator(vantage_points=vps)

    # Mock individual probe responses to simulate GeoDNS edge IP differences
    async def mock_probe(target, vp):
        ip_map = {
            RegionCode.US_EAST: "104.21.5.10",
            RegionCode.EU_CENTRAL: "104.21.5.20",
            RegionCode.AP_SOUTHEAST: "104.21.5.30",
        }
        latency_map = {
            RegionCode.US_EAST: 45.2,
            RegionCode.EU_CENTRAL: 110.5,
            RegionCode.AP_SOUTHEAST: 215.8,
        }
        ip = ip_map[vp.region]
        return RegionalObservation(
            region=vp.region,
            vantage_point_name=vp.name,
            resolved_ip=ip,
            all_resolved_ips=[ip],
            http_status=200,
            latency_ms=latency_map[vp.region],
            cdn_provider="Cloudflare",
            reachable=True,
        )

    with patch.object(orchestrator, "probe_vantage_point", side_effect=mock_probe):
        comparison: MultiRegionComparison = await orchestrator.audit_target("example.com")

        assert comparison.total_regions_tested == 3
        assert comparison.successful_regions == 3
        assert comparison.has_geodns_diversity is True
        assert comparison.detected_cdn == "Cloudflare"
        assert comparison.average_latency_ms > 0
        assert "GeoDNS" in comparison.summary
        assert len(comparison.observations) == 3
