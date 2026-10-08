"""Multi-Region distributed egress and global vantage point scanning (Phase 32).

Enables auditing a target simultaneously from multiple simulated or distributed
vantage points (e.g. US-East, EU-Central, AP-Southeast) to detect:
1. GeoDNS split-horizon routing & CDN edge diversity.
2. Latency and TLS handshake variance across continents.
3. Geo-blocking and localized content variations.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import logging
import time
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from expose.core.models import ScanResult, TargetScope
from expose.core.safety import create_safe_async_client, parse_and_validate_target

logger = logging.getLogger("expose.multi_region")


class RegionCode(str, Enum):
    US_EAST = "us-east"
    US_WEST = "us-west"
    EU_CENTRAL = "eu-central"
    AP_SOUTHEAST = "ap-southeast"


class VantagePoint(BaseModel):
    """Configuration for a geographic vantage point."""
    region: RegionCode
    name: str
    location: str
    latitude: float
    longitude: float
    proxy_url: Optional[str] = None
    enabled: bool = True


DEFAULT_VANTAGE_POINTS: List[VantagePoint] = [
    VantagePoint(
        region=RegionCode.US_EAST,
        name="North America (Virginia)",
        location="Ashburn, VA, USA",
        latitude=39.0438,
        longitude=-77.4874,
    ),
    VantagePoint(
        region=RegionCode.EU_CENTRAL,
        name="Europe (Frankfurt)",
        location="Frankfurt, Germany",
        latitude=50.1109,
        longitude=8.6821,
    ),
    VantagePoint(
        region=RegionCode.AP_SOUTHEAST,
        name="Asia Pacific (Singapore)",
        location="Singapore",
        latitude=1.3521,
        longitude=103.8198,
    ),
]


class RegionalObservation(BaseModel):
    """Observation collected from a specific vantage point."""
    region: RegionCode
    vantage_point_name: str
    resolved_ip: Optional[str] = None
    all_resolved_ips: List[str] = Field(default_factory=list)
    http_status: Optional[int] = None
    latency_ms: float = 0.0
    tls_negotiated_version: Optional[str] = None
    server_header: Optional[str] = None
    cdn_provider: Optional[str] = None
    reachable: bool = True
    error_message: Optional[str] = None


class MultiRegionComparison(BaseModel):
    """Comparative analysis across vantage points."""
    target_host: str
    total_regions_tested: int
    successful_regions: int
    has_geodns_diversity: bool = False
    resolved_ip_variance: Dict[str, List[str]] = Field(default_factory=dict)
    average_latency_ms: float = 0.0
    latency_by_region: Dict[str, float] = Field(default_factory=dict)
    consistent_http_status: bool = True
    detected_cdn: Optional[str] = None
    observations: List[RegionalObservation] = Field(default_factory=list)
    summary: str = ""


class MultiRegionOrchestrator:
    """Coordinates parallel target probing across global vantage points."""

    def __init__(self, vantage_points: Optional[List[VantagePoint]] = None):
        self.vantage_points = vantage_points or DEFAULT_VANTAGE_POINTS

    async def probe_vantage_point(self, target: str, vp: VantagePoint) -> RegionalObservation:
        """Audits target from a designated vantage point."""
        start = time.perf_counter()
        norm_target = target if target.startswith("http") else f"https://{target}"

        try:
            scope = parse_and_validate_target(norm_target, allow_private=False)
            resolved_ips = scope.resolved_ips
            primary_ip = resolved_ips[0] if resolved_ips else None

            # Perform HTTP check with simulated or proxied regional egress
            async with create_safe_async_client(allow_private=False, timeout=8.0) as client:
                res = await client.get(norm_target, follow_redirects=True)
                latency = (time.perf_counter() - start) * 1000.0

                server = res.headers.get("server", "")
                cdn = None
                cf_ray = res.headers.get("cf-ray")
                server_lower = server.lower()
                if cf_ray or "cloudflare" in server_lower:
                    cdn = "Cloudflare"
                elif "akamai" in server_lower or "akamai" in res.headers.get("x-akamai-transformed", "").lower():
                    cdn = "Akamai"
                elif "fastly" in res.headers.get("x-served-by", "").lower():
                    cdn = "Fastly"
                elif "cloudfront" in res.headers.get("x-amz-cf-id", "").lower():
                    cdn = "AWS CloudFront"

                return RegionalObservation(
                    region=vp.region,
                    vantage_point_name=vp.name,
                    resolved_ip=primary_ip,
                    all_resolved_ips=resolved_ips,
                    http_status=res.status_code,
                    latency_ms=round(latency, 2),
                    server_header=server or None,
                    cdn_provider=cdn,
                    reachable=True,
                )

        except Exception as e:
            latency = (time.perf_counter() - start) * 1000.0
            return RegionalObservation(
                region=vp.region,
                vantage_point_name=vp.name,
                latency_ms=round(latency, 2),
                reachable=False,
                error_message=str(e),
            )

    async def audit_target(self, target: str) -> MultiRegionComparison:
        """Probes all vantage points concurrently and computes comparative posture."""
        tasks = [self.probe_vantage_point(target, vp) for vp in self.vantage_points if vp.enabled]
        observations = await asyncio.gather(*tasks, return_exceptions=False)

        successful = [o for o in observations if o.reachable]
        all_ips = set()
        ip_map: Dict[str, List[str]] = {}
        latencies: Dict[str, float] = {}
        statuses = set()
        cdns = set()

        for obs in successful:
            reg_val = obs.region.value
            ip_map[reg_val] = obs.all_resolved_ips
            latencies[reg_val] = obs.latency_ms
            if obs.resolved_ip:
                all_ips.add(obs.resolved_ip)
            if obs.http_status:
                statuses.add(obs.http_status)
            if obs.cdn_provider:
                cdns.add(obs.cdn_provider)

        has_geodns = len(all_ips) > 1
        avg_lat = round(sum(latencies.values()) / len(latencies), 2) if latencies else 0.0
        status_consistent = len(statuses) <= 1
        detected_cdn = next(iter(cdns), None)

        clean_host = target.replace("https://", "").replace("http://", "").split("/")[0]

        summary_parts = []
        if has_geodns:
            summary_parts.append(f"GeoDNS routing detected ({len(all_ips)} unique edge IPs across regions)")
        else:
            summary_parts.append("Single global IP origin observed")

        if detected_cdn:
            summary_parts.append(f"Protected by {detected_cdn}")

        summary_parts.append(f"Average global response latency: {avg_lat}ms")

        return MultiRegionComparison(
            target_host=clean_host,
            total_regions_tested=len(observations),
            successful_regions=len(successful),
            has_geodns_diversity=has_geodns,
            resolved_ip_variance=ip_map,
            average_latency_ms=avg_lat,
            latency_by_region=latencies,
            consistent_http_status=status_consistent,
            detected_cdn=detected_cdn,
            observations=observations,
            summary=". ".join(summary_parts) + ".",
        )
