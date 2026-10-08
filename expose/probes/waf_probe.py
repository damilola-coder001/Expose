"""WAF and Edge Security Posture probe for Expose.

Identifies reverse proxy and Web Application Firewall (WAF) layers (Cloudflare, AWS WAF,
Akamai, Imperva, Fastly, F5 BIG-IP) and evaluates edge protection posture.
"""

from typing import List, Optional, Tuple
import httpx

from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    ObservationStatus,
    Severity,
    TargetScope,
)
from expose.probes.base import BaseProbe


WAF_SIGNATURES = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "cf-request-id"], "server", "cloudflare", "Cloudflare Edge Security & DDoS Shield"),
    ("AWS CloudFront / WAF", ["x-amz-cf-id", "x-amzn-waf-action"], "server", "cloudfront", "AWS CloudFront Edge & AWS WAF"),
    ("Akamai", ["x-akamai-transformed", "x-akamai-request-id", "akamai-origin-hop"], "server", "akamaighost", "Akamai Edge Security Suite"),
    ("Fastly", ["fastly-restarts", "x-served-by", "x-fastly-request-id"], "server", "varnish", "Fastly Edge Cloud & Signal Sciences WAF"),
    ("Imperva Incapsula", ["x-iinfo", "x-cdn"], None, None, "Imperva Incapsula Web Application Firewall"),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache"], "server", "sucuri", "Sucuri CloudProxy Website Firewall"),
    ("F5 BIG-IP", ["f5_cspm"], "server", "big-ip", "F5 BIG-IP Application Security Manager"),
    ("Azure Front Door", ["x-azure-ref", "x-fd-features"], None, None, "Azure Front Door & Web Application Firewall"),
]


class WAFProbe(BaseProbe):
    """Detects and fingerprints Web Application Firewall (WAF) and CDN edge layers."""

    @property
    def name(self) -> str:
        return "waf_and_edge_security"

    @property
    def category(self) -> Category:
        return Category.CONFIGURATION

    @property
    def description(self) -> str:
        return "Fingerprints reverse proxy, CDN, and Web Application Firewall (WAF) edge protection."

    async def execute(self, target: TargetScope) -> List[Finding]:
        findings: List[Finding] = []
        # A private/loopback scan cannot establish internet-edge posture. Do not
        # present a missing public WAF/CDN as a confirmed security flaw there.
        if target.is_private:
            return findings
        target_url = target.normalized_url

        try:
            async with httpx.AsyncClient(
                timeout=6.0,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "Expose-Security-Intelligence/1.0 (Edge Detection)"}
            ) as client:
                resp = await client.get(target_url)
                headers = resp.headers

                # Vercel and other edge providers emit an explicit mitigation
                # marker when automated traffic is challenged. This proves an
                # access control intervened, but not whether the application
                # itself has a WAF/CDN configuration; keep it informational.
                mitigation = headers.get("x-vercel-mitigated", "")
                if mitigation:
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"Edge mitigation challenge intercepted the scanner request ({mitigation}). Application edge posture was not assessed.",
                        response={
                            "status_code": resp.status_code,
                            "server": headers.get("server", "Unknown"),
                            "x-vercel-mitigated": mitigation,
                        },
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title="Edge Security Challenge Intercepted Automated Assessment",
                            severity=Severity.INFO,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.OBSERVED,
                            description="An edge security layer challenged the scanner before the application response was available, so header and WAF posture results are inconclusive.",
                            impact_explanation="This is a scan-scope boundary, not a security finding against the application.",
                            remediation="If an authorized assessment is needed, allowlist the scanner or use a verified browser-based scan path.",
                            evidence=evidence,
                            category=Category.CONFIGURATION,
                            rule_id="EXP-EDGE-CHALLENGE-INTERCEPTED",
                        )
                    )
                    return findings

                if resp.status_code >= 400:
                    return findings

                detected_wafs = self._detect_waf(headers)
                if detected_wafs:
                    for provider_name, desc, matched_header, matched_val in detected_wafs:
                        evidence = Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary=f"Detected {provider_name} edge layer via header '{matched_header}: {matched_val}'.",
                            response={matched_header: matched_val, "status_code": resp.status_code}
                        )
                        findings.append(
                            self.create_finding(
                                target=target,
                                title=f"Edge Web Application Firewall Detected ({provider_name})",
                                severity=Severity.INFO,
                                confidence=Confidence.CONFIRMED,
                                status=ObservationStatus.OBSERVED,
                                description=f"The application is routed through {desc}, providing edge filtering, DDoS protection, and TLS termination.",
                                impact_explanation="Hides the origin IP address from direct internet scans and absorbs volumetric L7 attacks.",
                                remediation="Ensure origin servers restrict direct ingress traffic exclusively to edge proxy IP ranges.",
                                verification_command=f"curl -sI '{target_url}' | grep -i '{matched_header}'",
                                evidence=evidence,
                                category=Category.CONFIGURATION
                            )
                        )
                else:
                    # No WAF detected on wire
                    server_banner = headers.get("server", "Unknown")
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"No recognizable edge WAF or CDN headers observed on {target_url} (Server: {server_banner}).",
                        response={"server": server_banner, "status_code": resp.status_code}
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title="No Edge WAF or Cloud Reverse Proxy Detected",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description=f"The application responds directly as '{server_banner}' without an observable edge Web Application Firewall (WAF) or CDN layer.",
                            impact_explanation="Direct-to-origin exposure increases vulnerability to denial-of-service (DDoS) and direct network exploitation.",
                            remediation="Consider deploying an edge proxy or cloud WAF (e.g., Cloudflare, AWS WAF, Fastly) to protect the origin server.",
                            verification_command=f"curl -sI '{target_url}'",
                            evidence=evidence,
                            category=Category.CONFIGURATION,
                            cwe_id="CWE-16"
                        )
                    )
        except Exception:
            pass

        return findings

    def _detect_waf(self, headers: httpx.Headers) -> List[Tuple[str, str, str, str]]:
        detected = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        server_val = headers_lower.get("server", "").lower()

        for name, header_keys, server_key, server_match, desc in WAF_SIGNATURES:
            matched = False
            for hk in header_keys:
                if hk in headers_lower:
                    detected.append((name, desc, hk, headers_lower[hk]))
                    matched = True
                    break
            if not matched and server_match and server_match in server_val:
                detected.append((name, desc, "server", headers_lower.get("server", "")))

        return detected
