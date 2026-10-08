"""Security metadata and policy probe for Expose.

Validates RFC 9116 security.txt vulnerability disclosure policy and analyzes robots.txt
for sensitive administrative or internal route disclosure.
"""

from datetime import datetime, timezone
import re
from typing import List
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
from .base import BaseProbe


class MetadataProbe(BaseProbe):
    """Inspects RFC 9116 security.txt files and robots.txt disclosures."""

    @property
    def name(self) -> str:
        return "security_metadata"

    @property
    def category(self) -> Category:
        return Category.SECURITY_METADATA

    @property
    def description(self) -> str:
        return "Validates RFC 9116 security.txt policies and analyzes robots.txt for sensitive route disclosures."

    async def execute(self, target: TargetScope) -> List[Finding]:
        findings: List[Finding] = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Expose-Security-Intelligence/0.1.0",
        }

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
            # 1. RFC 9116 security.txt discovery
            security_txt_url = f"{target.normalized_url}/.well-known/security.txt"
            fallback_url = f"{target.normalized_url}/security.txt"

            sec_resp = None
            sec_url_used = security_txt_url
            security_txt_responses = []
            try:
                sec_resp = await client.get(security_txt_url, headers=headers)
                security_txt_responses.append(sec_resp)
                if sec_resp.status_code != 200:
                    sec_resp = await client.get(fallback_url, headers=headers)
                    security_txt_responses.append(sec_resp)
                    sec_url_used = fallback_url
            except Exception:
                pass

            # A missing policy is only confirmed when both standard locations
            # answered definitively with 404/410. Timeouts, TLS failures, and
            # access controls are inconclusive and must not become findings.
            security_txt_missing = (
                len(security_txt_responses) == 2
                and all(response.status_code in (404, 410) for response in security_txt_responses)
            )

            if security_txt_missing:
                evidence = Evidence(
                    type=EvidenceType.SECURITY_TXT,
                    summary=f"No valid security.txt found at {security_txt_url}.",
                    request={"method": "GET", "url": security_txt_url},
                    raw_data={"status_codes": [response.status_code for response in security_txt_responses]}
                )
                findings.append(
                    self.create_finding(
                        target=target,
                        title="Missing RFC 9116 'security.txt' Policy",
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description="The website does not publish a 'security.txt' file at '/.well-known/security.txt'.",
                        impact_explanation="Ethical researchers finding vulnerabilities on your site have no standardized channel or PGP key to report findings responsibly.",
                        remediation=(
                            "Create '/.well-known/security.txt' containing at minimum:\n"
                            f"Contact: mailto:security@{target.host}\n"
                            "Expires: 2027-12-31T23:59:59.000Z\n"
                            f"Canonical: https://{target.host}/.well-known/security.txt"
                        ),
                        verification_command=f"curl -sL {security_txt_url}",
                        evidence=evidence,
                        category=Category.SECURITY_METADATA,
                        cwe_id="CWE-358"
                    )
                )
            elif sec_resp and sec_resp.status_code == 200 and sec_resp.text.strip():
                body = sec_resp.text
                has_contact = bool(re.search(r"^Contact:\s*.+", body, re.MULTILINE | re.IGNORECASE))
                expires_match = re.search(r"^Expires:\s*([^\r\n]+)", body, re.MULTILINE | re.IGNORECASE)

                if not has_contact:
                    evidence = Evidence(
                        type=EvidenceType.SECURITY_TXT,
                        summary=f"security.txt exists at {sec_url_used} but lacks mandatory 'Contact:' field.",
                        response={"body_sample": body[:500]}
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title="Invalid RFC 9116 security.txt: Missing 'Contact:' Directive",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description="The security.txt file exists but does not provide a required 'Contact:' address.",
                            impact_explanation="Prevents security reporters from contacting your team securely.",
                            remediation="Add a valid 'Contact: mailto:...' directive to security.txt.",
                            verification_command=f"curl -sL {sec_url_used}",
                            evidence=evidence,
                            category=Category.SECURITY_METADATA,
                            cwe_id="CWE-358"
                        )
                    )

                if expires_match:
                    expires_str = expires_match.group(1).strip()
                    try:
                        expires_dt = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
                        if expires_dt < datetime.now(timezone.utc):
                            evidence = Evidence(
                                type=EvidenceType.SECURITY_TXT,
                                summary=f"security.txt policy expired on {expires_str}.",
                                response={"expires": expires_str, "body_sample": body[:500]}
                            )
                            findings.append(
                                self.create_finding(
                                    target=target,
                                    title="Expired RFC 9116 security.txt Policy",
                                    severity=Severity.LOW,
                                    confidence=Confidence.CONFIRMED,
                                    status=ObservationStatus.CONFIRMED,
                                    description=f"The security.txt file expired on {expires_str}.",
                                    impact_explanation="Stale vulnerability disclosure policies may leave researchers reporting to decommissioned contact inboxes.",
                                    remediation="Update the 'Expires:' directive in security.txt to a future date.",
                                    verification_command=f"curl -sL {sec_url_used}",
                                    evidence=evidence,
                                    category=Category.SECURITY_METADATA,
                                    cwe_id="CWE-358"
                                )
                            )
                        else:
                            evidence = Evidence(
                                type=EvidenceType.SECURITY_TXT,
                                summary=f"Valid RFC 9116 security.txt found at {sec_url_used}.",
                                response={"body_sample": body[:300]}
                            )
                            findings.append(
                                self.create_finding(
                                    target=target,
                                    title="RFC 9116 security.txt Policy Published",
                                    severity=Severity.INFO,
                                    confidence=Confidence.CONFIRMED,
                                    status=ObservationStatus.OBSERVED,
                                    description=f"Active vulnerability disclosure policy found at {sec_url_used}.",
                                    impact_explanation="Encourages coordinated vulnerability disclosure by researchers.",
                                    remediation="Review security.txt directives annually.",
                                    verification_command=f"curl -sL {sec_url_used}",
                                    evidence=evidence,
                                    category=Category.SECURITY_METADATA
                                )
                            )
                    except Exception:
                        pass

            # 2. robots.txt analysis
            robots_url = f"{target.normalized_url}/robots.txt"
            try:
                rob_resp = await client.get(robots_url, headers=headers)
                if rob_resp.status_code == 200 and "text" in rob_resp.headers.get("content-type", "").lower():
                    body = rob_resp.text
                    sensitive_patterns = [
                        r"/admin", r"/internal", r"/private", r"/backend", r"/staging",
                        r"/backup", r"/db", r"/config", r"/\.git", r"/phpmyadmin"
                    ]
                    sensitive_disallows = []
                    for line in body.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            parts = line.split(":", 1)
                            if len(parts) > 1:
                                path = parts[1].strip()
                                for pat in sensitive_patterns:
                                    if re.search(pat, path, re.IGNORECASE):
                                        sensitive_disallows.append(path)
                                        break

                    if sensitive_disallows:
                        evidence = Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary=f"robots.txt disallows sensitive routes: {', '.join(sensitive_disallows[:5])}",
                            response={"disallowed_sensitive_paths": sensitive_disallows}
                        )
                        findings.append(
                            self.create_finding(
                                target=target,
                                title="Sensitive Internal Path Disclosure in robots.txt",
                                severity=Severity.LOW,
                                confidence=Confidence.CONFIRMED,
                                status=ObservationStatus.CONFIRMED,
                                description=f"robots.txt lists sensitive routes: {', '.join(sensitive_disallows[:6])}.",
                                impact_explanation="Attackers frequently inspect robots.txt to discover hidden admin panels, staging routes, and backup endpoints.",
                                remediation="Protect internal routes with authentication; avoid listing private URLs in robots.txt.",
                                verification_command=f"curl -sL {robots_url} | grep -i Disallow",
                                evidence=evidence,
                                category=Category.INFORMATION_DISCLOSURE,
                                cwe_id="CWE-200"
                            )
                        )
            except Exception:
                pass

        return findings
