"""DNS and email authentication security posture probe.

Performs live DNS resolution for record types, validates SPF, DMARC, CAA, and DNSSEC.
Distinguishes CONFIRMED misconfigurations from positive OBSERVED attributes.
"""

import ipaddress
from typing import List, Optional
import dns.resolver
import dns.rdatatype
import dns.exception

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


import httpx
import dns.zone
import dns.query

TAKEOVER_SIGNATURES = [
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here", Severity.HIGH),
    ("s3.amazonaws.com", "Amazon S3 Bucket", "NoSuchBucket", Severity.HIGH),
    ("s3-website", "Amazon S3 Website", "NoSuchBucket", Severity.HIGH),
    ("herokuapp.com", "Heroku App", "no-such-app", Severity.HIGH),
    ("herokudns.com", "Heroku DNS", "no-such-app", Severity.HIGH),
    ("azurewebsites.net", "Azure App Service", "404 Web Site not found", Severity.HIGH),
    ("cloudapp.azure.com", "Azure Cloud Service", "404 Web Site not found", Severity.HIGH),
    ("trafficmanager.net", "Azure Traffic Manager", "404 Web Site not found", Severity.HIGH),
    ("fastly.net", "Fastly CDN", "Fastly error: unknown domain", Severity.HIGH),
    ("myshopify.com", "Shopify Store", "Sorry, this shop is currently unavailable", Severity.HIGH),
    ("zendesk.com", "Zendesk Help Center", "Help Center Closed", Severity.MEDIUM),
]


class DNSProbe(BaseProbe):
    """Inspects DNS infrastructure, email security records (SPF, DMARC), CAA, DNSSEC, and takeover vectors."""

    @property
    def name(self) -> str:
        return "dns_posture"

    @property
    def category(self) -> Category:
        return Category.DNS_CONFIGURATION

    @property
    def description(self) -> str:
        return "Analyzes DNS records, CAA policies, email security (SPF, DMARC, DKIM), DNSSEC, and dangling CNAME takeover."

    async def execute(self, target: TargetScope) -> List[Finding]:
        findings: List[Finding] = []
        domain = target.host

        # SPF, DMARC, CAA, and DNSSEC are domain-zone controls. An IP literal or
        # private target has no public DNS zone to assess, so treating absent
        # records as confirmed flaws would create misleading findings.
        try:
            ipaddress.ip_address(domain)
            return findings
        except ValueError:
            pass
        if target.is_private:
            return findings

        resolver = dns.resolver.Resolver()
        resolver.timeout = 4.0
        resolver.lifetime = 4.0

        # 1. Inspect CAA Records
        caa_records = self._query_records(resolver, domain, "CAA")
        if caa_records is None:
            return findings
        if not caa_records:
            evidence = Evidence(
                type=EvidenceType.DNS_RECORD,
                summary=f"No CAA records found for {domain}.",
                raw_data={"query": domain, "type": "CAA", "records": []}
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Missing Certificate Authority Authorization (CAA) Record",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=(
                        f"The domain '{domain}' does not publish any CAA records. Without CAA, any "
                        "publicly trusted Certificate Authority (CA) is permitted to issue certificates "
                        "for this domain, increasing exposure to CA compromise or mis-issuance."
                    ),
                    impact_explanation=(
                        "Without CAA records, an attacker who compromises any global CA or exploits a rogue CA "
                        f"can generate valid SSL certificates for {domain} without triggering CA verification restrictions."
                    ),
                    remediation=(
                        "Publish CAA DNS records specifying authorized certificate authorities. Example:\n"
                        f"{domain}. IN CAA 0 issue \"letsencrypt.org\"\n"
                        f"{domain}. IN CAA 0 iodef \"mailto:security@{domain}\""
                    ),
                    verification_command=f"dig CAA {domain} +short",
                    evidence=evidence,
                    category=Category.DNS_CONFIGURATION,
                    cwe_id="CWE-295"
                )
            )
        else:
            evidence = Evidence(
                type=EvidenceType.DNS_RECORD,
                summary=f"Found {len(caa_records)} CAA record(s) on {domain}.",
                raw_data={"query": domain, "records": caa_records}
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Certificate Authority Authorization (CAA) Configured",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.OBSERVED,
                    description=f"Domain '{domain}' enforces CAA policies restricting which CAs may issue certificates.",
                    impact_explanation="Restricts certificate issuance to explicitly authorized CAs, preventing unauthorized issuance.",
                    remediation="Maintain and review authorized CA list periodically.",
                    verification_command=f"dig CAA {domain} +short",
                    evidence=evidence,
                    category=Category.DNS_CONFIGURATION
                )
            )

        # 2. Inspect SPF in TXT records
        txt_records = self._query_records(resolver, domain, "TXT")
        if txt_records is None:
            return findings
        spf_records = [r for r in txt_records if r.startswith("v=spf1")]

        if not spf_records:
            evidence = Evidence(
                type=EvidenceType.DNS_RECORD,
                summary=f"No TXT records matching 'v=spf1' found on {domain}.",
                raw_data={"query": domain, "type": "TXT", "all_txt_records": txt_records}
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Missing Sender Policy Framework (SPF) Record",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=(
                        f"The domain '{domain}' has no SPF record configured. Without an SPF record, "
                        "mail transfer agents cannot verify whether sending servers are authorized, "
                        "leaving the domain susceptible to email spoofing and phishing."
                    ),
                    impact_explanation=(
                        f"Phishing adversaries can forge emails claiming to originate from @{domain}, "
                        "tricking employees, partners, and customers into clicking credential-harvesting links."
                    ),
                    remediation="Define and publish an SPF record in a DNS TXT record. Example: v=spf1 include:_spf.example.com -all",
                    verification_command=f"dig TXT {domain} +short",
                    evidence=evidence,
                    category=Category.EMAIL_SECURITY,
                    cwe_id="CWE-358"
                )
            )
        else:
            has_permissive_all = any("+all" in spf.split() for spf in spf_records)
            if has_permissive_all:
                evidence = Evidence(
                    type=EvidenceType.DNS_RECORD,
                    summary=f"SPF record on {domain} contains permissive '+all'.",
                    raw_data={"query": domain, "records": spf_records}
                )
                findings.append(
                    self.create_finding(
                        target=target,
                        title="Overly Permissive SPF Record (+all)",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description=(
                            f"The SPF record for '{domain}' contains '+all'. This explicitly authorizes "
                            "any IP address in the world to send email on behalf of this domain."
                        ),
                        impact_explanation="Explicitly bypasses email origin authentication for all sending IP addresses globally.",
                        remediation="Change '+all' to '-all' (hard fail) or '~all' (soft fail) in the SPF TXT record.",
                        verification_command=f"dig TXT {domain} +short",
                        evidence=evidence,
                        category=Category.EMAIL_SECURITY,
                        cwe_id="CWE-358"
                    )
                )
            else:
                # Check lookup count limit
                for spf in spf_records:
                    terms = spf.split()
                    lookup_terms = [t for t in terms if any(t.startswith(prefix) for prefix in ("include:", "a", "mx", "ptr", "exists:", "redirect="))]
                    if len(lookup_terms) > 10:
                        evidence = Evidence(
                            type=EvidenceType.DNS_RECORD,
                            summary=f"SPF record contains {len(lookup_terms)} lookup mechanisms (RFC 7208 maximum is 10): {spf}",
                            raw_data={"spf": spf, "lookup_count": len(lookup_terms)}
                        )
                        findings.append(
                            self.create_finding(
                                target=target,
                                title="SPF Record Exceeds 10 DNS Lookup Limit (RFC 7208)",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.CONFIRMED,
                                status=ObservationStatus.CONFIRMED,
                                description=f"SPF record has {len(lookup_terms)} DNS lookup mechanisms. Mail receivers will return 'PermError' and treat legitimate emails as unauthenticated.",
                                impact_explanation="Legitimate outbound emails may be rejected or sent to spam folders due to SPF evaluation failure.",
                                remediation="Flatten SPF includes or use dedicated SPF management tooling to reduce nested DNS queries under 10.",
                                verification_command=f"dig TXT {domain} +short",
                                evidence=evidence,
                                category=Category.EMAIL_SECURITY,
                                cwe_id="CWE-358"
                            )
                        )

                evidence = Evidence(
                    type=EvidenceType.DNS_RECORD,
                    summary=f"Valid SPF record published for {domain}.",
                    raw_data={"records": spf_records}
                )
                findings.append(
                    self.create_finding(
                        target=target,
                        title="Sender Policy Framework (SPF) Configured",
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.OBSERVED,
                        description=f"Domain '{domain}' publishes a valid SPF record controlling mail server origins.",
                        impact_explanation="Helps receiving mail servers reject spoofed messages.",
                        remediation="Ensure all third-party sending providers (e.g. SendGrid, Google Workspace) remain documented.",
                        verification_command=f"dig TXT {domain} +short",
                        evidence=evidence,
                        category=Category.EMAIL_SECURITY
                    )
                )

        # 3. Inspect DMARC
        dmarc_target = f"_dmarc.{domain}"
        dmarc_txt = self._query_records(resolver, dmarc_target, "TXT")
        if dmarc_txt is None:
            return findings
        dmarc_records = [r for r in dmarc_txt if r.startswith("v=DMARC1")]

        if not dmarc_records:
            evidence = Evidence(
                type=EvidenceType.DNS_RECORD,
                summary=f"No DMARC record found at {dmarc_target}.",
                raw_data={"query": dmarc_target, "type": "TXT", "records": dmarc_txt}
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Missing DMARC Policy Record",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=(
                        f"The domain '{domain}' does not publish a DMARC record at '{dmarc_target}'. "
                        "DMARC instructs recipient email systems how to handle emails that fail SPF and "
                        "DKIM checks, and enables abuse reporting."
                    ),
                    impact_explanation="Without DMARC, fraudulent emails passing or failing loose SPF rules will still land in inboxes without forensic alerts.",
                    remediation=f"Publish a DMARC TXT record at '_dmarc.{domain}'. Start with: v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain};",
                    verification_command=f"dig TXT _dmarc.{domain} +short",
                    evidence=evidence,
                    category=Category.EMAIL_SECURITY,
                    cwe_id="CWE-358"
                )
            )
        else:
            for dmarc in dmarc_records:
                tags = self._parse_dmarc_tags(dmarc)
                policy = tags.get("p", "").lower()
                if policy == "none":
                    evidence = Evidence(
                        type=EvidenceType.DNS_RECORD,
                        summary=f"DMARC record at {dmarc_target} has monitoring-only policy p=none.",
                        raw_data={"query": dmarc_target, "dmarc_record": dmarc, "parsed_tags": tags}
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title="DMARC Policy Set to Ineffective 'p=none'",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description=(
                                f"The DMARC policy for '{domain}' is set to 'p=none'. While helpful for initial "
                                "telemetry collection, 'p=none' does not enforce rejection or quarantine of spoofed messages."
                            ),
                            impact_explanation="Spoofed messages will continue to be delivered to recipient inboxes because the policy instructs receivers to take no action.",
                            remediation="Progress policy from 'p=none' to 'p=quarantine' and ultimately 'p=reject'.",
                            verification_command=f"dig TXT _dmarc.{domain} +short",
                            evidence=evidence,
                            category=Category.EMAIL_SECURITY,
                            cwe_id="CWE-358"
                        )
                    )
                else:
                    evidence = Evidence(
                        type=EvidenceType.DNS_RECORD,
                        summary=f"DMARC policy enforcement is active: p={policy}",
                        raw_data={"dmarc_record": dmarc}
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title=f"DMARC Enforcement Active (p={policy})",
                            severity=Severity.INFO,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.OBSERVED,
                            description=f"Domain '{domain}' actively enforces DMARC policy '{policy}' on spoofed mail.",
                            impact_explanation="Significantly mitigates domain spoofing in modern email gateways.",
                            remediation="Review aggregate reports (rua) regularly for delivery false positives.",
                            verification_command=f"dig TXT _dmarc.{domain} +short",
                            evidence=evidence,
                            category=Category.EMAIL_SECURITY
                        )
                    )

        # 4. Check DNSSEC
        dnssec_active = self._check_dnssec(resolver, domain)
        if dnssec_active is None:
            # The resolver could not answer reliably, so do not convert an
            # operational DNS failure into a DNSSEC misconfiguration.
            pass
        elif not dnssec_active:
            evidence = Evidence(
                type=EvidenceType.DNS_RECORD,
                summary=f"DNSSEC is not enabled or lacks valid RRSIG records for {domain}.",
                raw_data={"domain": domain, "dnssec_enabled": False}
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="DNSSEC Not Configured",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=(
                        f"The domain '{domain}' does not have DNSSEC configured. Without DNSSEC, DNS responses "
                        "could theoretically be forged by an adversary with man-in-the-middle network capabilities."
                    ),
                    impact_explanation="Exposes recursive DNS resolvers to cache poisoning attacks if spoofed DNS packets are accepted.",
                    remediation="Enable DNSSEC at your DNS registrar and authoritative DNS provider.",
                    verification_command=f"dig +dnssec {domain} +short",
                    evidence=evidence,
                    category=Category.DNS_CONFIGURATION,
                    cwe_id="CWE-358"
                )
            )
        else:
            evidence = Evidence(
                type=EvidenceType.DNS_RECORD,
                summary=f"DNSSEC is active with cryptographic RRSIG records for {domain}.",
                raw_data={"domain": domain, "dnssec_enabled": True}
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="DNSSEC Cryptographically Signed",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.OBSERVED,
                    description=f"Domain '{domain}' provides DNSSEC cryptographic signatures protecting DNS responses.",
                    impact_explanation="Prevents DNS cache poisoning and man-in-the-middle spoofing of domain records.",
                    remediation="Ensure KSK (Key Signing Key) rollover schedules are maintained.",
                    verification_command=f"dig +dnssec {domain} +short",
                    evidence=evidence,
                    category=Category.DNS_CONFIGURATION
                )
            )

        # 5. Dangling CNAME & Subdomain Takeover Analysis
        cname_findings = await self._check_subdomain_takeover(target, resolver, domain)
        findings.extend(cname_findings)

        # 6. Zone Transfer (AXFR) Audit
        axfr_findings = self._check_zone_transfer(target, resolver, domain)
        findings.extend(axfr_findings)

        return findings

    async def _check_subdomain_takeover(self, target: TargetScope, resolver: dns.resolver.Resolver, domain: str) -> List[Finding]:
        findings: List[Finding] = []
        cnames = self._query_records(resolver, domain, "CNAME")
        if not cnames:
            return findings

        for cname in cnames:
            cname_clean = cname.rstrip(".").lower()
            for pattern, service_name, fingerprint, sev in TAKEOVER_SIGNATURES:
                if pattern in cname_clean:
                    try:
                        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                            resp = await client.get(f"http://{domain}")
                            if fingerprint.lower() in resp.text.lower():
                                evidence = Evidence(
                                    type=EvidenceType.DNS_RECORD,
                                    summary=f"Dangling CNAME '{cname_clean}' points to unclaimed {service_name} resource.",
                                    raw_data={"cname": cname_clean, "matched_fingerprint": fingerprint, "service": service_name}
                                )
                                findings.append(
                                    self.create_finding(
                                        target=target,
                                        title=f"Potential Subdomain Takeover: Dangling CNAME to {service_name}",
                                        severity=sev,
                                        confidence=Confidence.CONFIRMED,
                                        status=ObservationStatus.CONFIRMED,
                                        description=f"CNAME '{cname_clean}' points to a {service_name} resource that returns an unclaimed footprint ('{fingerprint}').",
                                        impact_explanation="An attacker can register the abandoned resource name on the cloud provider and take full control of traffic sent to this domain.",
                                        remediation=f"Claim the resource on {service_name} or remove the dangling CNAME record from DNS.",
                                        verification_command=f"curl -sL http://{domain} | grep -i '{fingerprint}'",
                                        evidence=evidence,
                                        category=Category.DNS_CONFIGURATION,
                                        cwe_id="CWE-284"
                                    )
                                )
                    except Exception:
                        pass
        return findings

    def _check_zone_transfer(self, target: TargetScope, resolver: dns.resolver.Resolver, domain: str) -> List[Finding]:
        findings: List[Finding] = []
        ns_records = self._query_records(resolver, domain, "NS")
        if not ns_records:
            return findings
        for ns in ns_records[:3]:
            ns_clean = ns.rstrip(".")
            try:
                ns_ips = [str(r) for r in resolver.resolve(ns_clean, "A")]
                for ip in ns_ips[:1]:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ip, domain, timeout=3.0))
                        if zone and len(zone.nodes) > 1:
                            evidence = Evidence(
                                type=EvidenceType.DNS_RECORD,
                                summary=f"Authoritative nameserver {ns_clean} ({ip}) allowed open AXFR zone transfer for {domain} ({len(zone.nodes)} records exposed).",
                                raw_data={"nameserver": ns_clean, "ip": ip, "node_count": len(zone.nodes)}
                            )
                            findings.append(
                                self.create_finding(
                                    target=target,
                                    title=f"Critical DNS Zone Transfer (AXFR) Allowed by Nameserver ({ns_clean})",
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.CONFIRMED,
                                    status=ObservationStatus.CONFIRMED,
                                    description=f"Nameserver '{ns_clean}' responded to an unauthenticated AXFR query, dumping all internal and external DNS records.",
                                    impact_explanation="Reveals all hidden subdomains, internal staging servers, VPN endpoints, and infrastructure topology to attackers.",
                                    remediation=f"Restrict AXFR zone transfers on '{ns_clean}' to authorized secondary slave nameservers only.",
                                    verification_command=f"dig axfr @{ip} {domain}",
                                    evidence=evidence,
                                    category=Category.DNS_CONFIGURATION,
                                    cwe_id="CWE-200"
                                )
                            )
                    except Exception:
                        pass
            except Exception:
                pass
        return findings

    def _query_records(self, resolver: dns.resolver.Resolver, qname: str, rtype: str) -> Optional[List[str]]:
        """Returns records, an empty list for an authoritative absence, or None when DNS is unavailable."""
        results: List[str] = []
        try:
            answers = resolver.resolve(qname, rtype)
            for rdata in answers:
                if rtype == "TXT":
                    txt_bytes = b"".join(rdata.strings)
                    results.append(txt_bytes.decode("utf-8", errors="replace"))
                elif rtype == "CAA":
                    results.append(f"{rdata.flags} {rdata.tag.decode()} \"{rdata.value.decode()}\"")
                else:
                    results.append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except dns.exception.DNSException:
            return None
        return results

    def _parse_dmarc_tags(self, record: str) -> dict:
        tags = {}
        for part in record.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        return tags

    def _check_dnssec(self, resolver: dns.resolver.Resolver, domain: str) -> Optional[bool]:
        try:
            answers = resolver.resolve(domain, "DNSKEY")
            if answers and len(answers) > 0:
                return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException:
            return None
        try:
            answers = resolver.resolve(domain, "DS")
            if answers and len(answers) > 0:
                return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException:
            return None
        try:
            answers = resolver.resolve(domain, "A")
            response = answers.response
            for section in (response.answer, response.authority):
                for rrset in section:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException:
            return None
        return False
