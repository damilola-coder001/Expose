"""Authoritative Security Standards Mapping Module (Phase 10).

Maps empirical security findings to standard security verification frameworks:
- OWASP Top 10:2025 (Current top-level web application risk taxonomy)
- OWASP ASVS 5.0 (Application Security Verification Standard 5.0.0 release)
- CWE (Common Weakness Enumeration)
- CVE (Common Vulnerabilities and Exposures where applicable)

Strict Rule: Do not force mappings where they do not make sense (e.g. neutral
inventory observations, informational discoveries, or architectural telemetry).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class StandardsMapping:
    """Security standards mapping for a finding or rule."""
    owasp_top10: Optional[str] = None      # e.g., "A05:2025 - Security Misconfiguration"
    owasp_asvs: Optional[str] = None       # e.g., "V9.2.1"
    cwe_id: Optional[str] = None           # e.g., "CWE-319"
    cve_id: Optional[str] = None           # e.g., "CVE-2024-XXXX"
    asvs_description: Optional[str] = None # Text of the ASVS verification requirement
    reference_urls: List[str] = field(default_factory=list)


# OWASP Top 10:2025 Taxonomy Definitions
OWASP_TOP_10_2025 = {
    "A01:2025": "A01:2025 - Broken Access Control",
    "A02:2025": "A02:2025 - Cryptographic Failures",
    "A03:2025": "A03:2025 - Injection",
    "A04:2025": "A04:2025 - Insecure Design",
    "A05:2025": "A05:2025 - Security Misconfiguration",
    "A06:2025": "A06:2025 - Vulnerable and Outdated Components",
    "A07:2025": "A07:2025 - Identification and Authentication Failures",
    "A08:2025": "A08:2025 - Software and Data Integrity Failures",
    "A09:2025": "A09:2025 - Security Logging and Monitoring Failures",
    "A10:2025": "A10:2025 - Server-Side Request Forgery (SSRF)",
}

# Catalog of Standards Mappings by Rule ID / Pattern
STANDARDS_CATALOG: Dict[str, StandardsMapping] = {
    # Transport & TLS (V9 Communications)
    "EXP-TLS-EXPIRED": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V9.1.3",
        cwe_id="CWE-295",
        asvs_description="Verify that TLS certificates are valid, trusted, and not expired.",
        reference_urls=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]
    ),
    "EXP-TLS-HOSTNAME-MISMATCH": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V9.1.3",
        cwe_id="CWE-297",
        asvs_description="Verify that the TLS certificate matches the domain or hostname requested.",
        reference_urls=["https://cwe.mitre.org/data/definitions/297.html"]
    ),
    "EXP-TLS-SELFSIGNED": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V9.1.3",
        cwe_id="CWE-295",
        asvs_description="Verify that TLS certificates are issued by a recognized and trusted certificate authority.",
        reference_urls=["https://cwe.mitre.org/data/definitions/295.html"]
    ),
    "EXP-TLS-REVOKED": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V9.1.3",
        cwe_id="CWE-295",
        asvs_description="Verify that TLS certificates are not revoked via OCSP or CRL checking.",
        reference_urls=["https://cwe.mitre.org/data/definitions/295.html"]
    ),
    "EXP-TLS-DEPRECATED-VERSION": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V9.1.2",
        cwe_id="CWE-326",
        asvs_description="Verify that legacy and broken protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1) are disabled.",
        reference_urls=["https://cwe.mitre.org/data/definitions/326.html"]
    ),
    "EXP-TLS-WEAK-CIPHER": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V9.1.1",
        cwe_id="CWE-327",
        asvs_description="Verify that only approved, modern cipher suites providing forward secrecy are supported.",
        reference_urls=["https://cwe.mitre.org/data/definitions/327.html"]
    ),
    "EXP-TRANSPORT-NO-REDIRECT": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V9.2.1",
        cwe_id="CWE-319",
        asvs_description="Verify that all plaintext HTTP requests are automatically redirected to HTTPS.",
        reference_urls=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]
    ),
    "EXP-HSTS-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V9.2.1",
        cwe_id="CWE-319",
        asvs_description="Verify that the HTTP Strict-Transport-Security (HSTS) header is present and configured with a max-age of at least 1 year.",
        reference_urls=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"]
    ),
    "EXP-HSTS-WEAK": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V9.2.2",
        cwe_id="CWE-319",
        asvs_description="Verify that HSTS specifies includeSubDomains and preload to prevent downgrade attacks.",
        reference_urls=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"]
    ),

    # Browser Security & Headers (V14 Configuration)
    "EXP-CSP-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.4.1",
        cwe_id="CWE-693",
        asvs_description="Verify that a Content-Security-Policy (CSP) response header is implemented to restrict unauthorized script execution.",
        reference_urls=["https://owasp.org/www-project-secure-headers/"]
    ),
    "EXP-CSP-UNSAFE": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.4.1",
        cwe_id="CWE-79",
        asvs_description="Verify that CSP directives do not include unsafe-inline or unsafe-eval without cryptographic nonces or hashes.",
        reference_urls=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"]
    ),
    "EXP-CLICKJACKING-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.4.4",
        cwe_id="CWE-1021",
        asvs_description="Verify that Content-Security-Policy frame-ancestors or X-Frame-Options is configured to prevent clickjacking.",
        reference_urls=["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"]
    ),
    "EXP-MIME-SNIFF-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.4.2",
        cwe_id="CWE-16",
        asvs_description="Verify that the X-Content-Type-Options: nosniff header is set on all HTTP responses.",
        reference_urls=["https://owasp.org/www-project-secure-headers/"]
    ),
    "EXP-REFERRER-POLICY-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.4.3",
        cwe_id="CWE-200",
        asvs_description="Verify that a restrictive Referrer-Policy is configured to prevent leakage of sensitive URLs and tokens.",
        reference_urls=["https://owasp.org/www-project-secure-headers/"]
    ),
    "EXP-PERMISSIONS-POLICY-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.4.5",
        cwe_id="CWE-16",
        asvs_description="Verify that Permissions-Policy is set to disable browser features like camera, microphone, and geolocation.",
        reference_urls=["https://owasp.org/www-project-secure-headers/"]
    ),
    "EXP-SERVER-HEADER-LEAK": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.5.2",
        cwe_id="CWE-200",
        asvs_description="Verify that web server technology and version banners (Server, X-Powered-By) are suppressed or obfuscated.",
        reference_urls=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
    ),
    "EXP-HTTP-TRACE-ENABLED": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.5.1",
        cwe_id="CWE-16",
        asvs_description="Verify that the HTTP TRACE and TRACK methods are disabled on the web server.",
        reference_urls=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
    ),

    # Cookie & Session Management (V3 Session Management)
    "EXP-COOKIE-NO-SECURE": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A07:2025"],
        owasp_asvs="V3.4.1",
        cwe_id="CWE-614",
        asvs_description="Verify that the Secure flag is set on all session and sensitive cookies.",
        reference_urls=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"]
    ),
    "EXP-COOKIE-NO-HTTPONLY": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A07:2025"],
        owasp_asvs="V3.4.1",
        cwe_id="CWE-1004",
        asvs_description="Verify that the HttpOnly flag is set on all session cookies to prevent access via JavaScript.",
        reference_urls=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"]
    ),
    "EXP-COOKIE-NO-SAMESITE": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A07:2025"],
        owasp_asvs="V3.4.3",
        cwe_id="CWE-1275",
        asvs_description="Verify that the SameSite attribute is set to Lax or Strict on all state-management cookies.",
        reference_urls=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"]
    ),
    "EXP-COOKIE-BROAD-DOMAIN": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A07:2025"],
        owasp_asvs="V3.4.4",
        cwe_id="CWE-287",
        asvs_description="Verify that the domain attribute of sensitive cookies is not set too broadly (e.g. parent domain wide).",
        reference_urls=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"]
    ),

    # Client-Side & Third-Party Integrity (V14 & V8)
    "EXP-SRI-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A08:2025"],
        owasp_asvs="V14.4.7",
        cwe_id="CWE-353",
        asvs_description="Verify that Subresource Integrity (SRI) attributes are included for external scripts and stylesheets.",
        reference_urls=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"]
    ),
    "EXP-SOURCEMAP-PUBLIC": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V12.3.2",
        cwe_id="CWE-540",
        asvs_description="Verify that production source map files (.js.map) are not publicly accessible.",
        reference_urls=["https://cwe.mitre.org/data/definitions/540.html"]
    ),
    "EXP-MIXED-CONTENT": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V14.4.6",
        cwe_id="CWE-319",
        asvs_description="Verify that pages served over HTTPS do not load active or passive subresources over insecure HTTP.",
        reference_urls=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"]
    ),
    "EXP-INSECURE-FORM-ACTION": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V9.2.1",
        cwe_id="CWE-523",
        asvs_description="Verify that all HTML forms submit exclusively over HTTPS endpoints.",
        reference_urls=["https://cwe.mitre.org/data/definitions/523.html"]
    ),
    "EXP-SENSITIVE-QUERY-PARAMS": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A04:2025"],
        owasp_asvs="V8.3.1",
        cwe_id="CWE-598",
        asvs_description="Verify that sensitive parameters (tokens, passwords) are not passed in GET query strings.",
        reference_urls=["https://cwe.mitre.org/data/definitions/598.html"]
    ),

    # Attack Surface & Information Disclosure (V4 & V12)
    "EXP-SENSITIVE-FILE-EXPOSED": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V12.3.1",
        cwe_id="CWE-200",
        asvs_description="Verify that sensitive configuration files (.env, .git, backups) are blocked from web access.",
        reference_urls=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
    ),
    "EXP-ROBOTS-SENSITIVE-PATH": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A01:2025"],
        owasp_asvs="V4.1.3",
        cwe_id="CWE-200",
        asvs_description="Verify that robots.txt does not disclose private admin paths or unauthenticated internal resources.",
        reference_urls=["https://cwe.mitre.org/data/definitions/200.html"]
    ),

    # DNS & Email Architecture (V9 Communications / Configuration)
    "EXP-DMARC-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V9.1.4",
        cwe_id="CWE-358",
        asvs_description="Verify that DMARC records are configured with an active enforcement policy (quarantine or reject).",
        reference_urls=["https://dmarc.org/"]
    ),
    "EXP-SPF-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V9.1.4",
        cwe_id="CWE-358",
        asvs_description="Verify that SPF records are published and enforce authorized sending infrastructure.",
        reference_urls=["https://tools.ietf.org/html/rfc7208"]
    ),
    "EXP-DNSSEC-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V9.1.5",
        cwe_id="CWE-358",
        asvs_description="Verify that DNS zones are signed with DNSSEC to prevent cache poisoning.",
        reference_urls=["https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"]
    ),

    # Nmap & Network Perimeter (V14 Configuration / Architecture)
    "EXP-PORT-EXPOSED-DB": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.1.1",
        cwe_id="CWE-284",
        asvs_description="Verify that database network listeners are isolated within internal subnets and not exposed to the public internet.",
        reference_urls=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
    ),
    "EXP-PORT-EXPOSED-TELNET": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V9.1.1",
        cwe_id="CWE-319",
        asvs_description="Verify that unencrypted legacy protocols such as Telnet or rlogin are disabled.",
        reference_urls=["https://cwe.mitre.org/data/definitions/319.html"]
    ),

    # Nikto Web Server Checks
    "EXP-NIKTO-SERVER-DISCLOSURE": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.5.2",
        cwe_id="CWE-200",
        asvs_description="Verify that web server technology and version banners (Server, X-Powered-By) are suppressed or obfuscated.",
        reference_urls=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
    ),
    "EXP-NIKTO-TRACE-ENABLED": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.5.1",
        cwe_id="CWE-693",
        asvs_description="Verify that HTTP TRACE and TRACK debugging methods are disabled.",
        reference_urls=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
    ),
    "EXP-NIKTO-DANGEROUS-METHODS": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.5.1",
        cwe_id="CWE-650",
        asvs_description="Verify that dangerous HTTP methods (PUT, DELETE) require strict authorization and are disabled on public roots.",
        reference_urls=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
    ),

    # OpenSCAP Configuration & Hardening
    "EXP-SCAP-TLS-DEPRECATED": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A02:2025"],
        owasp_asvs="V9.1.2",
        cwe_id="CWE-326",
        asvs_description="Verify that deprecated TLS protocols (TLS 1.0, TLS 1.1) are disabled in compliance with SCAP baselines and NIST SP 800-52r2.",
        reference_urls=["https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"]
    ),
    "EXP-SCAP-HSTS-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V9.2.1",
        cwe_id="CWE-319",
        asvs_description="Verify that HTTP Strict Transport Security (HSTS) with minimum max-age 31536000 is enforced per SCAP/CIS benchmark.",
        reference_urls=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"]
    ),
    "EXP-SCAP-MIME-SNIFF": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.4.2",
        cwe_id="CWE-16",
        asvs_description="Verify that X-Content-Type-Options: nosniff is configured across web endpoints per CIS web benchmarks.",
        reference_urls=["https://owasp.org/www-project-secure-headers/"]
    ),
    "EXP-SCAP-CSP-MISSING": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A05:2025"],
        owasp_asvs="V14.4.1",
        cwe_id="CWE-1021",
        asvs_description="Verify that a Content Security Policy is implemented per SCAP hardening recommendations.",
        reference_urls=["https://owasp.org/www-project-secure-headers/"]
    ),

    # GVM / CVE Vulnerability Tracking
    "EXP-GVM-VULNERABILITY": StandardsMapping(
        owasp_top10=OWASP_TOP_10_2025["A06:2025"],
        owasp_asvs="V14.2.1",
        cwe_id="CWE-1395",
        asvs_description="Verify that all third-party components and libraries are up to date and not vulnerable to known CVEs.",
        reference_urls=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"]
    ),
}

# Fuzzy Title Matching Dictionary for Dynamic Probes
_TITLE_PATTERN_MAPPING: List[tuple[str, str]] = [
    ("hsts", "EXP-HSTS-MISSING"),
    ("strict-transport-security", "EXP-HSTS-MISSING"),
    ("content-security-policy", "EXP-CSP-MISSING"),
    ("csp", "EXP-CSP-MISSING"),
    ("clickjacking", "EXP-CLICKJACKING-MISSING"),
    ("x-frame-options", "EXP-CLICKJACKING-MISSING"),
    ("nosniff", "EXP-MIME-SNIFF-MISSING"),
    ("x-content-type-options", "EXP-MIME-SNIFF-MISSING"),
    ("referrer-policy", "EXP-REFERRER-POLICY-MISSING"),
    ("permissions-policy", "EXP-PERMISSIONS-POLICY-MISSING"),
    ("server version", "EXP-SERVER-HEADER-LEAK"),
    ("x-powered-by", "EXP-SERVER-HEADER-LEAK"),
    ("http trace", "EXP-HTTP-TRACE-ENABLED"),
    ("secure flag", "EXP-COOKIE-NO-SECURE"),
    ("httponly", "EXP-COOKIE-NO-HTTPONLY"),
    ("samesite", "EXP-COOKIE-NO-SAMESITE"),
    ("cookie domain", "EXP-COOKIE-BROAD-DOMAIN"),
    ("subresource integrity", "EXP-SRI-MISSING"),
    ("sri", "EXP-SRI-MISSING"),
    ("source map", "EXP-SOURCEMAP-PUBLIC"),
    ("mixed content", "EXP-MIXED-CONTENT"),
    ("insecure form", "EXP-INSECURE-FORM-ACTION"),
    ("plaintext http", "EXP-TRANSPORT-NO-REDIRECT"),
    ("redirect to https", "EXP-TRANSPORT-NO-REDIRECT"),
    ("certificate expired", "EXP-TLS-EXPIRED"),
    ("hostname mismatch", "EXP-TLS-HOSTNAME-MISMATCH"),
    ("self-signed", "EXP-TLS-SELFSIGNED"),
    ("weak cipher", "EXP-TLS-WEAK-CIPHER"),
    ("deprecated tls", "EXP-TLS-DEPRECATED-VERSION"),
    ("tls 1.0", "EXP-TLS-DEPRECATED-VERSION"),
    ("tls 1.1", "EXP-TLS-DEPRECATED-VERSION"),
    ("dmarc", "EXP-DMARC-MISSING"),
    ("spf", "EXP-SPF-MISSING"),
    ("dnssec", "EXP-DNSSEC-MISSING"),
    (".env", "EXP-SENSITIVE-FILE-EXPOSED"),
    (".git", "EXP-SENSITIVE-FILE-EXPOSED"),
    ("robots.txt", "EXP-ROBOTS-SENSITIVE-PATH"),
    ("exposed database", "EXP-PORT-EXPOSED-DB"),
    ("mysql", "EXP-PORT-EXPOSED-DB"),
    ("redis", "EXP-PORT-EXPOSED-DB"),
    ("postgresql", "EXP-PORT-EXPOSED-DB"),
    ("elasticsearch", "EXP-PORT-EXPOSED-DB"),
    ("mongodb", "EXP-PORT-EXPOSED-DB"),
    ("telnet", "EXP-PORT-EXPOSED-TELNET"),
    ("nikto", "EXP-NIKTO-SERVER-DISCLOSURE"),
    ("scap compliance", "EXP-SCAP-HSTS-MISSING"),
    ("gvm", "EXP-GVM-VULNERABILITY"),
]


def resolve_standards_mapping(
    rule_id: Optional[str] = None,
    title: Optional[str] = None,
    cwe_id: Optional[str] = None,
    cve_id: Optional[str] = None,
    is_observation: bool = False,
) -> Optional[StandardsMapping]:
    """Resolves standards mapping for a finding without forcing mappings where inappropriate.
    
    Args:
        rule_id: Explicit internal rule identifier (e.g., "EXP-HSTS-MISSING").
        title: Title of the finding.
        cwe_id: Explicit CWE identifier if already known.
        cve_id: Explicit CVE identifier if known.
        is_observation: If True, indicates a positive/neutral observation or asset inventory
                        item. In this case, standards mappings are omitted (returns None).
                        
    Returns:
        StandardsMapping containing OWASP Top 10:2025 and OWASP ASVS 5.0, or None if unmapped.
    """
    if is_observation:
        # Rule: Do not force standards mappings on neutral inventory discoveries
        return None

    # 1. Exact catalog match by rule_id
    if rule_id and rule_id in STANDARDS_CATALOG:
        base = STANDARDS_CATALOG[rule_id]
        if cve_id and not base.cve_id:
            return StandardsMapping(
                owasp_top10=base.owasp_top10,
                owasp_asvs=base.owasp_asvs,
                cwe_id=cwe_id or base.cwe_id,
                cve_id=cve_id,
                asvs_description=base.asvs_description,
                reference_urls=base.reference_urls,
            )
        return base

    # 2. Match by title heuristic
    if title:
        lower_title = title.lower()
        for keyword, catalog_key in _TITLE_PATTERN_MAPPING:
            if keyword in lower_title:
                base = STANDARDS_CATALOG[catalog_key]
                return StandardsMapping(
                    owasp_top10=base.owasp_top10,
                    owasp_asvs=base.owasp_asvs,
                    cwe_id=cwe_id or base.cwe_id,
                    cve_id=cve_id or base.cve_id,
                    asvs_description=base.asvs_description,
                    reference_urls=base.reference_urls,
                )

    # 3. Fallback on explicit CWE if known
    if cwe_id:
        for m in STANDARDS_CATALOG.values():
            if m.cwe_id == cwe_id:
                return StandardsMapping(
                    owasp_top10=m.owasp_top10,
                    owasp_asvs=m.owasp_asvs,
                    cwe_id=cwe_id,
                    cve_id=cve_id,
                    asvs_description=m.asvs_description,
                    reference_urls=m.reference_urls,
                )

    # No forced mapping
    return None
