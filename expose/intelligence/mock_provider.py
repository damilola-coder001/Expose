"""Deterministic Mock Security Research Provider (Phases 11 & 18).

Provides high-fidelity, grounded security intelligence responses for local testing,
CI environments, and offline scanning without requiring an external Gemini API key.
All citations reference verified, authoritative standards (OWASP, NIST, CISA, RFCs).
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from .provider import (
    AIIntelligenceReport,
    AIPrioritizationReport,
    FindingPriorityItem,
    SecurityResearchProvider,
    SourceCitation,
    SourceType,
)


class MockSecurityResearchProvider(SecurityResearchProvider):
    """Hermetic, deterministic provider for testing and offline environments."""

    @property
    def name(self) -> str:
        return "mock-security-researcher"

    async def analyze_finding(
        self,
        target_host: str,
        finding_data: Dict[str, Any],
        tech_context: Optional[Dict[str, Any]] = None,
    ) -> AIIntelligenceReport:
        title = finding_data.get("title", "")
        category = finding_data.get("category", "")
        severity = finding_data.get("severity", "MEDIUM")
        confidence = finding_data.get("confidence", "CONFIRMED")
        evidence = finding_data.get("evidence", {})
        cwe_id = finding_data.get("cwe_id")

        def clean_val(v: Any) -> str:
            s = getattr(v, "value", str(v))
            if "." in s:
                s = s.split(".")[-1]
            return s.replace("_", " ").title()

        cat_clean = clean_val(category)
        sev_clean = clean_val(severity)
        conf_clean = clean_val(confidence)

        lower_title = title.lower()

        # Dynamic contextualization using target host and tech stack
        server_info = ""
        if tech_context and tech_context.get("server"):
            server_info = f" running on {tech_context['server']}"

        # 1. HSTS / Transport
        if "strict-transport-security" in lower_title or "hsts" in lower_title or "https redirection" in lower_title:
            return AIIntelligenceReport(
                provider_name=self.name,
                model_version="mock-v1.0",
                generated_at=datetime.now(timezone.utc),
                observation=f"Expose observed that the target website '{target_host}' does not enforce HTTPS via the Strict-Transport-Security header during secure negotiations.",
                evidence_summary=evidence.get("summary", "Strict-Transport-Security response header was absent on HTTPS response."),
                security_meaning=(
                    f"The finding '{title}' indicates that HTTP Strict Transport Security (HSTS) is either missing, "
                    "misconfigured, or plaintext HTTP requests are not forcefully redirected to TLS."
                ),
                confidence_explanation="Confidence is CONFIRMED (100% certainty) based on direct empirical inspection of response headers received over the wire.",
                impact=(
                    f"For {target_host}{server_info}, any user on an insecure or shared network (public Wi-Fi, coffee shop, airport) "
                    "can be intercepted via SSL-stripping tools (e.g. sslstrip), converting HTTPS requests to unencrypted HTTP "
                    "and exposing credentials, session cookies, and sensitive application data."
                ),
                real_world_context=(
                    "OWASP and CISA mandate HSTS as a baseline defense against Man-in-the-Middle (MitM) attacks. "
                    "RFC 6797 requires compliant user agents to strictly reject insecure connections and refuse user click-through "
                    "warnings if certificate anomalies occur. Documented SSL-stripping attacks have historically harvested plaintext authorization tokens."
                ),
                recommendation="Configure the edge web server or CDN to return 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' and ensure all HTTP port 80 traffic immediately responds with a 301 Permanent Redirect to https://.",
                verification_method=f"Run 'curl -s -D - -o /dev/null https://{target_host}' and verify that the Strict-Transport-Security header is present with max-age >= 31536000.",
                explanation=(
                    f"The finding '{title}' indicates that HTTP Strict Transport Security (HSTS) is either missing, "
                    "misconfigured, or plaintext HTTP requests are not forcefully redirected to TLS."
                ),
                contextual_impact=(
                    f"For {target_host}{server_info}, any user on an insecure or shared network (public Wi-Fi, coffee shop, airport) "
                    "can be intercepted via SSL-stripping tools (e.g. sslstrip), converting HTTPS requests to unencrypted HTTP "
                    "and exposing credentials, session cookies, and sensitive application data."
                ),
                research_summary=(
                    "OWASP and CISA mandate HSTS as a baseline defense against Man-in-the-Middle (MitM) attacks. "
                    "RFC 6797 requires compliant user agents to strictly reject insecure connections and refuse user click-through "
                    "warnings if certificate anomalies occur."
                ),
                comparative_examples=(
                    "Major public Wi-Fi credential thefts and corporate espionage attacks have exploited missing HSTS "
                    "through ARP spoofing and SSL-stripping proxies to harvest plaintext authorization bearer tokens."
                ),
                developer_recommendations=[
                    "Configure the edge web server or CDN to return 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                    "Ensure all HTTP port 80 traffic immediately responds with a 301 Permanent Redirect to https://.",
                    "Verify domain eligibility and submit the domain to the Chrome/Firefox HSTS Preload list at hstspreload.org."
                ],
                priority_rationale=(
                    "Fix this immediately before addressing informational headers, because transport-layer downgrade attacks "
                    "completely invalidate application-layer defenses (cookies, tokens, and CSRF protection)."
                ),
                source_citations=[
                    SourceCitation(
                        title="OWASP HTTP Strict Transport Security Cheat Sheet",
                        url="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                        source_type=SourceType.OWASP,
                        snippet="HSTS protects against SSL-stripping and active MitM eavesdropping by forcing HTTPS at the browser level."
                    ),
                    SourceCitation(
                        title="RFC 6797: HTTP Strict Transport Security (HSTS)",
                        url="https://datatracker.ietf.org/doc/html/rfc6797",
                        source_type=SourceType.RFC_STANDARD,
                        snippet="Specifications for the Strict-Transport-Security HTTP response header field."
                    ),
                    SourceCitation(
                        title="CISA Binding Operational Directive 18-01: Enhance Email and Web Security",
                        url="https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security",
                        source_type=SourceType.CISA,
                        snippet="Requires all federal agency domains to enable HTTPS exclusively and enforce HSTS with a 1-year minimum max-age."
                    ),
                ],
                is_grounded=True,
            )

        # 2. Content-Security-Policy (CSP)
        elif "content-security-policy" in lower_title or "csp" in lower_title:
            return AIIntelligenceReport(
                provider_name=self.name,
                model_version="mock-v1.0",
                generated_at=datetime.now(timezone.utc),
                observation=f"Expose observed that '{target_host}' does not return a restrictive Content-Security-Policy (CSP) header on HTTP/HTTPS responses.",
                evidence_summary=evidence.get("summary", "Content-Security-Policy header was absent or improperly configured on observed HTTP responses."),
                security_meaning=(
                    f"The finding '{title}' denotes an absence or weakness in the Content-Security-Policy (CSP) header. "
                    "Without a strong CSP, the browser will execute arbitrary inline scripts and load untrusted third-party resources."
                ),
                confidence_explanation="Confidence is CONFIRMED based on direct response header inspection from unauthenticated GET requests.",
                impact=(
                    f"On {target_host}, if an injection flaw (reflected, stored, or DOM-based XSS) exists anywhere on the site, "
                    "an attacker can inject JavaScript that steals session tokens, logs keystrokes, or exfiltrates confidential user state."
                ),
                real_world_context=(
                    "OWASP Top 10:2025 classifies Injection and Security Misconfigurations among the highest web application threats. "
                    "In the 2018 British Airways Magecart incident, lack of script integrity and source controls enabled attackers to skim 380,000 payment card records via third-party script tampering. "
                    "ASVS 5.0 V14.4.1 requires strict CSPs utilizing nonces or cryptographic hashes to prevent untrusted script execution."
                ),
                recommendation="Implement a Content-Security-Policy header starting with 'default-src 'self'', eliminate 'unsafe-inline' and 'unsafe-eval' via nonces, and deploy in Report-Only mode first to monitor traffic.",
                verification_method=f"Run 'curl -s -I https://{target_host}' and verify that the Content-Security-Policy header is present with restrictive directives.",
                explanation=(
                    f"The finding '{title}' denotes an absence or weakness in the Content-Security-Policy (CSP) header. "
                    "Without a strong CSP, the browser will execute arbitrary inline scripts and load untrusted third-party resources."
                ),
                contextual_impact=(
                    f"On {target_host}, if an injection flaw (reflected, stored, or DOM-based XSS) exists anywhere on the site, "
                    "an attacker can inject JavaScript that steals session tokens, logs keystrokes, or exfiltrates confidential user state."
                ),
                research_summary=(
                    "OWASP Top 10:2025 classifies Injection and Security Misconfigurations among the highest web application threats. "
                    "ASVS 5.0 V14.4.1 requires strict CSPs utilizing nonces or cryptographic hashes to prevent untrusted script execution."
                ),
                comparative_examples=(
                    "The British Airways Magecart breach (2018) involved third-party script tampering that skimmed 380,000 credit card records. "
                    "A strict CSP restricting script destinations and requiring integrity hashes prevents unauthorized exfiltration endpoints."
                ),
                developer_recommendations=[
                    "Implement a Content-Security-Policy header starting with 'default-src 'self';'.",
                    "Eliminate 'unsafe-inline' and 'unsafe-eval' by adopting nonce-based script loading.",
                    "Deploy CSP in Report-Only mode ('Content-Security-Policy-Report-Only') first to monitor and refine directive policies."
                ],
                priority_rationale=(
                    "CSP is the primary defense-in-depth mitigation against Cross-Site Scripting (XSS). It should be scheduled "
                    "as a critical priority alongside input validation."
                ),
                source_citations=[
                    SourceCitation(
                        title="OWASP Content Security Policy Cheat Sheet",
                        url="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                        source_type=SourceType.OWASP,
                        snippet="Comprehensive guide to constructing effective, nonce-based and hash-based CSP architectures."
                    ),
                    SourceCitation(
                        title="NIST SP 800-95: Guide to Secure Web Services",
                        url="https://csrc.nist.gov/publications/detail/sp/800-95/final",
                        source_type=SourceType.NIST,
                        snippet="Federal guidelines on browser controls, script execution isolation, and content filtering."
                    ),
                ],
                is_grounded=True,
            )

        # 3. Cookie Flags
        elif "cookie" in lower_title:
            return AIIntelligenceReport(
                provider_name=self.name,
                model_version="mock-v1.0",
                generated_at=datetime.now(timezone.utc),
                observation=f"Expose observed cookies issued by '{target_host}' without essential protective attributes (Secure, HttpOnly, SameSite).",
                evidence_summary=evidence.get("summary", "Set-Cookie headers observed without Secure, HttpOnly, or SameSite attributes."),
                security_meaning=(
                    f"The finding '{title}' identifies cookies issued without essential defense attributes "
                    "(such as Secure, HttpOnly, or appropriate SameSite policies)."
                ),
                confidence_explanation="Confidence is CONFIRMED through literal inspection of Set-Cookie header directives returned during initial handshake.",
                impact=(
                    f"For {target_host}, cookies missing 'Secure' risk transmission over plaintext connections; cookies missing "
                    "'HttpOnly' are readable by any client-side JavaScript (including XSS payloads); cookies missing 'SameSite' "
                    "are vulnerable to Cross-Site Request Forgery (CSRF) across origins."
                ),
                real_world_context=(
                    "OWASP ASVS 5.0 Section V3.4 mandates all state-management and session tokens to explicitly specify "
                    "'Secure; HttpOnly; SameSite=Lax' (or 'SameSite=Strict') to isolate cookies to trusted origins. Historically, major platforms suffered session hijacking via script-readable cookies."
                ),
                recommendation="Set 'Secure', 'HttpOnly', and 'SameSite=Lax' (or 'SameSite=Strict') on all Set-Cookie directives generated by the application.",
                verification_method=f"Run 'curl -s -c - https://{target_host}' and verify that all cookies include the Secure, HttpOnly, and SameSite attributes.",
                explanation=(
                    f"The finding '{title}' identifies cookies issued without essential defense attributes "
                    "(such as Secure, HttpOnly, or appropriate SameSite policies)."
                ),
                contextual_impact=(
                    f"For {target_host}, cookies missing 'Secure' risk transmission over plaintext connections; cookies missing "
                    "'HttpOnly' are readable by any client-side JavaScript (including XSS payloads); cookies missing 'SameSite' "
                    "are vulnerable to Cross-Site Request Forgery (CSRF) across origins."
                ),
                research_summary=(
                    "OWASP ASVS 5.0 Section V3.4 mandates all state-management and session tokens to explicitly specify "
                    "'Secure; HttpOnly; SameSite=Lax' (or 'SameSite=Strict') to isolate cookies to trusted origins."
                ),
                comparative_examples=(
                    "Historically, major webmail and banking platforms suffered session hijacking attacks where attackers "
                    "used DOM-accessible document.cookie payloads to exfiltrate active session tokens to external drop servers."
                ),
                developer_recommendations=[
                    "Set the 'Secure' attribute on all Set-Cookie headers so cookies are exclusively transmitted over TLS.",
                    "Set 'HttpOnly' on all authentication and session identifiers to block DOM access.",
                    "Set 'SameSite=Lax' or 'SameSite=Strict' to guard against cross-site forged transactions."
                ],
                priority_rationale=(
                    "Session security directly dictates user account isolation. Fixing cookie flags is trivial to deploy and immediately "
                    "neutralizes session theft vectors."
                ),
                source_citations=[
                    SourceCitation(
                        title="OWASP Session Management Cheat Sheet",
                        url="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                        source_type=SourceType.OWASP,
                        snippet="Technical controls for session cookies: Secure, HttpOnly, SameSite, and domain scope isolation."
                    ),
                    SourceCitation(
                        title="RFC 6265bis: Cookies: HTTP State Management Mechanism",
                        url="https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis",
                        source_type=SourceType.RFC_STANDARD,
                        snippet="Modern updates to HTTP state management including SameSite and cookie prefix semantics."
                    ),
                ],
                is_grounded=True,
            )

        # 4. Sensitive Files / Environment / Git Exposure
        elif ".env" in lower_title or ".git" in lower_title or "sensitive file" in lower_title:
            return AIIntelligenceReport(
                provider_name=self.name,
                model_version="mock-v1.0",
                generated_at=datetime.now(timezone.utc),
                observation=f"Expose observed that sensitive configuration or version control metadata is directly accessible over the public Internet at '{target_host}'.",
                evidence_summary=evidence.get("summary", "Direct HTTP request to sensitive file returned HTTP 200 OK with sensitive contents."),
                security_meaning=(
                    f"The finding '{title}' reveals that a sensitive configuration file or version control metadata "
                    "is directly accessible over the public Internet, bypassing access controls."
                ),
                confidence_explanation="Confidence is CONFIRMED based on direct HTTP response status 200 and signature matching on returned content.",
                impact=(
                    f"On {target_host}, public access to configuration files or git metadata routinely exposes database credentials, "
                    "API secret keys, private encryption salts, and full backend source code repositories."
                ),
                real_world_context=(
                    "CISA Alert AA21-209A lists exposed configuration files and dotfiles as major initial access vectors in automated credential harvesting campaigns that lead to cloud takeovers. "
                    "OWASP Top 10:2025 classifies this under Security Misconfiguration (A05)."
                ),
                recommendation="Immediately block web access to all dotfiles (e.g. deny all matching '/\\.' in web server configuration), rotate all credentials contained within exposed files, and remove them from webroot.",
                verification_method=f"Run 'curl -s -o /dev/null -w \"%{{http_code}}\" https://{target_host}/.env' and verify it returns HTTP 403 or 404.",
                explanation=(
                    f"The finding '{title}' reveals that a sensitive configuration file or version control metadata "
                    "is directly accessible over the public Internet, bypassing access controls."
                ),
                contextual_impact=(
                    f"On {target_host}, public access to configuration files or git metadata routinely exposes database credentials, "
                    "API secret keys, private encryption salts, and full backend source code repositories."
                ),
                research_summary=(
                    "CISA and OWASP classify public exposure of secret keys as a critical security incident. "
                    "Automated threat actors constantly scan the IPv4 address space for /.env and /.git/config to execute automated account takeovers."
                ),
                comparative_examples=(
                    "Thousands of AWS, SendGrid, and Stripe credentials have been harvested in mass automated campaigns "
                    "scanning for public /.env files, leading to full cloud tenant takeovers and data ransomware."
                ),
                developer_recommendations=[
                    "Immediately block web access to all dotfiles (e.g. 'location ~ /\\.' deny all in Nginx).",
                    "Immediately rotate any secrets, database passwords, or API keys contained within the exposed files.",
                    "Ensure build and deployment pipelines never copy .env or .git files into production document roots."
                ],
                priority_rationale=(
                    "This is a CRITICAL finding that must be addressed immediately before any other remediation, "
                    "as attackers can use exposed credentials to fully bypass all network and application defenses."
                ),
                source_citations=[
                    SourceCitation(
                        title="CISA Alert AA21-209A: Top Routinely Exploited Software Vulnerabilities",
                        url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-209a",
                        source_type=SourceType.CISA,
                        snippet="Advisory highlighting public misconfigurations and exposed credential files as initial access vectors."
                    ),
                    SourceCitation(
                        title="OWASP Top 10:2025 - A05 Security Misconfiguration",
                        url="https://owasp.org/Top10/",
                        source_type=SourceType.OWASP,
                        snippet="Catalogues unintentional exposure of configuration files, backups, and administrative tools."
                    ),
                ],
                is_grounded=True,
            )

        # 5. Generic / Default Security Finding
        return AIIntelligenceReport(
            provider_name=self.name,
            model_version="mock-v1.0",
            generated_at=datetime.now(timezone.utc),
            observation=f"Expose observed an empirical finding '{title}' under category {cat_clean} with severity {sev_clean} on '{target_host}'.",
            evidence_summary=evidence.get("summary", "Technical protocol observation captured during automated probe."),
            security_meaning=(
                f"The finding '{title}' reflects an observed weakness classified under {cat_clean} (Severity: {sev_clean}). "
                f"Empirical evidence gathered: {evidence.get('summary', 'Protocol evidence captured')}."
            ),
            confidence_explanation=f"Confidence is assessed as {conf_clean.upper()} based on direct empirical wire observation.",
            impact=(
                f"For {target_host}, unresolved weaknesses in {cat_clean} can be chained by adversaries to degrade target security, "
                "facilitate reconnaissance, or bypass defense-in-depth layers."
            ),
            real_world_context=(
                f"Authoritative guidance from OWASP ASVS 5.0 and CWE ({cwe_id or 'General'}) emphasizes that proactive hardening "
                "of edge infrastructure eliminates automated attack surfaces before targeted exploitation occurs. CISA incident retrospectives demonstrate compromises commonly start with edge reconnaissance."
            ),
            recommendation="Review the specific configuration directive identified in the finding remediation guidance and apply recommended security controls.",
            verification_method=f"Run 'curl -s -I https://{target_host}' or the relevant protocol probe command against '{target_host}' to confirm resolution.",
            explanation=(
                f"The finding '{title}' reflects an observed weakness classified under {cat_clean} (Severity: {sev_clean}). "
                f"Empirical evidence gathered: {evidence.get('summary', 'Protocol evidence captured')}."
            ),
            contextual_impact=(
                f"For {target_host}, unresolved weaknesses in {cat_clean} can be chained by adversaries to degrade target security, "
                "facilitate reconnaissance, or bypass defense-in-depth layers."
            ),
            research_summary=(
                f"Authoritative guidance from OWASP ASVS 5.0 and CWE ({cwe_id or 'General'}) emphasizes that proactive hardening "
                "of edge infrastructure eliminates automated attack surfaces before targeted exploitation occurs."
            ),
            comparative_examples=(
                "Real-world incident retrospectives by CISA demonstrate that sophisticated compromises typically commence "
                "with opportunistic reconnaissance of unhardened edge parameters."
            ),
            developer_recommendations=[
                "Review the specific configuration directive identified in the finding remediation guidance.",
                "Validate configuration against OWASP Secure Headers and ASVS 5.0 verification guidelines.",
                "Run the provided independent verification command to confirm remediation."
            ],
            priority_rationale=(
                f"Prioritized according to severity ({severity}) and exploitability context within the overall target attack surface."
            ),
            source_citations=[
                SourceCitation(
                    title="OWASP Application Security Verification Standard (ASVS) 5.0",
                    url="https://owasp.org/www-project-application-security-verification-standard/",
                    source_type=SourceType.OWASP,
                    snippet="Stable 5.0.0 framework for verifying web application technical security controls."
                ),
                SourceCitation(
                    title="NIST Special Publication 800-53: Security and Privacy Controls",
                    url="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
                    source_type=SourceType.NIST,
                    snippet="Security control catalog for federal information systems and organizations."
                ),
            ],
            is_grounded=True,
        )

    async def prioritize_findings(
        self,
        target_host: str,
        findings_data: List[Dict[str, Any]],
        tech_context: Optional[Dict[str, Any]] = None,
    ) -> AIPrioritizationReport:
        items: List[FindingPriorityItem] = []
        severity_rank = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}

        # Sort findings by severity
        sorted_findings = sorted(
            findings_data,
            key=lambda f: (severity_rank.get(f.get("severity", "LOW"), 99), f.get("title", ""))
        )

        roadmap = []
        for idx, f in enumerate(sorted_findings, start=1):
            sev = f.get("severity", "LOW")
            if sev == "CRITICAL":
                urgency = "IMMEDIATE_ACTION"
                just = "Direct compromise vector or secret leakage. Remediate within hours."
            elif sev == "HIGH":
                urgency = "HIGH_PRIORITY"
                just = "Severe security exposure or cryptographic failure. Remediate in next deployment cycle."
            elif sev == "MEDIUM":
                urgency = "MEDIUM_PRIORITY"
                just = "Defense-in-depth protection missing. Schedule for upcoming sprint."
            else:
                urgency = "DEFENSIVE_HARDENING"
                just = "Hardening and best-practice alignment. Address during routine maintenance."

            items.append(
                FindingPriorityItem(
                    finding_id=f.get("id", f"EXP-{idx}"),
                    title=f.get("title", "Finding"),
                    priority_rank=idx,
                    urgency_tier=urgency,
                    justification=just,
                )
            )

        if any(i.urgency_tier == "IMMEDIATE_ACTION" for i in items):
            exec_summary = (
                f"Security scan for {target_host} identified CRITICAL exposure items that require immediate operator intervention. "
                "High-priority transport and secret leakages must be quarantined prior to standard hardening."
            )
            roadmap.append("Phase 1: Quarantining critical secrets and exposed administrative endpoints.")
            roadmap.append("Phase 2: Transport security and Strict-Transport-Security (HSTS) enforcement.")
            roadmap.append("Phase 3: Browser policy deployment (CSP, Clickjacking, Cookie protection).")
        else:
            exec_summary = (
                f"Security posture for {target_host} exhibits standard enterprise controls with recommendations "
                "focused on defense-in-depth hardening and cryptographic modernization."
            )
            roadmap.append("Phase 1: Enforce TLS 1.3 and HSTS across all subdomains.")
            roadmap.append("Phase 2: Harden HTTP response headers (CSP, Referrer-Policy, Permissions-Policy).")
            roadmap.append("Phase 3: Audit client-side scripts and integrate Subresource Integrity (SRI).")

        return AIPrioritizationReport(
            target=target_host,
            prioritized_items=items,
            executive_summary=exec_summary,
            remediation_roadmap=roadmap,
        )
