"""HTTP transport and security headers probe for Expose.

Implements the comprehensive 11-test Mozilla HTTP Observatory evaluation suite:
1. Content Security Policy (CSP)
2. HTTP Strict Transport Security (HSTS)
3. Clickjacking Protection (X-Frame-Options / frame-ancestors)
4. MIME Sniffing Prevention (X-Content-Type-Options)
5. Referrer Policy
6. Permissions Policy
7. HTTP-to-HTTPS Redirection
8. Cross-Origin Resource Sharing (CORS)
9. Subresource Integrity (SRI)
10. Cookie Security Posture
11. Server & Technology Version Disclosure
"""

import re
from typing import Any, Dict, List, Optional, Tuple
import httpx

from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    HeaderTestResult,
    HeaderTestStatus,
    ObservationStatus,
    Severity,
    TargetScope,
)
from .base import BaseProbe


class HTTPHeadersProbe(BaseProbe):
    """Evaluates HTTP/HTTPS transport security, redirection enforcement, and Mozilla Observatory test matrix."""

    def __init__(self):
        super().__init__()
        self.last_matrix: List[HeaderTestResult] = []

    @property
    def name(self) -> str:
        return "http_headers"

    @property
    def category(self) -> Category:
        return Category.TRANSPORT_SECURITY

    @property
    def description(self) -> str:
        return "Evaluates Mozilla HTTP Observatory security headers, CSP, HSTS, redirection, and transport posture."

    async def execute(self, target: TargetScope) -> List[Finding]:
        findings: List[Finding] = []
        matrix: List[HeaderTestResult] = []

        headers_to_send = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Expose-Security-Intelligence/0.2.0 (Mozilla-Observatory-Engine)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        # 1. Plain HTTP to HTTPS Redirection Check
        redirect_test_result, redirect_finding = await self._test_redirection(target, headers_to_send)
        matrix.append(redirect_test_result)
        if redirect_finding:
            findings.append(redirect_finding)

        # 2. Query primary endpoint
        direct_resp = None
        final_resp = None
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8.0) as client:
                direct_resp = await client.get(target.normalized_url, headers=headers_to_send)
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
                final_resp = await client.get(target.normalized_url, headers=headers_to_send)
        except Exception as e:
            evidence = Evidence(
                type=EvidenceType.HTTP_EXCHANGE,
                summary=f"Failed to connect to HTTP endpoint {target.normalized_url}: {str(e)}",
                request={"method": "GET", "url": target.normalized_url},
                raw_data={"error": str(e)}
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="HTTP Service Unreachable",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description=f"HTTP connection to '{target.normalized_url}' failed: {str(e)}",
                    impact_explanation="The web service appears down or blocking scanner requests.",
                    remediation="Verify web server availability and reverse proxy configurations.",
                    verification_command=f"curl -sI {target.normalized_url}",
                    evidence=evidence,
                    category=Category.TRANSPORT_SECURITY
                )
            )
            self.last_matrix = matrix
            return findings

        resp_headers = final_resp.headers
        raw_cookies = self._extract_set_cookies(final_resp) or self._extract_set_cookies(direct_resp)
        resp_text = getattr(final_resp, "text", "") or ""

        # Error documents, authentication gates, and bot challenges are not a
        # reliable representation of the application page. In particular,
        # scoring absent headers from a 403 challenge produces false findings
        # against sites protected by an edge service.
        if final_resp.status_code >= 400:
            self.last_matrix = matrix
            return findings

        # 3. Content Security Policy (CSP)
        csp_result, csp_findings = self._test_csp(target, resp_headers, direct_resp)
        matrix.append(csp_result)
        findings.extend(csp_findings)

        # 4. HTTP Strict Transport Security (HSTS)
        hsts_result, hsts_findings = self._test_hsts(target, resp_headers, direct_resp)
        matrix.append(hsts_result)
        findings.extend(hsts_findings)

        # 5. Clickjacking Protection (X-Frame-Options / frame-ancestors)
        xfo_result, xfo_findings = self._test_clickjacking(target, resp_headers)
        matrix.append(xfo_result)
        findings.extend(xfo_findings)

        # 6. MIME Sniffing Prevention (X-Content-Type-Options)
        xcto_result, xcto_findings = self._test_xcto(target, resp_headers)
        matrix.append(xcto_result)
        findings.extend(xcto_findings)

        # 7. Referrer Policy
        ref_result, ref_findings = self._test_referrer_policy(target, resp_headers)
        matrix.append(ref_result)
        findings.extend(ref_findings)

        # 8. Permissions Policy
        perm_result, perm_findings = self._test_permissions_policy(target, resp_headers)
        matrix.append(perm_result)
        findings.extend(perm_findings)

        # 9. Cross-Origin Resource Sharing (CORS)
        cors_result, cors_findings = await self._test_cors(target, headers_to_send)
        matrix.append(cors_result)
        findings.extend(cors_findings)

        # 10. Subresource Integrity (SRI)
        sri_result, sri_findings = self._test_sri(target, resp_text)
        matrix.append(sri_result)
        findings.extend(sri_findings)

        # 11. Cookie Security Posture
        cookie_result, cookie_findings = self._test_cookies(target, raw_cookies)
        matrix.append(cookie_result)
        findings.extend(cookie_findings)

        # 12. Server & Technology Version Disclosure
        server_result, server_findings = self._test_server_disclosure(target, resp_headers)
        matrix.append(server_result)
        findings.extend(server_findings)

        # Mixed Content Check
        mixed_findings = self._test_mixed_content(target, resp_text)
        findings.extend(mixed_findings)

        # OPTIONS Probe Check
        options_findings = await self._test_options_methods(target, headers_to_send)
        findings.extend(options_findings)

        self.last_matrix = matrix
        return findings

    def _extract_set_cookies(self, resp: Any) -> List[str]:
        if resp is None or not hasattr(resp, "headers"):
            return []
        headers = resp.headers
        if hasattr(headers, "get_list"):
            return headers.get_list("set-cookie") or []
        if isinstance(headers, dict):
            c = headers.get("set-cookie") or headers.get("Set-Cookie")
            if isinstance(c, list):
                return c
            if isinstance(c, str):
                return [c]
        return []

    async def _test_redirection(self, target: TargetScope, headers_to_send: dict) -> Tuple[HeaderTestResult, Optional[Finding]]:
        if target.scheme != "https":
            return HeaderTestResult(
                id="redirection",
                name="HTTP-to-HTTPS Redirection",
                header_name="Location",
                status=HeaderTestStatus.INFO,
                score_modifier=0,
                observed_value="Plaintext HTTP Target (HTTPS not requested)",
                expected_value="301 Permanent Redirect to HTTPS",
                description="Plaintext HTTP requests must automatically redirect to encrypted HTTPS.",
                advice="Enable HTTPS and enforce HTTP-to-HTTPS 301 redirection.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
            ), None

        http_target = f"http://{target.host}"
        if target.port != 443 and target.port != 80:
            http_target += f":{target.port}"

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=6.0) as client:
                http_resp = await client.get(http_target, headers=headers_to_send)
                loc = http_resp.headers.get("Location", "")
                is_redirect_to_https = (
                    http_resp.status_code in (301, 302, 307, 308) and
                    loc.lower().startswith("https://")
                )

                if is_redirect_to_https:
                    finding = self.create_finding(
                        target=target,
                        title="HTTP to HTTPS Redirection Enforced",
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.OBSERVED,
                        description=f"Plaintext requests to {http_target} automatically redirect to encrypted HTTPS ({loc}).",
                        impact_explanation="Prevents accidental cleartext transmission of credentials and session tokens.",
                        remediation="Maintain redirection rules across all web server hostnames.",
                        verification_command=f"curl -sI {http_target} | grep -Ei 'HTTP/|Location:'",
                        evidence=Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary=f"HTTP correctly redirects to HTTPS: {loc}",
                            response={"status_code": http_resp.status_code, "location": loc}
                        ),
                        category=Category.TRANSPORT_SECURITY
                    )
                    return HeaderTestResult(
                        id="redirection",
                        name="HTTP-to-HTTPS Redirection",
                        header_name="Location",
                        status=HeaderTestStatus.PASS,
                        score_modifier=0,
                        observed_value=f"{http_resp.status_code} -> {loc}",
                        expected_value="301/308 Redirect to https://",
                        description="Plaintext HTTP requests automatically redirect to encrypted HTTPS.",
                        advice="Redirection is properly enforced.",
                        doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
                    ), finding
                else:
                    finding = self.create_finding(
                        target=target,
                        title="Missing HTTP to HTTPS Redirection Enforcement",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description=f"Requests made to plaintext '{http_target}' returned HTTP {http_resp.status_code} without redirecting to HTTPS.",
                        impact_explanation="Unencrypted plaintext communication allows eavesdropping and session hijacking on local networks.",
                        remediation="Configure web server to issue a 301 Permanent Redirect for all HTTP traffic to HTTPS.",
                        verification_command=f"curl -sI {http_target} | grep -Ei 'HTTP/|Location:'",
                        evidence=Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary=f"HTTP endpoint ({http_target}) returned status {http_resp.status_code} without redirecting to HTTPS.",
                            request={"method": "GET", "url": http_target},
                            response={"status_code": http_resp.status_code, "headers": dict(http_resp.headers), "location": loc}
                        ),
                        category=Category.TRANSPORT_SECURITY,
                        cwe_id="CWE-319"
                    )
                    return HeaderTestResult(
                        id="redirection",
                        name="HTTP-to-HTTPS Redirection",
                        header_name="Location",
                        status=HeaderTestStatus.FAIL,
                        score_modifier=-20,
                        observed_value=f"HTTP {http_resp.status_code}" + (f" -> {loc}" if loc else " (No redirect)"),
                        expected_value="301 Permanent Redirect to https://",
                        description="Initial HTTP requests must automatically redirect to HTTPS before any other processing.",
                        advice="Configure a 301/308 permanent redirect from http:// to https:// on port 80.",
                        doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
                    ), finding
        except Exception as e:
            return HeaderTestResult(
                id="redirection",
                name="HTTP-to-HTTPS Redirection",
                header_name="Location",
                status=HeaderTestStatus.WARN,
                score_modifier=0,
                observed_value=f"Port 80 probe error: {str(e)[:40]}",
                expected_value="301 Redirect to https://",
                description="Plaintext HTTP requests must automatically redirect to encrypted HTTPS.",
                advice="Ensure port 80 is listening and issuing 301 redirects to HTTPS.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
            ), None

    def _test_csp(self, target: TargetScope, headers: httpx.Headers, direct_resp: Optional[httpx.Response]) -> Tuple[HeaderTestResult, List[Finding]]:
        csp = headers.get("content-security-policy") or (direct_resp.headers.get("content-security-policy") if direct_resp else None)
        findings: List[Finding] = []

        multi_framework_remediation = (
            "Deploy a Content-Security-Policy header restricting allowed origins for scripts, styles, objects, and framing.\n\n"
            "Framework Configurations:\n"
            "• Nginx (/etc/nginx/conf.d/default.conf):\n"
            "  add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; upgrade-insecure-requests;\" always;\n\n"
            "• Apache (.htaccess / httpd.conf):\n"
            "  Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; upgrade-insecure-requests;\"\n\n"
            "• Caddy (Caddyfile):\n"
            "  header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; upgrade-insecure-requests;\"\n\n"
            "• Next.js (next.config.js):\n"
            "  async headers() {\n"
            "    return [{\n"
            "      source: '/(.*)',\n"
            "      headers: [{\n"
            "        key: 'Content-Security-Policy',\n"
            "        value: \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self';\"\n"
            "      }]\n"
            "    }];\n"
            "  }\n\n"
            "• Cloudflare Transform Rules:\n"
            "  Modify Response Header -> Set static 'Content-Security-Policy' = \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\""
        )

        if not csp:
            finding = self.create_finding(
                target=target,
                title="Missing Content-Security-Policy (CSP) Header",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description="Content-Security-Policy (CSP) is not configured.",
                impact_explanation="Leaves the application with no defense-in-depth against Cross-Site Scripting (XSS), data exfiltration, or rogue third-party scripts.",
                remediation=multi_framework_remediation,
                verification_command=f"curl -sI {target.normalized_url} | grep -i content-security-policy",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary=f"No Content-Security-Policy header returned by {target.normalized_url}",
                    response={"headers": dict(headers)}
                ),
                category=Category.BROWSER_SECURITY,
                cwe_id="CWE-1021"
            )
            findings.append(finding)
            return HeaderTestResult(
                id="content-security-policy",
                name="Content Security Policy",
                header_name="Content-Security-Policy",
                status=HeaderTestStatus.FAIL,
                score_modifier=-25,
                observed_value=None,
                expected_value="default-src 'self'; script-src 'self'; base-uri 'self'; ...",
                description="CSP restricts resource execution and provides defense-in-depth against Cross-Site Scripting (XSS).",
                advice="Implement a robust Content-Security-Policy restricting script, style, and frame execution origins.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            ), findings

        csp_lower = csp.lower()
        has_unsafe_inline = "'unsafe-inline'" in csp_lower and ("nonce-" not in csp_lower and "sha256-" not in csp_lower and "sha384-" not in csp_lower and "sha512-" not in csp_lower)
        has_unsafe_eval = "'unsafe-eval'" in csp_lower
        
        # Directive breakdown
        directives = [d.strip() for d in csp.split(";") if d.strip()]
        directive_map: Dict[str, str] = {}
        for d in directives:
            parts = d.split(None, 1)
            if parts:
                directive_map[parts[0].lower()] = parts[1] if len(parts) > 1 else ""

        has_wildcard_script = False
        if "script-src" in directive_map:
            script_sources = directive_map["script-src"].split()
            if "*" in script_sources or "https:*" in script_sources or "http:*" in script_sources:
                has_wildcard_script = True
        elif "default-src" in directive_map:
            default_sources = directive_map["default-src"].split()
            if "*" in default_sources:
                has_wildcard_script = True

        has_base_uri = "base-uri" in directive_map
        has_form_action = "form-action" in directive_map
        has_object_none = "object-src" in directive_map and "'none'" in directive_map["object-src"].lower()

        # Check 1: Wildcard Script Execution
        if has_wildcard_script:
            finding = self.create_finding(
                target=target,
                title="Insecure Content-Security-Policy: Wildcard '*' in Script Sources",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description="The CSP allows wildcards ('*') in script-src or default-src, permitting script loading from any domain.",
                impact_explanation="Wildcard script sources completely bypass CSP protections against malicious third-party script injection.",
                remediation="Replace wildcard '*' with specific trusted origins or use nonce-based script whitelisting.",
                verification_command=f"curl -sI {target.normalized_url} | grep -i content-security-policy",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary=f"CSP contains wildcard script source: {csp}",
                    response={"csp": csp}
                ),
                category=Category.BROWSER_SECURITY,
                cwe_id="CWE-79"
            )
            findings.append(finding)

        # Check 2: Unsafe-Inline
        if has_unsafe_inline:
            finding = self.create_finding(
                target=target,
                title="Insecure Content-Security-Policy: 'unsafe-inline' Permitted",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description="The CSP includes 'unsafe-inline' in script-src/default-src without cryptographic nonces or hashes.",
                impact_explanation="Significantly weakens XSS mitigations by allowing arbitrary inline script execution.",
                remediation="Refactor inline scripts into external files, or employ cryptographic nonces ('nonce-...') or hashes ('sha256-...').",
                verification_command=f"curl -sI {target.normalized_url} | grep -i content-security-policy",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary=f"CSP contains 'unsafe-inline' without nonce/hash: {csp}",
                    response={"csp": csp}
                ),
                category=Category.BROWSER_SECURITY,
                cwe_id="CWE-79"
            )
            findings.append(finding)

        # Check 3: Unsafe-Eval
        if has_unsafe_eval:
            finding = self.create_finding(
                target=target,
                title="Insecure Content-Security-Policy: 'unsafe-eval' Permitted",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description="The CSP includes 'unsafe-eval', allowing dynamic code evaluation via eval() and Function constructor.",
                impact_explanation="Enables DOM-based script injection vectors if user data reaches dynamic evaluators.",
                remediation="Refactor code to eliminate eval() and remove 'unsafe-eval' from CSP.",
                verification_command=f"curl -sI {target.normalized_url} | grep -i content-security-policy",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary=f"CSP contains 'unsafe-eval': {csp}",
                    response={"csp": csp}
                ),
                category=Category.BROWSER_SECURITY,
                cwe_id="CWE-95"
            )
            findings.append(finding)

        # Check 4: Missing base-uri
        if not has_base_uri:
            finding = self.create_finding(
                target=target,
                title="Weak Content-Security-Policy: Missing 'base-uri' Directive",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description="The CSP does not define a 'base-uri' directive.",
                impact_explanation="Adversaries who inject HTML tags can inject a <base href=\"https://attacker.com\"> tag to redirect all relative script and asset requests to an external server.",
                remediation="Add \"base-uri 'self';\" (or \"base-uri 'none';\") to your Content-Security-Policy header.",
                verification_command=f"curl -sI {target.normalized_url} | grep -i content-security-policy",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary="CSP does not declare 'base-uri'.",
                    response={"csp": csp}
                ),
                category=Category.BROWSER_SECURITY,
                cwe_id="CWE-1021"
            )
            findings.append(finding)

        # Check 5: Missing form-action
        if not has_form_action:
            finding = self.create_finding(
                target=target,
                title="Weak Content-Security-Policy: Missing 'form-action' Directive",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description="The CSP does not define a 'form-action' directive.",
                impact_explanation="Forms on the site could be targeted by injection attacks to submit sensitive credentials or tokens to arbitrary cross-origin endpoints.",
                remediation="Add \"form-action 'self';\" to your Content-Security-Policy header.",
                verification_command=f"curl -sI {target.normalized_url} | grep -i content-security-policy",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary="CSP does not declare 'form-action'.",
                    response={"csp": csp}
                ),
                category=Category.BROWSER_SECURITY,
                cwe_id="CWE-1021"
            )
            findings.append(finding)

        # Check 6: Object-src not set to none
        if not has_object_none and "default-src 'none'" not in csp_lower:
            finding = self.create_finding(
                target=target,
                title="Weak Content-Security-Policy: Missing 'object-src 'none'' Directive",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description="The CSP does not set 'object-src 'none'', leaving legacy browser plugins unconstrained.",
                impact_explanation="Allows embedding of legacy plugin objects (Flash, Java Applets) if supported by older browsers or extensions.",
                remediation="Add \"object-src 'none';\" to your Content-Security-Policy header.",
                verification_command=f"curl -sI {target.normalized_url} | grep -i content-security-policy",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary="CSP lacks 'object-src 'none''.",
                    response={"csp": csp}
                ),
                category=Category.BROWSER_SECURITY,
                cwe_id="CWE-1021"
            )
            findings.append(finding)

        if has_wildcard_script or has_unsafe_inline or has_unsafe_eval:
            return HeaderTestResult(
                id="content-security-policy",
                name="Content Security Policy",
                header_name="Content-Security-Policy",
                status=HeaderTestStatus.WARN,
                score_modifier=-20 if (has_wildcard_script or has_unsafe_inline) else -10,
                observed_value=csp[:120] + ("..." if len(csp) > 120 else ""),
                expected_value="default-src 'self' (without 'unsafe-inline' or '*')",
                description="CSP is active but contains permissive directives ('unsafe-inline', 'unsafe-eval', or wildcard origins).",
                advice="Harden CSP by removing 'unsafe-inline' and wildcard sources, utilizing nonces or hashes.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            ), findings

        finding = self.create_finding(
            target=target,
            title="Content-Security-Policy (CSP) Configured",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            status=ObservationStatus.OBSERVED,
            description="Application publishes a Content-Security-Policy restricting resource execution.",
            impact_explanation="Provides browser-enforced boundaries limiting Cross-Site Scripting impact.",
            remediation="Review CSP reporting endpoints periodically.",
            verification_command=f"curl -sI {target.normalized_url} | grep -i content-security-policy",
            evidence=Evidence(
                type=EvidenceType.HTTP_EXCHANGE,
                summary="Content-Security-Policy header is active and robust.",
                response={"csp": csp[:200]}
            ),
            category=Category.BROWSER_SECURITY
        )
        findings.append(finding)
        return HeaderTestResult(
            id="content-security-policy",
            name="Content Security Policy",
            header_name="Content-Security-Policy",
            status=HeaderTestStatus.PASS,
            score_modifier=0,
            observed_value=csp[:120] + ("..." if len(csp) > 120 else ""),
            expected_value="default-src 'self'; script-src 'self' ...",
            description="Robust CSP restricts script execution without dangerous wildcards or unpinned inline execution.",
            advice="CSP is well-configured.",
            doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
        ), findings

    def _test_hsts(self, target: TargetScope, headers: httpx.Headers, direct_resp: Optional[httpx.Response]) -> Tuple[HeaderTestResult, List[Finding]]:
        if target.scheme != "https":
            return HeaderTestResult(
                id="strict-transport-security",
                name="HTTP Strict Transport Security",
                header_name="Strict-Transport-Security",
                status=HeaderTestStatus.INFO,
                score_modifier=0,
                observed_value="N/A (HTTP target)",
                expected_value="max-age=31536000; includeSubDomains; preload",
                description="HSTS forces browsers to communicate strictly over encrypted HTTPS.",
                advice="Enable HTTPS to activate HSTS.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ), []

        hsts = headers.get("strict-transport-security") or (direct_resp.headers.get("strict-transport-security") if direct_resp else None)
        findings: List[Finding] = []

        if not hsts:
            finding = self.create_finding(
                target=target,
                title="Missing HTTP Strict Transport Security (HSTS)",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description="HTTP Strict Transport Security (HSTS) is not enabled.",
                impact_explanation="Browsers may attempt unencrypted connections on first visits, leaving visitors vulnerable to SSL-stripping MITM attacks.",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to HTTPS responses.",
                verification_command=f"curl -sI {target.normalized_url} | grep -i strict-transport-security",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary=f"No Strict-Transport-Security header present in response from {target.normalized_url}",
                    response={"headers": dict(headers)}
                ),
                category=Category.TRANSPORT_SECURITY,
                cwe_id="CWE-319"
            )
            findings.append(finding)
            return HeaderTestResult(
                id="strict-transport-security",
                name="HTTP Strict Transport Security",
                header_name="Strict-Transport-Security",
                status=HeaderTestStatus.FAIL,
                score_modifier=-20,
                observed_value=None,
                expected_value="max-age=31536000; includeSubDomains; preload",
                description="HSTS prevents man-in-the-middle SSL-stripping attacks by forcing browsers to use HTTPS.",
                advice="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ), findings

        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        has_subdomains = "includesubdomains" in hsts.lower()
        has_preload = "preload" in hsts.lower()

        if max_age < 15768000:  # Less than 6 months (182.5 days)
            finding = self.create_finding(
                target=target,
                title="Low HSTS max-age Duration",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description=f"The HSTS max-age is set to {max_age} seconds (minimum recommended: 15,768,000s / 6 months; ideal: 31,536,000s / 1 year).",
                impact_explanation="A short HSTS window increases susceptibility to downgrade attacks if a user does not revisit frequently.",
                remediation="Increase HSTS max-age to at least 31536000 seconds (1 year).",
                verification_command=f"curl -sI {target.normalized_url} | grep -i strict-transport-security",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary=f"HSTS max-age is {max_age} seconds: {hsts}",
                    response={"hsts_header": hsts}
                ),
                category=Category.TRANSPORT_SECURITY,
                cwe_id="CWE-319"
            )
            findings.append(finding)
            return HeaderTestResult(
                id="strict-transport-security",
                name="HTTP Strict Transport Security",
                header_name="Strict-Transport-Security",
                status=HeaderTestStatus.WARN,
                score_modifier=-10,
                observed_value=hsts,
                expected_value="max-age=31536000; includeSubDomains; preload",
                description=f"HSTS max-age is only {max_age} seconds (under standard 6-month threshold).",
                advice="Increase max-age to 31536000 (1 year) and includeSubDomains.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ), findings

        if max_age >= 31536000 and has_subdomains and has_preload:
            finding = self.create_finding(
                target=target,
                title="HSTS Preload-Ready Configuration",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.OBSERVED,
                description=f"HSTS is configured with max-age={max_age}, includeSubDomains, and preload.",
                impact_explanation="Eligible for browser HSTS preload list inclusion, ensuring hard-coded HTTPS encryption out of the box.",
                remediation="Submit domain to hstspreload.org if not already listed.",
                verification_command=f"curl -sI {target.normalized_url} | grep -i strict-transport-security",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary=f"Preload-ready HSTS: {hsts}",
                    response={"hsts": hsts}
                ),
                category=Category.TRANSPORT_SECURITY
            )
            findings.append(finding)
            return HeaderTestResult(
                id="strict-transport-security",
                name="HTTP Strict Transport Security",
                header_name="Strict-Transport-Security",
                status=HeaderTestStatus.PASS,
                score_modifier=5,  # Mozilla +5 bonus
                observed_value=hsts,
                expected_value="max-age=31536000; includeSubDomains; preload",
                description="Strong HSTS configuration meeting all browser preloading standards (max-age >= 1yr, includeSubDomains, preload).",
                advice="Optimal HSTS configuration with preloading enabled (+5 bonus).",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ), findings

        finding = self.create_finding(
            target=target,
            title="HTTP Strict Transport Security (HSTS) Active",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            status=ObservationStatus.OBSERVED,
            description=f"HSTS is configured with max-age={max_age} seconds.",
            impact_explanation="Guarantees browser-enforced HTTPS connections for subsequent visits.",
            remediation="Consider adding '; includeSubDomains; preload' to maximize security.",
            verification_command=f"curl -sI {target.normalized_url} | grep -i strict-transport-security",
            evidence=Evidence(
                type=EvidenceType.HTTP_EXCHANGE,
                summary=f"Strong HSTS header configured: {hsts}",
                response={"hsts": hsts}
            ),
            category=Category.TRANSPORT_SECURITY
        )
        findings.append(finding)
        return HeaderTestResult(
            id="strict-transport-security",
            name="HTTP Strict Transport Security",
            header_name="Strict-Transport-Security",
            status=HeaderTestStatus.PASS,
            score_modifier=0,
            observed_value=hsts,
            expected_value="max-age=31536000; includeSubDomains; preload",
            description=f"HSTS is active with valid duration (max-age={max_age}s).",
            advice="Consider adding 'includeSubDomains; preload' for maximum protection.",
            doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        ), findings

    def _test_clickjacking(self, target: TargetScope, headers: httpx.Headers) -> Tuple[HeaderTestResult, List[Finding]]:
        xfo = headers.get("x-frame-options")
        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()
        findings: List[Finding] = []

        if has_frame_ancestors:
            return HeaderTestResult(
                id="x-frame-options",
                name="Clickjacking Protection",
                header_name="X-Frame-Options / CSP frame-ancestors",
                status=HeaderTestStatus.PASS,
                score_modifier=0,
                observed_value=f"CSP: {csp[:80]}...",
                expected_value="frame-ancestors 'self' / DENY",
                description="Modern frame-ancestors directive in CSP restricts framing.",
                advice="Clickjacking protection is robustly configured via CSP frame-ancestors.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            ), findings

        if xfo:
            xfo_clean = xfo.strip().upper()
            if xfo_clean in ("DENY", "SAMEORIGIN"):
                return HeaderTestResult(
                    id="x-frame-options",
                    name="Clickjacking Protection",
                    header_name="X-Frame-Options",
                    status=HeaderTestStatus.PASS,
                    score_modifier=0,
                    observed_value=xfo,
                    expected_value="DENY or SAMEORIGIN",
                    description="X-Frame-Options prevents malicious sites from framing this application in an iframe.",
                    advice="Clickjacking protection is properly enforced.",
                    doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                ), findings
            elif "ALLOW-FROM" in xfo_clean:
                finding = self.create_finding(
                    target=target,
                    title="Deprecated 'X-Frame-Options: ALLOW-FROM' Directive",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description="X-Frame-Options uses 'ALLOW-FROM', which is obsolete and ignored by modern browsers.",
                    impact_explanation="Modern browsers ignore ALLOW-FROM, leaving the page framing unconstrained.",
                    remediation="Migrate to CSP 'frame-ancestors <origin>' directive.",
                    verification_command=f"curl -sI {target.normalized_url} | grep -i x-frame-options",
                    evidence=Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"Obsolete ALLOW-FROM found: {xfo}",
                        response={"x_frame_options": xfo}
                    ),
                    category=Category.BROWSER_SECURITY,
                    cwe_id="CWE-1021"
                )
                findings.append(finding)
                return HeaderTestResult(
                    id="x-frame-options",
                    name="Clickjacking Protection",
                    header_name="X-Frame-Options",
                    status=HeaderTestStatus.WARN,
                    score_modifier=-10,
                    observed_value=xfo,
                    expected_value="DENY or SAMEORIGIN (or CSP frame-ancestors)",
                    description="ALLOW-FROM is deprecated and unsupported across modern browsers.",
                    advice="Replace 'X-Frame-Options: ALLOW-FROM' with CSP 'frame-ancestors'.",
                    doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                ), findings

        finding = self.create_finding(
            target=target,
            title="Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            status=ObservationStatus.CONFIRMED,
            description="The response lacks both 'X-Frame-Options' and CSP 'frame-ancestors'.",
            impact_explanation="Adversaries can embed your web application in hidden iframes to perform UI redressing / clickjacking attacks against logged-in users.",
            remediation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors 'self''.",
            verification_command=f"curl -sI {target.normalized_url} | grep -Ei 'x-frame-options|frame-ancestors'",
            evidence=Evidence(
                type=EvidenceType.HTTP_EXCHANGE,
                summary="Neither X-Frame-Options nor CSP frame-ancestors headers are present.",
                response={"headers": dict(headers)}
            ),
            category=Category.BROWSER_SECURITY,
            cwe_id="CWE-1021"
        )
        findings.append(finding)
        return HeaderTestResult(
            id="x-frame-options",
            name="Clickjacking Protection",
            header_name="X-Frame-Options",
            status=HeaderTestStatus.FAIL,
            score_modifier=-20,
            observed_value=None,
            expected_value="DENY or SAMEORIGIN (or CSP frame-ancestors 'self')",
            description="Protects users against UI redress / clickjacking attacks inside malicious iframes.",
            advice="Add 'X-Frame-Options: SAMEORIGIN' or CSP 'frame-ancestors 'self'' to all responses.",
            doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        ), findings

    def _test_xcto(self, target: TargetScope, headers: httpx.Headers) -> Tuple[HeaderTestResult, List[Finding]]:
        xcto = headers.get("x-content-type-options")
        findings: List[Finding] = []

        if xcto and xcto.strip().lower() == "nosniff":
            return HeaderTestResult(
                id="x-content-type-options",
                name="MIME Sniffing Prevention",
                header_name="X-Content-Type-Options",
                status=HeaderTestStatus.PASS,
                score_modifier=0,
                observed_value=xcto,
                expected_value="nosniff",
                description="Prevents browsers from MIME-sniffing a response away from declared Content-Type.",
                advice="MIME sniffing protection is properly enabled.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            ), findings

        finding = self.create_finding(
            target=target,
            title="Missing or Ineffective X-Content-Type-Options Header",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            status=ObservationStatus.CONFIRMED,
            description="The 'X-Content-Type-Options: nosniff' header is missing.",
            impact_explanation="Browsers may execute uploaded text or image files as JavaScript/HTML if they guess a different MIME type.",
            remediation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
            verification_command=f"curl -sI {target.normalized_url} | grep -i x-content-type-options",
            evidence=Evidence(
                type=EvidenceType.HTTP_EXCHANGE,
                summary=f"X-Content-Type-Options is '{xcto or 'MISSING'}' (expected 'nosniff').",
                response={"headers": dict(headers)}
            ),
            category=Category.BROWSER_SECURITY,
            cwe_id="CWE-16"
        )
        findings.append(finding)
        return HeaderTestResult(
            id="x-content-type-options",
            name="MIME Sniffing Prevention",
            header_name="X-Content-Type-Options",
            status=HeaderTestStatus.FAIL,
            score_modifier=-5,
            observed_value=xcto or None,
            expected_value="nosniff",
            description="Instructs browsers to strictly adhere to declared MIME types without content sniffing.",
            advice="Add 'X-Content-Type-Options: nosniff' to HTTP response headers.",
            doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        ), findings

    def _test_referrer_policy(self, target: TargetScope, headers: httpx.Headers) -> Tuple[HeaderTestResult, List[Finding]]:
        ref = headers.get("referrer-policy")
        findings: List[Finding] = []

        if not ref:
            finding = self.create_finding(
                target=target,
                title="Missing Referrer-Policy Header",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description="No Referrer-Policy header is configured.",
                impact_explanation="Sensitive URLs and query parameters may leak to external third-party servers via the HTTP Referer header.",
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                verification_command=f"curl -sI {target.normalized_url} | grep -i referrer-policy",
                evidence=Evidence(
                    type=EvidenceType.HTTP_EXCHANGE,
                    summary="Referrer-Policy header is not present.",
                    response={"headers": dict(headers)}
                ),
                category=Category.BROWSER_SECURITY,
                cwe_id="CWE-200"
            )
            findings.append(finding)
            return HeaderTestResult(
                id="referrer-policy",
                name="Referrer Policy",
                header_name="Referrer-Policy",
                status=HeaderTestStatus.WARN,
                score_modifier=-5,
                observed_value=None,
                expected_value="strict-origin-when-cross-origin / no-referrer",
                description="Controls how much referrer information is sent with outbound requests.",
                advice="Add 'Referrer-Policy: strict-origin-when-cross-origin' to protect URL parameters.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
            ), findings

        ref_clean = ref.strip().lower()
        if ref_clean in ("unsafe-url", "no-referrer-when-downgrade"):
            return HeaderTestResult(
                id="referrer-policy",
                name="Referrer Policy",
                header_name="Referrer-Policy",
                status=HeaderTestStatus.WARN,
                score_modifier=-5,
                observed_value=ref,
                expected_value="strict-origin-when-cross-origin",
                description=f"Policy '{ref}' exposes full URL paths to external domains.",
                advice="Change Referrer-Policy to 'strict-origin-when-cross-origin' or 'same-origin'.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
            ), findings

        return HeaderTestResult(
            id="referrer-policy",
            name="Referrer Policy",
            header_name="Referrer-Policy",
            status=HeaderTestStatus.PASS,
            score_modifier=0,
            observed_value=ref,
            expected_value="strict-origin-when-cross-origin",
            description="Referrer-Policy protects internal URL structure from leaking on outbound requests.",
            advice="Referrer-Policy is securely configured.",
            doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        ), findings

    def _test_permissions_policy(self, target: TargetScope, headers: httpx.Headers) -> Tuple[HeaderTestResult, List[Finding]]:
        perm = headers.get("permissions-policy") or headers.get("feature-policy")
        findings: List[Finding] = []

        if not perm:
            return HeaderTestResult(
                id="permissions-policy",
                name="Permissions Policy",
                header_name="Permissions-Policy",
                status=HeaderTestStatus.INFO,
                score_modifier=0,
                observed_value=None,
                expected_value="camera=(), microphone=(), geolocation=()",
                description="Restricts browser hardware APIs (camera, microphone, geolocation) for embedded iframes.",
                advice="Consider adding 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to restrict unused APIs.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
            ), findings

        return HeaderTestResult(
            id="permissions-policy",
            name="Permissions Policy",
            header_name="Permissions-Policy",
            status=HeaderTestStatus.PASS,
            score_modifier=0,
            observed_value=perm[:100] + ("..." if len(perm) > 100 else ""),
            expected_value="camera=(), microphone=(), geolocation=()",
            description="Permissions-Policy explicit boundaries active for hardware APIs.",
            advice="Permissions Policy is configured.",
            doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        ), findings

    async def _test_cors(self, target: TargetScope, headers_to_send: dict) -> Tuple[HeaderTestResult, List[Finding]]:
        findings: List[Finding] = []
        evil_origin = "https://evil-attacker-origin.com"
        probe_headers = {**headers_to_send, "Origin": evil_origin}

        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                resp = await client.get(target.normalized_url, headers=probe_headers)
                allow_origin = resp.headers.get("access-control-allow-origin", "")
                allow_creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

                if allow_origin == evil_origin and allow_creds:
                    finding = self.create_finding(
                        target=target,
                        title="Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description=f"Server reflected untrusted origin '{evil_origin}' in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true.",
                        impact_explanation="Attacker websites can make authenticated cross-origin requests to read private user data and API responses.",
                        remediation="Do not dynamically mirror untrusted Origin headers when Access-Control-Allow-Credentials is true.",
                        verification_command=f"curl -sI -H 'Origin: {evil_origin}' {target.normalized_url} | grep -i access-control",
                        evidence=Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary="CORS reflected attacker origin with credentials enabled.",
                            response={"access-control-allow-origin": allow_origin, "access-control-allow-credentials": "true"}
                        ),
                        category=Category.API_SECURITY,
                        cwe_id="CWE-942"
                    )
                    findings.append(finding)
                    return HeaderTestResult(
                        id="cross-origin-resource-sharing",
                        name="Cross-Origin Resource Sharing (CORS)",
                        header_name="Access-Control-Allow-Origin",
                        status=HeaderTestStatus.FAIL,
                        score_modifier=-20,
                        observed_value=f"Reflected {evil_origin} (Credentials: true)",
                        expected_value="Restricted whitelist origins or omitted",
                        description="Arbitrary origin reflection with credentials allows authenticated cross-origin data theft.",
                        advice="Validate Origin against a strict whitelist before echoing in Access-Control-Allow-Origin.",
                        doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    ), findings

                if allow_origin == "*":
                    return HeaderTestResult(
                        id="cross-origin-resource-sharing",
                        name="Cross-Origin Resource Sharing (CORS)",
                        header_name="Access-Control-Allow-Origin",
                        status=HeaderTestStatus.PASS if not allow_creds else HeaderTestStatus.WARN,
                        score_modifier=0 if not allow_creds else -10,
                        observed_value="Access-Control-Allow-Origin: *",
                        expected_value="Specific trusted origin or wildcard for public APIs",
                        description="Wildcard CORS allows any origin to read public API responses.",
                        advice="Ensure sensitive authenticated endpoints do not use wildcard CORS.",
                        doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    ), findings

                return HeaderTestResult(
                    id="cross-origin-resource-sharing",
                    name="Cross-Origin Resource Sharing (CORS)",
                    header_name="Access-Control-Allow-Origin",
                    status=HeaderTestStatus.PASS,
                    score_modifier=0,
                    observed_value=allow_origin or "Omitted (Same-Origin Default)",
                    expected_value="Same-Origin or explicit whitelist",
                    description="CORS access is properly restricted or defaults to same-origin isolation.",
                    advice="CORS headers are safe.",
                    doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ), findings
        except Exception:
            return HeaderTestResult(
                id="cross-origin-resource-sharing",
                name="Cross-Origin Resource Sharing (CORS)",
                header_name="Access-Control-Allow-Origin",
                status=HeaderTestStatus.PASS,
                score_modifier=0,
                observed_value="Standard Same-Origin Default",
                expected_value="Same-Origin or explicit whitelist",
                description="Default browser same-origin policy is enforced.",
                advice="CORS headers are standard.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            ), findings

    def _test_sri(self, target: TargetScope, html_text: str) -> Tuple[HeaderTestResult, List[Finding]]:
        findings: List[Finding] = []
        if not html_text:
            return HeaderTestResult(
                id="subresource-integrity",
                name="Subresource Integrity (SRI)",
                header_name="integrity",
                status=HeaderTestStatus.PASS,
                score_modifier=0,
                observed_value="No scripts evaluated",
                expected_value="integrity='sha384-...' for external scripts",
                description="SRI validates that external CDN scripts have not been tampered with or compromised.",
                advice="Apply integrity hashes to external script tags.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
            ), findings

        body = html_text[:150000]
        script_tags = re.findall(r'<script\b[^>]*>', body, re.IGNORECASE)
        external_missing_sri = []

        for tag in script_tags:
            src_match = re.search(r'src=["\'](https?://[^"\']+)["\']', tag, re.IGNORECASE)
            if src_match:
                src = src_match.group(1)
                # Check if cross-origin
                if target.host not in src:
                    has_integrity = "integrity=" in tag.lower()
                    if not has_integrity:
                        external_missing_sri.append(src)

        if external_missing_sri:
            sample = external_missing_sri[0]
            finding = self.create_finding(
                target=target,
                title="External Scripts Loaded Without Subresource Integrity (SRI)",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                status=ObservationStatus.CONFIRMED,
                description=f"External script '{sample}' is loaded from a third-party origin without an 'integrity' hash attribute ({len(external_missing_sri)} external scripts found without SRI).",
                impact_explanation="If the third-party CDN is compromised, malicious code can be injected into your users' browser sessions without detection.",
                remediation="Add cryptographic 'integrity=\"sha384-...\"' and 'crossorigin=\"anonymous\"' attributes to all third-party script tags.",
                verification_command=f"curl -sL {target.normalized_url} | grep -Ei '<script[^>]+src=[\"\\']https?://'",
                evidence=Evidence(
                    type=EvidenceType.DOM_CONTENT,
                    summary=f"{len(external_missing_sri)} external script(s) lack integrity attribute.",
                    matched_data=sample,
                    response={"unprotected_scripts": external_missing_sri[:5]}
                ),
                category=Category.THIRD_PARTY_RESOURCES,
                cwe_id="CWE-353"
            )
            findings.append(finding)
            return HeaderTestResult(
                id="subresource-integrity",
                name="Subresource Integrity (SRI)",
                header_name="integrity",
                status=HeaderTestStatus.WARN,
                score_modifier=-5,
                observed_value=f"{len(external_missing_sri)} external script(s) missing integrity hash",
                expected_value="integrity='sha384-...' crossorigin='anonymous'",
                description="Third-party CDN scripts loaded without integrity hashes can execute malicious code if the CDN is compromised.",
                advice="Add 'integrity' hashes and 'crossorigin' attributes to all external <script> tags.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
            ), findings

        return HeaderTestResult(
            id="subresource-integrity",
            name="Subresource Integrity (SRI)",
            header_name="integrity",
            status=HeaderTestStatus.PASS,
            score_modifier=0,
            observed_value="All external scripts pinned with SRI or purely first-party",
            expected_value="integrity='sha384-...' for external scripts",
            description="External resources are verified against cryptographic digests or served from same-origin.",
            advice="SRI configuration is satisfactory.",
            doc_url="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
        ), findings

    def _test_cookies(self, target: TargetScope, raw_set_cookies: List[str]) -> Tuple[HeaderTestResult, List[Finding]]:
        findings: List[Finding] = []
        if not raw_set_cookies:
            return HeaderTestResult(
                id="cookies",
                name="Cookie Security Posture",
                header_name="Set-Cookie",
                status=HeaderTestStatus.PASS,
                score_modifier=0,
                observed_value="No Set-Cookie headers observed",
                expected_value="Secure; HttpOnly; SameSite=Lax/Strict",
                description="Cookies store authentication and session state and require browser flags to prevent theft.",
                advice="When adding cookies, ensure 'Secure', 'HttpOnly', and 'SameSite' attributes are declared.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
            ), findings

        insecure_secure = []
        insecure_httponly = []
        insecure_samesite = []

        for cookie_str in raw_set_cookies:
            cookie_lower = cookie_str.lower()
            name = cookie_str.split("=")[0].strip()
            if target.scheme == "https" and "secure" not in cookie_lower:
                insecure_secure.append(name)
            if "httponly" not in cookie_lower:
                insecure_httponly.append(name)
            if "samesite" not in cookie_lower:
                insecure_samesite.append(name)

        if insecure_secure:
            return HeaderTestResult(
                id="cookies",
                name="Cookie Security Posture",
                header_name="Set-Cookie",
                status=HeaderTestStatus.FAIL,
                score_modifier=-20,
                observed_value=f"Missing 'Secure' flag on {len(insecure_secure)} cookie(s): {', '.join(insecure_secure[:3])}",
                expected_value="Secure; HttpOnly; SameSite=Lax",
                description="Cookies set over HTTPS without the 'Secure' attribute can be leaked across plaintext connections.",
                advice="Add '; Secure' to all Set-Cookie headers.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
            ), findings

        if insecure_httponly or insecure_samesite:
            issues = []
            if insecure_httponly:
                issues.append(f"Missing HttpOnly ({', '.join(insecure_httponly[:2])})")
            if insecure_samesite:
                issues.append(f"Missing SameSite ({', '.join(insecure_samesite[:2])})")
            return HeaderTestResult(
                id="cookies",
                name="Cookie Security Posture",
                header_name="Set-Cookie",
                status=HeaderTestStatus.WARN,
                score_modifier=-10,
                observed_value="; ".join(issues),
                expected_value="Secure; HttpOnly; SameSite=Lax/Strict",
                description="Cookies missing HttpOnly or SameSite are vulnerable to client-side theft via XSS or CSRF.",
                advice="Declare '; HttpOnly; SameSite=Lax' on all session and tracking cookies.",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
            ), findings

        return HeaderTestResult(
            id="cookies",
            name="Cookie Security Posture",
            header_name="Set-Cookie",
            status=HeaderTestStatus.PASS,
            score_modifier=0,
            observed_value=f"{len(raw_set_cookies)} cookie(s) configured with Secure, HttpOnly, and SameSite",
            expected_value="Secure; HttpOnly; SameSite=Lax/Strict",
            description="All observed cookies enforce browser security flags.",
            advice="Cookie configuration is secure.",
            doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
        ), findings

    def _test_server_disclosure(self, target: TargetScope, headers: httpx.Headers) -> Tuple[HeaderTestResult, List[Finding]]:
        findings: List[Finding] = []
        disclosures = []
        for header_name in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
            val = headers.get(header_name)
            if val:
                if bool(re.search(r"\d+\.\d+", val)):
                    disclosures.append(f"{header_name}: {val}")
                    finding = self.create_finding(
                        target=target,
                        title=f"Technology Version Disclosure via '{header_name}' Header",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description=f"HTTP response reveals exact software version: '{header_name}: {val}'.",
                        impact_explanation="Disclosing exact software builds simplifies reconnaissance and vulnerability targeting for automated exploit scanners.",
                        remediation=f"Configure the web server or reverse proxy to suppress or mask '{header_name}'.",
                        verification_command=f"curl -sI {target.normalized_url} | grep -i {header_name}",
                        evidence=Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary=f"Header '{header_name}' reveals detailed version: '{val}'",
                            response={header_name: val}
                        ),
                        category=Category.INFORMATION_EXPOSURE,
                        cwe_id="CWE-200"
                    )
                    findings.append(finding)

        if disclosures:
            return HeaderTestResult(
                id="server-disclosure",
                name="Server & Technology Version Disclosure",
                header_name="Server / X-Powered-By",
                status=HeaderTestStatus.WARN,
                score_modifier=-5,
                observed_value=", ".join(disclosures),
                expected_value="Suppressed or generic (e.g. 'cloudflare', 'nginx')",
                description="Revealing exact software version numbers assists attackers during fingerprinting.",
                advice="Suppress granular version banners in web server configuration (e.g. 'server_tokens off;').",
                doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server",
            ), findings

        server_val = headers.get("server") or "Generic / Suppressed"
        return HeaderTestResult(
            id="server-disclosure",
            name="Server & Technology Version Disclosure",
            header_name="Server",
            status=HeaderTestStatus.PASS,
            score_modifier=0,
            observed_value=server_val,
            expected_value="Generic or suppressed version strings",
            description="Web server tokens and backend versions are properly masked.",
            advice="Technology headers are restrained.",
            doc_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server",
        ), findings

    def _test_mixed_content(self, target: TargetScope, resp_text: str) -> List[Finding]:
        findings: List[Finding] = []
        if target.scheme == "https" and resp_text:
            body_content = resp_text[:128000]
            active_mixed = re.findall(r'<(?:script[^>]+src|iframe[^>]+src|link[^>]+href)=["\'](http://[^"\']+)["\']', body_content, re.IGNORECASE)
            passive_mixed = re.findall(r'<(?:img[^>]+src|audio[^>]+src|video[^>]+src)=["\'](http://[^"\']+)["\']', body_content, re.IGNORECASE)

            if active_mixed:
                sample_insecure = active_mixed[0]
                evidence = Evidence(
                    type=EvidenceType.DOM_CONTENT,
                    summary=f"Active mixed content detected: {len(active_mixed)} resource(s) loaded over plaintext HTTP.",
                    matched_data=sample_insecure,
                    response={"insecure_resources": active_mixed[:5]}
                )
                findings.append(
                    self.create_finding(
                        target=target,
                        title="Active Mixed Content Detected (<script>/<iframe> over plain HTTP)",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description=f"An active resource ('{sample_insecure}') is loaded over unencrypted HTTP on an HTTPS page.",
                        impact_explanation="Network attackers can intercept and alter the unencrypted resource, executing arbitrary JavaScript in the context of your HTTPS site.",
                        remediation="Ensure all scripts, iframes, and stylesheets use https:// or relative paths.",
                        verification_command=f"curl -sL {target.normalized_url} | grep -Ei 'src=[\"\\']http://|href=[\"\\']http://'",
                        evidence=evidence,
                        category=Category.TRANSPORT_SECURITY,
                        cwe_id="CWE-319"
                    )
                )
            elif passive_mixed:
                sample_insecure = passive_mixed[0]
                evidence = Evidence(
                    type=EvidenceType.DOM_CONTENT,
                    summary=f"Passive mixed content detected: {len(passive_mixed)} resource(s) loaded over plain HTTP.",
                    matched_data=sample_insecure,
                    response={"insecure_resources": passive_mixed[:5]}
                )
                findings.append(
                    self.create_finding(
                        target=target,
                        title="Passive Mixed Content Detected (<img> over plain HTTP)",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description=f"A passive resource ('{sample_insecure}') is loaded over unencrypted HTTP on an HTTPS page.",
                        impact_explanation="Insecure images allow network eavesdroppers to track user activity or replace images.",
                        remediation="Update image URLs to https://.",
                        verification_command=f"curl -sL {target.normalized_url} | grep -Ei '<img[^>]+src=[\"\\']http://'",
                        evidence=evidence,
                        category=Category.TRANSPORT_SECURITY,
                        cwe_id="CWE-319"
                    )
                )
        return findings

    async def _test_options_methods(self, target: TargetScope, headers_to_send: dict) -> List[Finding]:
        findings: List[Finding] = []
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                options_resp = await client.options(target.normalized_url, headers=headers_to_send)
                allow_methods = options_resp.headers.get("allow", "") or options_resp.headers.get("public", "")
                if allow_methods:
                    methods_upper = [m.strip().upper() for m in allow_methods.split(",")]
                    dangerous_advertised = [m for m in ("TRACE", "TRACK") if m in methods_upper]
                    if dangerous_advertised:
                        evidence = Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary=f"OPTIONS probe observed advertised methods: {allow_methods}",
                            response={"status_code": options_resp.status_code, "allow": allow_methods}
                        )
                        findings.append(
                            self.create_finding(
                                target=target,
                                title=f"Insecure HTTP Method Advertised in OPTIONS ({', '.join(dangerous_advertised)})",
                                severity=Severity.LOW,
                                confidence=Confidence.POTENTIAL,
                                status=ObservationStatus.OBSERVED,
                                description=f"The server advertises support for '{', '.join(dangerous_advertised)}' methods in its Allow/Public response headers.",
                                impact_explanation="If TRACE is active, Cross-Site Tracing (XST) attacks could reflect sensitive headers back to JavaScript.",
                                remediation="Disable TRACE and TRACK methods in web server configuration.",
                                verification_command=f"curl -s -X OPTIONS -i {target.normalized_url} | grep -Ei '^(allow|public):'",
                                evidence=evidence,
                                category=Category.TRANSPORT_SECURITY,
                                cwe_id="CWE-200"
                            )
                        )
        except Exception:
            pass
        return findings
