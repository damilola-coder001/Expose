"""Client-Side JavaScript and DOM security posture probe for Expose (Phase 7).

Inspects client-side script integrity, form submission protocols, source maps,
and public API endpoint references without speculative claims.
"""

from typing import List
import re
import urllib.parse
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


class ClientSideProbe(BaseProbe):
    """Inspects publicly observable client-side assets and DOM security parameters."""

    @property
    def name(self) -> str:
        return "client_side_analysis"

    @property
    def category(self) -> Category:
        return Category.CLIENT_SIDE_SECURITY

    @property
    def description(self) -> str:
        return "Analyzes client-side scripts, SRI integrity, forms, and public API endpoint references."

    async def execute(self, target: TargetScope) -> List[Finding]:
        findings: List[Finding] = []
        target_url = target.normalized_url

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Expose-Security-Intelligence/1.0 (Client-Side Analyzer)"}
        ) as client:
            try:
                resp = await client.get(target_url)
            except Exception:
                return findings

            body = resp.text

            # 1. Inspect External Script Tags for Subresource Integrity (SRI)
            script_pattern = re.compile(r'<script\s+[^>]*src=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
            external_scripts_without_sri = []
            for match in script_pattern.finditer(body):
                full_tag = match.group(0)
                src = match.group(1)

                try:
                    parsed_src = urllib.parse.urlparse(src)
                except Exception:
                    continue

                is_external = bool(parsed_src.netloc and parsed_src.netloc != target.host and not parsed_src.netloc.endswith("." + target.host))
                has_integrity = "integrity=" in full_tag.lower()

                if is_external and not has_integrity:
                    external_scripts_without_sri.append((src, parsed_src.netloc, full_tag))

            if external_scripts_without_sri:
                unique_hosts = list(dict.fromkeys(h for _, h, _ in external_scripts_without_sri))
                first_src, _, _ = external_scripts_without_sri[0]
                count = len(external_scripts_without_sri)
                summary_text = (
                    f"{count} external script(s) loaded without SRI from hosts: {', '.join(unique_hosts[:3])}"
                    + ("..." if len(unique_hosts) > 3 else "")
                )
                findings.append(self.create_finding(
                    target=target,
                    title="Missing Subresource Integrity (SRI) on External Scripts",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    category=Category.CLIENT_SIDE_SECURITY,
                    description=f"{count} external script(s) loaded from third-party hosts ({', '.join(unique_hosts[:5])}) without integrity cryptographic hashes.",
                    impact_explanation="If the third-party CDN or supplier is compromised, malicious code could be injected into client sessions without detection.",
                    remediation="Add cryptographic SRI integrity hashes (e.g. integrity=\"sha384-...\") and crossorigin=\"anonymous\" to external scripts.",
                    evidence=Evidence(
                        type=EvidenceType.SCRIPT_REFERENCE,
                        summary=summary_text,
                        matched_data="\n".join(t for _, _, t in external_scripts_without_sri[:5]),
                        command=f"curl -sL '{target_url}' | grep -i '<script'",
                    ),
                    verification_command=f"curl -sL '{target_url}' | grep -i '{first_src}'",
                    cwe_id="CWE-353",
                ))

                # 2. Check for public source maps (.js.map)
                if src.endswith(".js"):
                    map_url = urllib.parse.urljoin(target_url, src + ".map")
                    try:
                        map_resp = await client.head(map_url, timeout=3.0)
                        if map_resp.status_code == 200:
                            findings.append(self.create_finding(
                                target=target,
                                title="Public JavaScript Source Map Exposed",
                                severity=Severity.LOW,
                                confidence=Confidence.CONFIRMED,
                                status=ObservationStatus.CONFIRMED,
                                category=Category.INFORMATION_DISCLOSURE,
                                description=f"JavaScript source map file is publicly accessible at '{map_url}', revealing unminified original source code.",
                                impact_explanation="Source map files allow reverse-engineering of client application logic, internal API endpoints, and comments.",
                                remediation="Disable production source maps in your bundler (productionSourceMap: false) or restrict .map extensions at edge reverse proxy.",
                                evidence=Evidence(
                                    type=EvidenceType.SOURCE_MAP,
                                    summary=f"HTTP 200 OK returned for {map_url}",
                                    matched_data=map_url,
                                    command=f"curl -sI '{map_url}'",
                                ),
                                verification_command=f"curl -sI '{map_url}' | grep -E 'HTTP/[12] 200'",
                                cwe_id="CWE-540",
                            ))
                    except Exception:
                        pass

            # 3. Inspect Forms for Insecure Submissions
            form_pattern = re.compile(r'<form\s+[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
            for form_match in form_pattern.finditer(body):
                form_tag = form_match.group(0)
                form_inner = form_match.group(1)

                has_password = 'type="password"' in form_inner.lower() or "type='password'" in form_inner.lower()
                if not has_password:
                    continue

                is_get = 'method="get"' in form_tag.lower() or "method='get'" in form_tag.lower()
                has_http_action = 'action="http:' in form_tag.lower() or "action='http:" in form_tag.lower()

                if has_http_action:
                    findings.append(self.create_finding(
                        target=target,
                        title="Insecure Password Form Submission Over Plain HTTP",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        category=Category.TRANSPORT_SECURITY,
                        description="Credential form specifies an unencrypted HTTP action target.",
                        impact_explanation="Passwords submitted over unencrypted HTTP can be intercepted in transit on shared networks.",
                        remediation="Ensure all form action attributes explicitly specify https:// or use secure relative paths on an HTTPS-only host.",
                        evidence=Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary="Form contains password input with unencrypted http:// action target.",
                            matched_data=form_tag[:250],
                            command=f"curl -sL '{target_url}' | grep -i '<form' | grep -i 'action=\"http:'",
                        ),
                        verification_command=f"curl -sL '{target_url}' | grep -i '<form' | grep -i 'action=\"http:'",
                        cwe_id="CWE-319",
                    ))

                if is_get:
                    findings.append(self.create_finding(
                        target=target,
                        title="Password Submitted via HTTP GET Method",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        category=Category.CLIENT_SIDE_SECURITY,
                        description="Form containing password inputs uses the HTTP GET method.",
                        impact_explanation="Passwords submitted via GET leak into browser history, web server logs, and HTTP Referer headers.",
                        remediation="Change form submission method attribute to method=\"POST\".",
                        evidence=Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary="Form contains password input with method='GET'.",
                            matched_data=form_tag[:250],
                            command=f"curl -sL '{target_url}' | grep -i '<form' | grep -i 'method=\"get\"'",
                        ),
                        verification_command=f"curl -sL '{target_url}' | grep -i '<form' | grep -i 'method=\"get\"'",
                        cwe_id="CWE-598",
                    ))

            # 4. Discover Public API Endpoints Referenced in Markup & Scripts
            api_pattern = re.compile(r'["\'](/api/v[0-9]+[a-zA-Z0-9_\-/]+)["\']')
            discovered_apis = list(set(api_pattern.findall(body)))

            if discovered_apis:
                sample_apis = discovered_apis[:8]
                findings.append(self.create_finding(
                    target=target,
                    title="Public API Endpoints Referenced in Client-Side Code",
                    severity=Severity.INFO,
                    confidence=Confidence.INFORMATIONAL,
                    status=ObservationStatus.OBSERVED,
                    category=Category.INFORMATION_DISCLOSURE,
                    description=f"Client-side markup and scripts disclose {len(discovered_apis)} backend API endpoint paths.",
                    impact_explanation="Frontend client applications legitimately reference their backend APIs. This observation maps the attack surface; it does not indicate a vulnerability on its own.",
                    remediation="Confirm that all endpoints referenced in client code enforce server-side authentication and authorization controls.",
                    evidence=Evidence(
                        type=EvidenceType.SCRIPT_REFERENCE,
                        summary=f"Discovered API paths: {', '.join(sample_apis)}",
                        matched_data=", ".join(sample_apis),
                        command=f"curl -sL '{target_url}' | grep -Eo '\"/api/v[0-9]+[^\"]+\"' | head -n 8",
                    ),
                    verification_command=f"curl -sL '{target_url}' | grep -Eo '\"/api/v[0-9]+[^\"]+\"' | head -n 8",
                ))

            # 5. DOM XSS Dangerous Sink Inspection
            dom_sink_findings = self._inspect_dom_sinks(target, target_url, body)
            findings.extend(dom_sink_findings)

            # 6. Insecure postMessage Listener Inspection
            postmessage_findings = self._inspect_postmessage(target, target_url, body)
            findings.extend(postmessage_findings)

            # 7. Sensitive Web Storage Inspection
            storage_findings = self._inspect_web_storage(target, target_url, body)
            findings.extend(storage_findings)

        return findings

    def _inspect_dom_sinks(self, target: TargetScope, target_url: str, body: str) -> List[Finding]:
        findings: List[Finding] = []
        sink_patterns = [
            (r'document\.write\s*\(', "document.write()", Severity.MEDIUM, "CWE-79", "Direct use of document.write() can lead to DOM XSS if unescaped location/query params are supplied."),
            (r'(?:innerHTML|outerHTML)\s*=\s*(?:location|document\.location|window\.location|document\.URL|document\.referrer)', "Unescaped DOM Sink Assignment (innerHTML)", Severity.HIGH, "CWE-79", "Directly assigning URL parameters or document location to innerHTML allows DOM-based Cross-Site Scripting."),
            (r'eval\s*\(\s*(?:location|document\.location|window\.location|decodeURIComponent)', "Dynamic eval() Execution of URL Input", Severity.HIGH, "CWE-95", "Executing dynamic strings derived from user-controlled URL input via eval() permits arbitrary JavaScript execution."),
        ]

        for pattern, sink_name, sev, cwe, explanation in sink_patterns:
            matches = list(re.finditer(pattern, body, re.IGNORECASE))
            if matches:
                sample_snippet = body[max(0, matches[0].start() - 40):min(len(body), matches[0].end() + 60)].strip()
                evidence = Evidence(
                    type=EvidenceType.SCRIPT_REFERENCE,
                    summary=f"Discovered dangerous DOM sink pattern ({sink_name}) in client scripts.",
                    matched_data=sample_snippet,
                    command=f"curl -sL '{target_url}' | grep -E '{pattern}'"
                )
                findings.append(
                    self.create_finding(
                        target=target,
                        title=f"Potential DOM-Based XSS Sink ({sink_name})",
                        severity=sev,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description=f"Client-side scripts contain dangerous DOM manipulation sink '{sink_name}'.",
                        impact_explanation=explanation,
                        remediation="Use safe APIs like textContent or sanitize inputs with DOMPurify before inserting into the DOM.",
                        verification_command=f"curl -sL '{target_url}' | grep -E '{pattern}'",
                        evidence=evidence,
                        category=Category.CLIENT_SIDE_SECURITY,
                        cwe_id=cwe
                    )
                )
        return findings

    def _inspect_postmessage(self, target: TargetScope, target_url: str, body: str) -> List[Finding]:
        findings: List[Finding] = []
        pm_listener_pattern = re.compile(r'(?:window|document)\.addEventListener\s*\(\s*["\']message["\']\s*,\s*function\s*\(([^)]*)\)\s*\{([^}]*)\}', re.IGNORECASE | re.DOTALL)

        for match in pm_listener_pattern.finditer(body):
            event_param = match.group(1).strip() or "e"
            handler_body = match.group(2)

            origin_check_present = f"{event_param}.origin" in handler_body or "origin" in handler_body

            if not origin_check_present:
                snippet = match.group(0)[:200]
                evidence = Evidence(
                    type=EvidenceType.SCRIPT_REFERENCE,
                    summary="postMessage listener does not validate event.origin before processing messages.",
                    matched_data=snippet,
                    command=f"curl -sL '{target_url}' | grep -A 5 'addEventListener(\"message\"'"
                )
                findings.append(
                    self.create_finding(
                        target=target,
                        title="Insecure Cross-Window postMessage Listener (Missing Origin Validation)",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        status=ObservationStatus.CONFIRMED,
                        description="A window.addEventListener('message', ...) handler does not verify the sender's event.origin.",
                        impact_explanation="Any malicious website embedded in an iframe or opening this page in a popup can dispatch forged message events to execute internal client actions.",
                        remediation="Always verify 'if (event.origin !== \"https://trusted-domain.com\") return;' as the first line of every message event handler.",
                        verification_command=f"curl -sL '{target_url}' | grep -i 'addEventListener(\"message\"'",
                        evidence=evidence,
                        category=Category.CLIENT_SIDE_SECURITY,
                        cwe_id="CWE-345"
                    )
                )
        return findings

    def _inspect_web_storage(self, target: TargetScope, target_url: str, body: str) -> List[Finding]:
        findings: List[Finding] = []
        token_storage_pattern = re.compile(r'localStorage\.setItem\s*\(\s*["\'](?:jwt|token|access_token|bearer_token|auth_token)["\']', re.IGNORECASE)
        match = token_storage_pattern.search(body)
        if match:
            snippet = body[max(0, match.start() - 30):min(len(body), match.end() + 50)].strip()
            evidence = Evidence(
                type=EvidenceType.SCRIPT_REFERENCE,
                summary="Client scripts store authentication bearer tokens in unencrypted localStorage.",
                matched_data=snippet,
                command=f"curl -sL '{target_url}' | grep -Ei 'localStorage\\\\.setItem\\\\(\\\"(jwt|token|auth)'"
            )
            findings.append(
                self.create_finding(
                    target=target,
                    title="Sensitive Authentication Token Stored in localStorage",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    description="Client-side JavaScript stores session/auth tokens directly in browser localStorage.",
                    impact_explanation="localStorage is accessible to all client JavaScript on the origin. Any Cross-Site Scripting (XSS) vulnerability allows immediate token theft.",
                    remediation="Store session tokens in HttpOnly, Secure, SameSite cookies instead of accessible localStorage.",
                    verification_command=f"curl -sL '{target_url}' | grep -i 'localStorage.setItem'",
                    evidence=evidence,
                    category=Category.COOKIE_SESSION_SECURITY,
                    cwe_id="CWE-922"
                )
            )
        return findings

