"""Nikto Web Server Security Intelligence Probe for Expose.

Audits web servers for dangerous files, outdated server banner disclosures,
insecure HTTP methods (TRACE/PUT/DELETE), and misconfiguration vulnerabilities
using either the native Nikto binary (when present) or high-fidelity empirical HTTP auditing.
"""

import asyncio
import json
import re
import shutil
from typing import Dict, List, Optional, Tuple
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


# Common sensitive diagnostic and configuration paths checked by Nikto
NIKTO_SENSITIVE_PATHS: List[Tuple[str, Optional[str], str, Severity, str, str]] = [
    ("/test.php", "phpinfo", "PHP Test Script (/test.php) Exposed", Severity.MEDIUM, "CWE-200", "Publicly accessible test PHP script may expose server diagnostics."),
    ("/info.php", "phpinfo", "PHP Diagnostics Script (/info.php) Exposed", Severity.MEDIUM, "CWE-200", "Exposed phpinfo diagnostic script discloses server modules and configuration details."),
    ("/server-status", "Apache Server Status", "Apache Server Status Page Exposed", Severity.LOW, "CWE-200", "Apache mod_status handler is reachable without authentication, disclosing live client requests."),
    ("/cgi-bin/test-cgi", "CGI", "Test CGI Script (/cgi-bin/test-cgi) Exposed", Severity.MEDIUM, "CWE-200", "Exposed test CGI script in /cgi-bin can disclose server environment variables."),
    ("/.htaccess", "RewriteEngine", "Apache .htaccess Configuration Exposed", Severity.HIGH, "CWE-200", "Web server configuration file is readable over public HTTP."),
]


class NiktoProbe(BaseProbe):
    """Audits web server misconfigurations, dangerous paths, and server disclosures via Nikto or empirical HTTP checks."""

    @property
    def name(self) -> str:
        return "nikto_probe"

    @property
    def category(self) -> Category:
        return Category.CONFIGURATION

    @property
    def description(self) -> str:
        return "Audits web servers for outdated software versions, dangerous files, CGI scripts, and HTTP configuration flaws."

    async def execute(self, target: TargetScope) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Attempt binary execution if nikto or nikto.pl is installed
        nikto_bin = shutil.which("nikto") or shutil.which("nikto.pl")
        if nikto_bin:
            findings = await self._execute_nikto_binary(nikto_bin, target)
            if findings:
                return findings

        # 2. Fallback to native empirical web server security audit
        return await self._execute_native_nikto_checks(target)

    async def _execute_nikto_binary(self, nikto_bin: str, target: TargetScope) -> List[Finding]:
        """Runs the Nikto binary with safe timeouts and structured output parsing."""
        findings: List[Finding] = []
        cmd = [
            nikto_bin,
            "-h",
            target.normalized_url,
            "-Format",
            "json",
            "-output",
            "-",
            "-Tuning",
            "123b",
            "-timeout",
            "8",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=12.0)
            if stdout:
                findings = self._parse_nikto_output(stdout.decode("utf-8", errors="ignore"), target)
        except Exception:
            return []

        return findings

    def _parse_nikto_output(self, output: str, target: TargetScope) -> List[Finding]:
        """Parses Nikto JSON output or text lines into Expose findings."""
        findings: List[Finding] = []
        try:
            # Nikto JSON may contain embedded JSON objects or text banners
            json_start = output.find("{")
            if json_start != -1:
                data = json.loads(output[json_start:])
                items = data.get("vulnerabilities", []) or data.get("items", [])
                for item in items:
                    msg = item.get("msg") or item.get("description", "")
                    uri = item.get("url") or item.get("uri", "")
                    osvdb = item.get("osvdb", "")
                    
                    evidence = Evidence(
                        type=EvidenceType.NIKTO_OUTPUT,
                        summary=f"Nikto detected: {msg}",
                        raw_data={"uri": uri, "osvdb": osvdb, "output": msg},
                        command=f"nikto -h {target.normalized_url}",
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title=f"Nikto: {msg[:80]}",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LIKELY,
                            status=ObservationStatus.CONFIRMED,
                            description=msg,
                            remediation="Review web server configuration and remove identified test files or restrict permissions.",
                            evidence=evidence,
                            category=Category.CONFIGURATION,
                            rule_id="EXP-NIKTO-FINDING",
                            cwe_id="CWE-200",
                        )
                    )
        except Exception:
            pass

        return findings

    async def _execute_native_nikto_checks(self, target: TargetScope) -> List[Finding]:
        """Executes empirical web server and HTTP configuration checks."""
        findings: List[Finding] = []
        base_url = target.normalized_url.rstrip("/")

        async with httpx.AsyncClient(
            timeout=5.0,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Expose-Nikto-Probe/1.0)"},
        ) as client:
            # 1. Main request & Server Banner Information Disclosure
            try:
                resp = await client.get(base_url + "/")
                # A 4xx/5xx response may be a CDN challenge, authentication
                # gate, or error document rather than the application's page.
                # It cannot establish missing application response headers.
                if resp.status_code >= 400:
                    return findings
                server_hdr = resp.headers.get("server", "").strip()
                powered_by = resp.headers.get("x-powered-by", "").strip()

                # Check for detailed version numbers in Server header (e.g., Apache/2.4.41, nginx/1.18.0)
                if server_hdr and re.search(r"[\d]+\.[\d]+", server_hdr):
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"Server response header discloses software and exact version: '{server_hdr}'.",
                        response={"server": server_hdr, "status_code": resp.status_code},
                        command=f"curl -sI {base_url}/ | grep -i server",
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title=f"Web Server Version Disclosed in Header ({server_hdr})",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description=f"The web server discloses its exact software brand and version ({server_hdr}) in the HTTP response headers.",
                            remediation="Configure your web server (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx) to suppress version details.",
                            impact_explanation="Explicit version numbers allow automated reconnaissance tools to cross-reference known public CVEs.",
                            evidence=evidence,
                            category=Category.CONFIGURATION,
                            rule_id="EXP-NIKTO-SERVER-DISCLOSURE",
                            cwe_id="CWE-200",
                        )
                    )

                if powered_by:
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"X-Powered-By header discloses underlying backend framework: '{powered_by}'.",
                        response={"x-powered-by": powered_by, "status_code": resp.status_code},
                        command=f"curl -sI {base_url}/ | grep -i x-powered-by",
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title=f"Application Framework Disclosed via X-Powered-By ({powered_by})",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description=f"The application leaks its runtime environment or language via the X-Powered-By header ({powered_by}).",
                            remediation="Disable expose_php in php.ini, or remove the X-Powered-By header in your application framework settings.",
                            evidence=evidence,
                            category=Category.CONFIGURATION,
                            rule_id="EXP-NIKTO-POWERED-BY",
                            cwe_id="CWE-200",
                        )
                    )

                # Check for anti-clickjacking header (X-Frame-Options or CSP frame-ancestors)
                csp = resp.headers.get("content-security-policy", "")
                xfo = resp.headers.get("x-frame-options", "")
                if not xfo and "frame-ancestors" not in csp:
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary="HTTP response is missing both X-Frame-Options and Content-Security-Policy frame-ancestors directive.",
                        response={"status_code": resp.status_code},
                        command=f"curl -sI {base_url}/ | grep -Ei 'x-frame-options|content-security-policy'",
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title="Anti-Clickjacking Protection Missing (X-Frame-Options)",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description="The web server does not send an X-Frame-Options header or CSP frame-ancestors directive, potentially permitting UI redressing/clickjacking.",
                            remediation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or configure 'frame-ancestors 'self'' in Content-Security-Policy.",
                            impact_explanation="Attackers can render your web page in a hidden <iframe> on a malicious site and hijack user clicks.",
                            evidence=evidence,
                            category=Category.CONFIGURATION,
                            rule_id="EXP-NIKTO-CLICKJACKING",
                            cwe_id="CWE-1021",
                        )
                    )

            except Exception:
                pass

            # 2. Check HTTP Methods via OPTIONS request
            try:
                opt_resp = await client.options(base_url + "/")
                allowed_methods = opt_resp.headers.get("allow") or opt_resp.headers.get("public") or ""
                methods = [m.strip().upper() for m in allowed_methods.split(",") if m.strip()]

                if "TRACE" in methods or "TRACK" in methods:
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"OPTIONS request confirms dangerous HTTP debugging method enabled: '{', '.join(methods)}'.",
                        response={"allow": allowed_methods, "status_code": opt_resp.status_code},
                        command=f"curl -X OPTIONS -i {base_url}/",
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title="HTTP TRACE / TRACK Method Enabled (Cross-Site Tracing Risk)",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description="The HTTP TRACE or TRACK method is enabled. Web servers supporting TRACE echo incoming requests, which can be abused for Cross-Site Tracing (XST) to steal HTTPOnly cookies.",
                            remediation="Disable HTTP TRACE in your web server configuration (e.g. TraceEnable off in Apache).",
                            evidence=evidence,
                            category=Category.CONFIGURATION,
                            rule_id="EXP-NIKTO-TRACE-ENABLED",
                            cwe_id="CWE-693",
                        )
                    )

                dangerous_methods = [m for m in ["PUT", "DELETE"] if m in methods]
                if dangerous_methods:
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"Server advertises file modification methods on root: {', '.join(dangerous_methods)}.",
                        response={"allow": allowed_methods, "status_code": opt_resp.status_code},
                        command=f"curl -X OPTIONS -i {base_url}/",
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title=f"Insecure HTTP Methods Permitted ({', '.join(dangerous_methods)})",
                            severity=Severity.HIGH,
                            confidence=Confidence.LIKELY,
                            status=ObservationStatus.CONFIRMED,
                            description=f"The server advertises {', '.join(dangerous_methods)} methods in its Allow header on public endpoints.",
                            remediation="Restrict HTTP methods to GET, POST, and HEAD for public web interfaces unless authenticated REST APIs require others.",
                            evidence=evidence,
                            category=Category.CONFIGURATION,
                            rule_id="EXP-NIKTO-DANGEROUS-METHODS",
                            cwe_id="CWE-650",
                        )
                    )
            except Exception:
                pass

            # 3. Test sensitive Nikto diagnostic paths
            for path, signature, title, sev, cwe, desc in NIKTO_SENSITIVE_PATHS:
                try:
                    probe_url = base_url + path
                    p_resp = await client.get(probe_url)
                    if p_resp.status_code == 200:
                        content_type = p_resp.headers.get("content-type", "").lower()
                        # Verify signature if required or ensure it's not a generic HTML SPA catch-all
                        if signature and signature.lower() in p_resp.text.lower():
                            snippet = p_resp.text[:300].strip()
                            evidence = Evidence(
                                type=EvidenceType.HTTP_EXCHANGE,
                                summary=f"Path {path} returned HTTP 200 and matched signature '{signature}'.",
                                response={"status_code": p_resp.status_code, "content_type": content_type},
                                matched_data=snippet[:120],
                                command=f"curl -sI {probe_url}",
                            )
                            findings.append(
                                self.create_finding(
                                    target=target,
                                    title=title,
                                    severity=sev,
                                    confidence=Confidence.CONFIRMED,
                                    status=ObservationStatus.CONFIRMED,
                                    description=desc,
                                    remediation=f"Delete or restrict public access to {path}.",
                                    evidence=evidence,
                                    category=Category.CONFIGURATION,
                                    rule_id=f"EXP-NIKTO-{path.replace('/', '-').strip('-').upper()}",
                                    cwe_id=cwe,
                                )
                            )
                except Exception:
                    continue

        return findings
