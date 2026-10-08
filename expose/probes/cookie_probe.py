"""Cookie security probe for Expose.

Extracts all Set-Cookie headers and validates Secure, HttpOnly, and SameSite attributes
with verifiable evidence.
"""

from http.cookies import SimpleCookie
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


class CookieProbe(BaseProbe):
    """Evaluates security attributes (Secure, HttpOnly, SameSite) across all Set-Cookie directives."""

    @property
    def name(self) -> str:
        return "cookie_security"

    @property
    def category(self) -> Category:
        return Category.COOKIE_SECURITY

    @property
    def description(self) -> str:
        return "Analyzes cookies for missing Secure, HttpOnly, and SameSite flags."

    async def execute(self, target: TargetScope) -> List[Finding]:
        findings: List[Finding] = []

        headers_to_send = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Expose-Security-Intelligence/0.1.0",
        }

        raw_set_cookies: List[str] = []

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
            try:
                resp = await client.get(target.normalized_url, headers=headers_to_send)
                raw_set_cookies = resp.headers.get_list("set-cookie")
            except Exception:
                return findings

        if not raw_set_cookies:
            return findings

        session_keywords = {"session", "auth", "token", "jwt", "id", "sid", "user", "login", "key", "connect.sid", "phpsessid", "jsessionid"}

        for cookie_str in raw_set_cookies:
            cookie_obj = SimpleCookie()
            try:
                cookie_obj.load(cookie_str)
            except Exception:
                continue

            cookie_lower = cookie_str.lower()

            for key, morsel in cookie_obj.items():
                is_secure = "secure" in cookie_lower
                is_httponly = "httponly" in cookie_lower
                has_samesite = "samesite" in cookie_lower
                samesite_val = ""
                if "samesite=strict" in cookie_lower:
                    samesite_val = "Strict"
                elif "samesite=lax" in cookie_lower:
                    samesite_val = "Lax"
                elif "samesite=none" in cookie_lower:
                    samesite_val = "None"

                is_likely_session = any(w in key.lower() for w in session_keywords)
                domain_val = morsel.get("domain", "").strip()
                path_val = morsel.get("path", "").strip()

                # Check 1: Prefix Validation (__Host- and __Secure-)
                if key.startswith("__Host-"):
                    violations = []
                    if not is_secure or target.scheme != "https":
                        violations.append("missing 'Secure' attribute over HTTPS")
                    if domain_val:
                        violations.append(f"specifies Domain='{domain_val}' (must NOT define Domain)")
                    if path_val != "/":
                        violations.append(f"Path='{path_val or '(omitted)'}' (must be Path=/)")
                    
                    if violations:
                        evidence = Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary=f"Cookie '{key}' uses '__Host-' prefix but violates RFC 6265bis specifications: {'; '.join(violations)}.",
                            response={"set_cookie": cookie_str, "cookie_name": key, "violations": violations}
                        )
                        findings.append(
                            self.create_finding(
                                target=target,
                                title=f"Invalid Cookie Prefix: '__Host-' Specification Violation on '{key}'",
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                status=ObservationStatus.CONFIRMED,
                                description=f"The cookie '{key}' uses the '__Host-' security prefix but violates prefix rules: {', '.join(violations)}.",
                                impact_explanation="Modern browsers will reject this cookie, breaking authentication and session persistence for users.",
                                remediation=f"For '__Host-{key[7:]}', ensure: (1) Transmitted over HTTPS, (2) '; Secure' is set, (3) '; Path=/' is set, and (4) 'Domain=' is completely omitted.",
                                verification_command=f"curl -sI {target.normalized_url} | grep -i Set-Cookie",
                                evidence=evidence,
                                category=Category.COOKIE_SECURITY,
                                cwe_id="CWE-1275"
                            )
                        )
                elif key.startswith("__Secure-"):
                    violations = []
                    if not is_secure or target.scheme != "https":
                        violations.append("missing 'Secure' attribute over HTTPS")
                    if violations:
                        evidence = Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary=f"Cookie '{key}' uses '__Secure-' prefix without the 'Secure' attribute over HTTPS.",
                            response={"set_cookie": cookie_str, "cookie_name": key}
                        )
                        findings.append(
                            self.create_finding(
                                target=target,
                                title=f"Invalid Cookie Prefix: '__Secure-' Specification Violation on '{key}'",
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                status=ObservationStatus.CONFIRMED,
                                description=f"The cookie '{key}' uses the '__Secure-' prefix but lacks the 'Secure' attribute.",
                                impact_explanation="Modern browsers reject '__Secure-' prefixed cookies that are missing the Secure flag.",
                                remediation=f"Append '; Secure' to the Set-Cookie directive for '{key}' and serve only over HTTPS.",
                                verification_command=f"curl -sI {target.normalized_url} | grep -i Set-Cookie",
                                evidence=evidence,
                                category=Category.COOKIE_SECURITY,
                                cwe_id="CWE-1275"
                            )
                        )

                # Check 2: Missing Secure Flag on HTTPS
                if target.scheme == "https" and not is_secure:
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"Cookie '{key}' is set over HTTPS without the 'Secure' attribute.",
                        response={"set_cookie": cookie_str, "cookie_name": key}
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title=f"Insecure Cookie: Missing 'Secure' Attribute on '{key}'",
                            severity=Severity.MEDIUM if not is_likely_session else Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description=f"Cookie '{key}' was transmitted without the 'Secure' flag.",
                            impact_explanation="Browsers will send this cookie over unencrypted HTTP connections if any link or asset is loaded insecurely, enabling network eavesdropping.",
                            remediation=f"Append '; Secure' to the Set-Cookie directive for '{key}'.\n\nFramework Examples:\n• Express.js: res.cookie('{key}', val, {{ secure: true, httpOnly: true, sameSite: 'lax' }})\n• Django: SESSION_COOKIE_SECURE = True\n• FastAPI / Starlette: response.set_cookie(key='{key}', value=val, secure=True, httponly=True, samesite='lax')",
                            verification_command=f"curl -sI {target.normalized_url} | grep -i Set-Cookie",
                            evidence=evidence,
                            category=Category.COOKIE_SECURITY,
                            cwe_id="CWE-614"
                        )
                    )

                # Check 3: Missing HttpOnly Flag
                if not is_httponly:
                    sev = Severity.MEDIUM if is_likely_session else Severity.LOW
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"Cookie '{key}' lacks the 'HttpOnly' flag.",
                        response={"set_cookie": cookie_str, "cookie_name": key}
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title=f"Insecure Cookie: Missing 'HttpOnly' Attribute on '{key}'",
                            severity=sev,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description=f"Cookie '{key}' lacks the 'HttpOnly' attribute.",
                            impact_explanation="Client-side JavaScript can read this cookie value via document.cookie, exposing it to exfiltration via Cross-Site Scripting (XSS).",
                            remediation=f"Append '; HttpOnly' to the Set-Cookie directive for '{key}'.\n\nFramework Examples:\n• Express.js: res.cookie('{key}', val, {{ httpOnly: true, secure: true }})\n• Django: SESSION_COOKIE_HTTPONLY = True\n• Next.js / Route Handler: cookies().set('{key}', val, {{ httpOnly: true, secure: true }})",
                            verification_command=f"curl -sI {target.normalized_url} | grep -i Set-Cookie",
                            evidence=evidence,
                            category=Category.COOKIE_SECURITY,
                            cwe_id="CWE-1004"
                        )
                    )

                # Check 4: Missing or Ineffective SameSite Flag
                if not has_samesite:
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"Cookie '{key}' does not define a 'SameSite' attribute.",
                        response={"set_cookie": cookie_str, "cookie_name": key}
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title=f"Insecure Cookie: Missing 'SameSite' Attribute on '{key}'",
                            severity=Severity.LOW if not is_likely_session else Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description=f"Cookie '{key}' does not declare a SameSite attribute.",
                            impact_explanation="Without SameSite, cookies are attached to cross-origin requests, leaving endpoints vulnerable to Cross-Site Request Forgery (CSRF).",
                            remediation=f"Append '; SameSite=Lax' (or SameSite=Strict) to the Set-Cookie directive for '{key}'.",
                            verification_command=f"curl -sI {target.normalized_url} | grep -i Set-Cookie",
                            evidence=evidence,
                            category=Category.COOKIE_SECURITY,
                            cwe_id="CWE-1275"
                        )
                    )
                elif samesite_val == "None" and not is_secure:
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"Cookie '{key}' specifies SameSite=None without Secure attribute.",
                        response={"set_cookie": cookie_str, "cookie_name": key}
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title=f"Invalid Cookie: SameSite=None Without Secure on '{key}'",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            description=f"The cookie '{key}' specifies 'SameSite=None' but is missing 'Secure'. Modern standards reject SameSite=None cookies unless accompanied by the Secure flag.",
                            impact_explanation="Browsers will reject this cookie entirely in cross-site contexts, potentially breaking legitimate user sessions.",
                            remediation=f"Ensure '; Secure' is included whenever '; SameSite=None' is declared.",
                            verification_command=f"curl -sI {target.normalized_url} | grep -i Set-Cookie",
                            evidence=evidence,
                            category=Category.COOKIE_SECURITY,
                            cwe_id="CWE-1275"
                        )
                    )

                # Check 5: Suspicious Cookie Scope (Domain & Path)
                if domain_val:
                    clean_domain = domain_val.lstrip(".")
                    if target.host != clean_domain and target.host.endswith("." + clean_domain):
                        evidence = Evidence(
                            type=EvidenceType.HTTP_EXCHANGE,
                            summary=f"Cookie '{key}' is scoped broadly to parent domain '{domain_val}' rather than '{target.host}'.",
                            response={"set_cookie": cookie_str, "cookie_name": key, "cookie_domain": domain_val}
                        )
                        findings.append(
                            self.create_finding(
                                target=target,
                                title=f"Suspicious Cookie Scope: Broad Domain Scope on '{key}'",
                                severity=Severity.LOW if not is_likely_session else Severity.MEDIUM,
                                confidence=Confidence.CONFIRMED,
                                status=ObservationStatus.CONFIRMED,
                                description=f"Cookie '{key}' specifies Domain='{domain_val}', exposing it to all sibling subdomains under '{clean_domain}'.",
                                impact_explanation="If any sibling subdomain is compromised or hosts user content, attackers can read or tamper with this cookie.",
                                remediation=f"Omit the 'Domain' attribute so the cookie defaults strictly to the origin host '{target.host}'.",
                                verification_command=f"curl -sI {target.normalized_url} | grep -i Set-Cookie",
                                evidence=evidence,
                                category=Category.COOKIE_SECURITY,
                                cwe_id="CWE-287"
                            )
                        )

                # Positive Control Check: Fully Hardened Cookie
                if is_secure and is_httponly and has_samesite and samesite_val in ("Lax", "Strict"):
                    evidence = Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"Cookie '{key}' is fully hardened with Secure, HttpOnly, and SameSite={samesite_val}.",
                        response={"set_cookie": cookie_str, "cookie_name": key}
                    )
                    findings.append(
                        self.create_finding(
                            target=target,
                            title=f"Hardened Cookie Security: '{key}' Enforces Defense-in-Depth",
                            severity=Severity.INFO,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.OBSERVED,
                            description=f"The cookie '{key}' is properly configured with Secure, HttpOnly, and SameSite={samesite_val}.",
                            impact_explanation="Protects against packet sniffing, XSS exfiltration, and CSRF request forgery.",
                            remediation="Maintain these security flags across all newly issued cookies.",
                            verification_command=f"curl -sI {target.normalized_url} | grep -i Set-Cookie",
                            evidence=evidence,
                            category=Category.COOKIE_SECURITY
                        )
                    )

        return findings
