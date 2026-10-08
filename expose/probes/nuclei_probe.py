"""Isolated Nuclei-compatible exposure scanner probe for Expose (Phase 6).

Executes approved, strictly non-destructive template operations for external exposure detection
and normalizes results into standardized Expose findings with verifiable empirical evidence.
"""

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
from expose.probes.base import BaseProbe


EXPOSURE_TEMPLATES = [
    # 1. Source control & sensitive repository files
    ("/.git/config", "[core]", "Git Configuration (.git/config) File Exposed", Severity.HIGH, "CWE-200", None, "Publicly accessible .git/config file leaking repository branches, remotes, and commit metadata.", "Block public access to .git directories and hidden files at your web server or CDN level."),
    ("/.git/HEAD", "ref: refs/", "Git Repository Root (.git/HEAD) Exposed", Severity.CRITICAL, "CWE-200", None, "Publicly accessible .git/HEAD file indicates entire source repository history is downloadable.", "Block all web requests matching /.git/* at the reverse proxy or web server."),
    ("/.svn/entries", "dir\n", "SVN Metadata (.svn/entries) File Exposed", Severity.MEDIUM, "CWE-200", None, "Exposed SVN directory metadata reveals repository structure and file names.", "Block public access to .svn directories in web server configuration."),
    ("/.DS_Store", "Bud1", "macOS .DS_Store Metadata File Exposed", Severity.LOW, "CWE-200", None, "Public .DS_Store file reveals directory contents and hidden filenames.", "Remove .DS_Store files and configure server rules to deny access."),
    
    # 2. Configuration & environment files
    ("/.env", "=", "Environment (.env) Configuration File Exposed", Severity.CRITICAL, "CWE-200", "CVE-2017-9841", "Publicly accessible .env configuration file leaking database passwords, API secret keys, and environment variables.", "Remove .env files from the web root and configure your web server to block all hidden (.*) files."),
    ("/.env.local", "=", "Local Environment (.env.local) File Exposed", Severity.CRITICAL, "CWE-200", None, "Publicly accessible local environment file containing development secrets and API keys.", "Block access to all .env* patterns in web server configuration."),
    ("/.env.production", "=", "Production Environment (.env.production) File Exposed", Severity.CRITICAL, "CWE-200", None, "Publicly accessible production environment file leaking live database credentials and tokens.", "Block access to all .env* patterns immediately."),
    ("/config.json", "database", "Configuration File (config.json) Exposed", Severity.HIGH, "CWE-200", None, "Unprotected config.json file containing application configuration or connection strings.", "Move config.json outside public web root."),
    ("/wp-config.php.bak", "DB_PASSWORD", "WordPress Configuration Backup (wp-config.php.bak) Exposed", Severity.CRITICAL, "CWE-200", None, "Backup WordPress configuration file exposing plaintext database credentials and auth salts.", "Delete .bak files from public web directories immediately."),
    
    # 3. Project manifests and infrastructure
    ("/package.json", '"dependencies"', "Node.js Manifest (package.json) Exposed", Severity.LOW, "CWE-200", None, "Publicly accessible package.json discloses exact frontend/backend dependency tree and versions.", "Move package.json outside public document root."),
    ("/composer.json", '"require"', "PHP Composer Manifest (composer.json) Exposed", Severity.LOW, "CWE-200", None, "Publicly accessible composer.json exposes PHP library versions and vendor dependencies.", "Block access to composer.json at the web server."),
    ("/Dockerfile", "FROM ", "Docker Build Specification (Dockerfile) Exposed", Severity.MEDIUM, "CWE-200", None, "Exposed Dockerfile reveals base images, internal build layers, and environment setups.", "Exclude Dockerfiles from production public assets."),
    ("/docker-compose.yml", "services:", "Docker Compose Configuration Exposed", Severity.HIGH, "CWE-200", None, "Docker compose file discloses internal network topology, service names, and port mappings.", "Prevent deployment of orchestration files into web directories."),
    
    # 4. Database dumps and archives
    ("/dump.sql", "CREATE TABLE", "Database SQL Dump (dump.sql) Exposed", Severity.CRITICAL, "CWE-200", None, "Public SQL database dump file leaking full table schemas and raw records.", "Delete database dump files from the public web root immediately."),
    ("/backup.sql", "CREATE TABLE", "Database Backup (backup.sql) Exposed", Severity.CRITICAL, "CWE-200", None, "Public database backup dump exposed to unauthenticated downloads.", "Remove database backup files from public web directories."),
    ("/db.sql", "INSERT INTO", "Database Dump (db.sql) Exposed", Severity.CRITICAL, "CWE-200", None, "Raw SQL dump accessible over public HTTP.", "Delete SQL files from public web directories."),
    
    # 5. Spring Boot Actuators & Metrics
    ("/actuator/env", "activeProfiles", "Spring Boot Actuator Environment (/actuator/env) Exposed", Severity.CRITICAL, "CWE-200", None, "Spring Boot Actuator env endpoint exposes system properties, environment variables, and config keys.", "Secure Spring Boot Actuator endpoints with Spring Security or disable management.endpoints.web.exposure.include=*."),
    ("/actuator/heapdump", None, "Spring Boot Actuator Heapdump (/actuator/heapdump) Exposed", Severity.CRITICAL, "CWE-200", None, "JVM heap dump endpoint accessible without authentication, allowing full memory inspection.", "Disable or restrict /actuator/heapdump endpoint to authenticated administrative users."),
    ("/actuator/health", '"status"', "Spring Boot Actuator Health (/actuator/health) Exposed", Severity.INFO, "CWE-200", None, "Spring Boot Actuator health endpoint is publicly accessible.", "Restrict actuator health endpoint to internal network monitoring if sensitive health metrics are included."),
    ("/actuator/prometheus", None, "Spring Boot Prometheus (/actuator/prometheus) Exposed", Severity.LOW, "CWE-200", None, "Prometheus metrics endpoint reveals internal JVM and request rates.", "Restrict Prometheus endpoints to internal monitoring VPCs."),
    ("/metrics", None, "Prometheus Metrics Endpoint (/metrics) Exposed", Severity.LOW, "CWE-200", None, "Unauthenticated /metrics endpoint exposes system performance and process metrics.", "Protect /metrics behind authentication or reverse-proxy access control."),
    
    # 6. Debug Panels & Framework Diagnostics
    ("/_ignition/health-check", None, "Laravel Ignition Diagnostic Page Exposed", Severity.MEDIUM, "CWE-200", None, "Laravel Ignition error handler / diagnostic tool is accessible in production.", "Set APP_DEBUG=false in production .env configuration."),
    ("/telescope", "Telescope", "Laravel Telescope Debug Dashboard Exposed", Severity.MEDIUM, "CWE-200", None, "Laravel Telescope debug dashboard is publicly viewable without authentication.", "Restrict Telescope access in TelescopeServiceProvider authorization gate."),
    ("/phpinfo.php", "PHP Version", "PHPInfo Diagnostic Page (/phpinfo.php) Exposed", Severity.MEDIUM, "CWE-200", None, "phpinfo() output exposes complete PHP configuration, module versions, and server environment variables.", "Delete phpinfo diagnostic scripts from production environments."),
    ("/server-status", "Apache Server Status", "Server Status Monitoring Page Exposed", Severity.LOW, "CWE-200", None, "The Apache mod_status endpoint is publicly exposed without authentication.", "Restrict access to /server-status to internal loopback interfaces (127.0.0.1) or disable mod_status."),
    ("/elmah.axd", "Error Log for", "ASP.NET ELMAH Error Log (/elmah.axd) Exposed", Severity.HIGH, "CWE-200", None, "ELMAH diagnostic error logging dashboard is publicly exposed, leaking stack traces and parameters.", "Restrict elmah.axd in web.config using authorization role filters."),
    
    # 7. API Documentation & OpenAPI Definitions
    ("/openapi.json", "openapi", "OpenAPI Specification (/openapi.json) Exposed", Severity.INFO, "CWE-200", None, "OpenAPI specification document publicly accessible, detailing all API routes and schemas.", "Ensure all documented endpoints enforce proper server-side authentication."),
    ("/v2/api-docs", "swagger", "Swagger 2.0 API Documentation (/v2/api-docs) Exposed", Severity.INFO, "CWE-200", None, "Swagger API definitions publicly accessible without authentication.", "Ensure internal administrative endpoints are not published publicly without auth."),
    ("/swagger-ui.html", "swagger-ui", "Swagger UI Interactive Console Exposed", Severity.INFO, "CWE-200", None, "Interactive Swagger UI dashboard is accessible in production.", "Disable Swagger UI in production builds or restrict behind administrative SSO."),
]

# Paths where HTML response is genuinely expected (rather than an SPA 404 fallback)
HTML_EXPECTED_PATHS = {
    "/server-status",
    "/telescope",
    "/_ignition/health-check",
    "/swagger-ui.html",
    "/elmah.axd",
    "/phpinfo.php",
}


class NucleiProbe(BaseProbe):
    """Executes approved non-intrusive exposure templates with strict evidence normalization."""

    @property
    def name(self) -> str:
        return "nuclei_exposure_probe"

    @property
    def category(self) -> Category:
        return Category.EXTERNAL_EXPOSURE

    @property
    def description(self) -> str:
        return "Detects exposed sensitive files, git repositories, backups, and configuration leaks."

    async def execute(self, target: TargetScope) -> List[Finding]:
        findings: List[Finding] = []
        base_url = target.normalized_url.rstrip("/")

        async with httpx.AsyncClient(
            timeout=5.0,
            verify=False,
            follow_redirects=False,
            headers={"User-Agent": "Expose-Security-Scanner/1.0 (Approved Template Runner)"}
        ) as client:
            for path, match_str, title, sev, cwe, cve, desc, remed in EXPOSURE_TEMPLATES:
                url = f"{base_url}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        body_lower = resp.text.lower()
                        is_html = "<html" in body_lower or "<!doctype html" in body_lower

                        # SPA False-Positive Guard: Reject HTML responses on non-HTML sensitive paths
                        if is_html and path not in HTML_EXPECTED_PATHS:
                            continue

                        # String match check
                        if match_str and match_str not in resp.text:
                            continue

                        # Extra check for .env files: ensure not returning empty or generic non-env content
                        if path.startswith("/.env") and not any(line and "=" in line for line in resp.text.splitlines()[:20]):
                            continue

                        body_sample = resp.text[:200]
                        evidence = Evidence(
                            type=EvidenceType.NUCLEI_MATCH,
                            summary=f"HTTP 200 OK returned for {url}",
                            matched_data=body_sample,
                            command=f"curl -sIL '{url}'",
                            response={"status_code": 200, "url": url}
                        )
                        findings.append(self.create_finding(
                            target=target,
                            title=title,
                            severity=sev,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.CONFIRMED,
                            category=Category.EXTERNAL_EXPOSURE if sev in (Severity.CRITICAL, Severity.HIGH) else Category.INFORMATION_DISCLOSURE,
                            description=desc,
                            impact_explanation="Exposing administrative, environment, or backup data accelerates reconnaissance and direct compromise.",
                            remediation=remed,
                            verification_command=f"curl -sIL '{url}'",
                            evidence=evidence,
                            cwe_id=cwe,
                            cve_id=cve,
                        ))
                except Exception:
                    pass

        return findings

