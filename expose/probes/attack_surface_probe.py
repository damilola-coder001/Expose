"""Attack Surface Discovery Probe for Expose (Phase 8).

Discovers publicly observable:
- Pages
- Endpoints
- Forms
- Scripts
- API references
- Robots.txt
- Sitemap
- Public resources
- Third-party resources

Builds the internal asset model:
Target
 ├── Pages
 ├── APIs
 ├── Assets
 ├── Scripts
 └── External dependencies
"""

import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
import httpx

from expose.core.attack_surface import (
    APIAsset,
    AttackSurface,
    ExternalDependency,
    FormAsset,
    FormInput,
    PageAsset,
    RobotsTxtAsset,
    ScriptAsset,
    StaticAsset,
)
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


class AttackSurfaceProbe(BaseProbe):
    """Discovers and catalogs publicly observable attack surface assets."""

    @property
    def name(self) -> str:
        return "attack_surface"

    @property
    def category(self) -> Category:
        return Category.ATTACK_SURFACE

    @property
    def description(self) -> str:
        return "Maps publicly exposed pages, APIs, forms, scripts, robots.txt, sitemaps, and third-party dependencies."

    async def execute(self, target: TargetScope) -> List[Finding]:
        findings, _ = await self.discover_attack_surface(target)
        return findings

    async def discover_attack_surface(self, target: TargetScope) -> Tuple[List[Finding], AttackSurface]:
        findings: List[Finding] = []
        base_url = target.normalized_url
        root_host = target.host.lower()

        pages: List[PageAsset] = []
        apis: List[APIAsset] = []
        assets: List[StaticAsset] = []
        scripts: List[ScriptAsset] = []
        forms: List[FormAsset] = []
        external_map: Dict[str, Dict[str, any]] = {}
        sitemaps_list: List[str] = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Expose-Security-Intelligence/1.0 (Attack Surface Mapper)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
            # 1. Fetch Root Page
            root_html = ""
            try:
                resp = await client.get(base_url, headers=headers)
                root_html = resp.text
                pages.append(PageAsset(
                    url=str(resp.url),
                    path=urlparse(str(resp.url)).path or "/",
                    title=self._extract_title(root_html),
                    status_code=resp.status_code,
                    is_internal=True,
                    discovered_via="root_crawl"
                ))
            except Exception as e:
                return findings, AttackSurface(target=base_url, exposure_summary=f"Could not reach target: {e}")

            # 2. Inspect robots.txt
            robots_url = urljoin(base_url, "/robots.txt")
            robots_asset = RobotsTxtAsset()
            try:
                r_resp = await client.get(robots_url, headers=headers)
                if r_resp.status_code == 200 and "user-agent" in r_resp.text.lower():
                    robots_asset.is_present = True
                    for line in r_resp.text.splitlines():
                        line = line.strip()
                        if line.startswith("#") or not line:
                            continue
                        lower = line.lower()
                        if lower.startswith("disallow:"):
                            parts = line.split(":", 1)
                            if len(parts) > 1 and parts[1].strip():
                                path = parts[1].strip()
                                robots_asset.disallowed_paths.append(path)
                        elif lower.startswith("allow:"):
                            parts = line.split(":", 1)
                            if len(parts) > 1 and parts[1].strip():
                                robots_asset.allowed_paths.append(parts[1].strip())
                        elif lower.startswith("sitemap:"):
                            parts = line.split(":", 1)
                            if len(parts) > 1 and parts[1].strip():
                                sitemap_url = parts[1].strip()
                                robots_asset.sitemaps.append(sitemap_url)
                                sitemaps_list.append(sitemap_url)

                    # Flag sensitive disallowed paths that expose administrative endpoints
                    sensitive_disallowed = [
                        p for p in robots_asset.disallowed_paths
                        if any(s in p.lower() for s in ("admin", "backup", "secret", "private", "internal", "config", "debug"))
                    ]
                    if sensitive_disallowed:
                        findings.append(self.create_finding(
                            target=target,
                            title=f"Sensitive Paths Disclosed in robots.txt ({', '.join(sensitive_disallowed[:3])})",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            status=ObservationStatus.OBSERVED,
                            category=Category.INFORMATION_EXPOSURE,
                            description=f"robots.txt explicitly lists sensitive internal paths: {', '.join(sensitive_disallowed)}.",
                            impact_explanation="Search engines respect Disallow rules, but adversaries use robots.txt as an attack map to locate unlinked admin consoles and internal endpoints.",
                            remediation="Do not rely on robots.txt for access control. Enforce server-side authentication and restrict administrative consoles at the reverse proxy.",
                            evidence=Evidence(
                                type=EvidenceType.HTTP_EXCHANGE,
                                summary=f"Disallowed paths found in robots.txt: {', '.join(sensitive_disallowed)}",
                                response={"status_code": 200, "disallowed_sample": sensitive_disallowed},
                                command=f"curl -sL {robots_url} | grep -i Disallow",
                            ),
                            verification_command=f"curl -sL {robots_url} | grep -i Disallow",
                            cwe_id="CWE-200"
                        ))
            except Exception:
                pass

            # 3. Inspect sitemap.xml
            if not sitemaps_list:
                sitemaps_list.append(urljoin(base_url, "/sitemap.xml"))

            for sm_url in sitemaps_list[:2]:
                try:
                    sm_resp = await client.get(sm_url, headers=headers)
                    if sm_resp.status_code == 200 and "<urlset" in sm_resp.text:
                        urls = re.findall(r'<loc>([^<]+)</loc>', sm_resp.text)
                        for u in urls[:25]:
                            p_path = urlparse(u).path
                            if not any(p.url == u for p in pages):
                                pages.append(PageAsset(
                                    url=u,
                                    path=p_path or "/",
                                    is_internal=root_host in u.lower(),
                                    discovered_via="sitemap"
                                ))
                except Exception:
                    pass

            # 4. Parse DOM Elements from Root HTML
            # A. Anchors / Pages
            for href in re.findall(r'<a\s+[^>]*href=["\']([^"\'#\s]+)["\']', root_html, re.IGNORECASE):
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.scheme in ("http", "https"):
                    is_int = (parsed.hostname or "").lower() == root_host
                    if not any(p.url == full_url for p in pages):
                        pages.append(PageAsset(
                            url=full_url,
                            path=parsed.path or "/",
                            is_internal=is_int,
                            discovered_via="html_anchor"
                        ))
                    if not is_int and parsed.hostname:
                        self._register_external(external_map, parsed.hostname, full_url)

            # B. Scripts
            for script_tag in re.finditer(r'<script\s+([^>]*)>(.*?)</script>', root_html, re.IGNORECASE | re.DOTALL):
                attrs = script_tag.group(1)
                src_match = re.search(r'src=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                has_sri = "integrity=" in attrs.lower()
                sri_match = re.search(r'integrity=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                sri_hash = sri_match.group(1) if sri_match else None

                if src_match:
                    src_url = urljoin(base_url, src_match.group(1))
                    parsed_src = urlparse(src_url)
                    is_ext = (parsed_src.hostname or "").lower() != root_host
                    cdn = self._classify_cdn(parsed_src.hostname) if is_ext else None

                    scripts.append(ScriptAsset(
                        url=src_url,
                        is_external=is_ext,
                        cdn_provider=cdn,
                        has_sri=has_sri,
                        sri_hash=sri_hash
                    ))

                    if is_ext and parsed_src.hostname:
                        self._register_external(external_map, parsed_src.hostname, src_url)

            # C. Assets (Stylesheets, Images, Icons)
            for link_tag in re.findall(r'<link\s+[^>]+>', root_html, re.IGNORECASE):
                href_match = re.search(r'href=["\']([^"\']+)["\']', link_tag, re.IGNORECASE)
                rel_match = re.search(r'rel=["\']([^"\']+)["\']', link_tag, re.IGNORECASE)
                if href_match:
                    asset_url = urljoin(base_url, href_match.group(1))
                    rel = rel_match.group(1).lower() if rel_match else "stylesheet"
                    atype = "stylesheet" if "stylesheet" in rel else ("icon" if "icon" in rel else "manifest")
                    parsed_a = urlparse(asset_url)
                    is_ext = (parsed_a.hostname or "").lower() != root_host

                    assets.append(StaticAsset(
                        url=asset_url,
                        asset_type=atype,
                        is_external=is_ext
                    ))
                    if is_ext and parsed_a.hostname:
                        self._register_external(external_map, parsed_a.hostname, asset_url)

            for img_src in re.findall(r'<img\s+[^>]*src=["\']([^"\']+)["\']', root_html, re.IGNORECASE):
                img_url = urljoin(base_url, img_src)
                parsed_img = urlparse(img_url)
                is_ext = (parsed_img.hostname or "").lower() != root_host
                assets.append(StaticAsset(
                    url=img_url,
                    asset_type="image",
                    is_external=is_ext
                ))
                if is_ext and parsed_img.hostname:
                    self._register_external(external_map, parsed_img.hostname, img_url)

            # D. Forms
            for form_match in re.finditer(r'<form\s+([^>]*)>(.*?)</form>', root_html, re.IGNORECASE | re.DOTALL):
                f_attrs = form_match.group(1)
                f_inner = form_match.group(2)

                act_match = re.search(r'action=["\']([^"\']*)["\']', f_attrs, re.IGNORECASE)
                act_url = urljoin(base_url, act_match.group(1) if act_match else "")
                method_match = re.search(r'method=["\']([^"\']*)["\']', f_attrs, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else "GET"

                inputs: List[FormInput] = []
                has_pw = False
                for inp_match in re.finditer(r'<input\s+([^>]+)>', f_inner, re.IGNORECASE):
                    i_attrs = inp_match.group(1)
                    t_match = re.search(r'type=["\']([^"\']*)["\']', i_attrs, re.IGNORECASE)
                    n_match = re.search(r'name=["\']([^"\']*)["\']', i_attrs, re.IGNORECASE)
                    i_type = t_match.group(1).lower() if t_match else "text"
                    i_name = n_match.group(1) if n_match else "unnamed"

                    is_sens = i_type in ("password", "token", "ssn", "creditcard") or any(
                        s in i_name.lower() for s in ("password", "passwd", "token", "secret", "cvv")
                    )
                    if i_type == "password":
                        has_pw = True

                    inputs.append(FormInput(
                        name=i_name,
                        input_type=i_type,
                        is_sensitive=is_sens
                    ))

                is_sec = not act_url.lower().startswith("http://")
                forms.append(FormAsset(
                    action=act_url,
                    method=method,
                    inputs=inputs,
                    has_password=has_pw,
                    is_secure_action=is_sec
                ))

            # E. API Endpoints Referenced in Scripts / HTML
            api_patterns = [
                re.compile(r'["\'](/api/v[0-9]+/[a-zA-Z0-9_\-/]+)["\']'),
                re.compile(r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']'),
                re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/]+)["\']'),
            ]
            seen_apis: Set[str] = set()
            for pattern in api_patterns:
                for match in pattern.findall(root_html):
                    if match not in seen_apis and not match.endswith(".js") and not match.endswith(".css"):
                        seen_apis.add(match)
                        apis.append(APIAsset(
                            path=match,
                            method="ANY",
                            is_public=True
                        ))

            # Assemble External Dependencies List
            external_deps = [
                ExternalDependency(
                    origin=origin,
                    category=meta["category"],
                    resource_count=meta["count"],
                    sample_urls=meta["samples"][:3]
                )
                for origin, meta in external_map.items()
            ]

            # Construct Human-Readable Exposure Statement
            summary = (
                f"Website exposes {len(pages)} Page(s), {len(apis)} API Endpoint(s), "
                f"{len(assets)} Static Resource(s), {len(scripts)} JavaScript Bundle(s), "
                f"{len(forms)} Submission Form(s), and relies on {len(external_deps)} External Third-Party Origin(s)."
            )

            attack_surface = AttackSurface(
                target=base_url,
                pages=pages,
                apis=apis,
                assets=assets,
                scripts=scripts,
                forms=forms,
                external_dependencies=external_deps,
                robots_txt=robots_asset,
                sitemaps=sitemaps_list,
                exposure_summary=summary
            )

            # Generate Neutral Finding Cataloging the Public Attack Surface
            findings.append(self.create_finding(
                target=target,
                title="Public Attack Surface Inventory Completed",
                severity=Severity.INFO,
                confidence=Confidence.INFORMATIONAL,
                status=ObservationStatus.OBSERVED,
                category=Category.ATTACK_SURFACE,
                description=summary,
                impact_explanation="Cataloging publicly exposed pages, APIs, forms, and external dependencies defines the security perimeter for defense-in-depth reviews.",
                remediation="Ensure all exposed endpoints enforce proper access controls and external dependencies are pinned with Subresource Integrity.",
                evidence=Evidence(
                    type=EvidenceType.DOM_CONTENT,
                    summary=summary,
                    raw_data={
                        "pages_count": len(pages),
                        "apis_count": len(apis),
                        "assets_count": len(assets),
                        "scripts_count": len(scripts),
                        "forms_count": len(forms),
                        "third_party_origins": [d.origin for d in external_deps],
                    }
                ),
                verification_command=f"curl -sL {base_url} | grep -Eo '(href|src)=\"[^\"]+\"' | head -n 20"
            ))

            return findings, attack_surface

    def _extract_title(self, html: str) -> str:
        m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else "Untitled Document"

    def _register_external(self, external_map: Dict[str, any], origin: str, url: str) -> None:
        clean_origin = origin.lower()
        if clean_origin not in external_map:
            external_map[clean_origin] = {
                "category": self._classify_external_origin(clean_origin),
                "count": 0,
                "samples": []
            }
        external_map[clean_origin]["count"] += 1
        if url not in external_map[clean_origin]["samples"]:
            external_map[clean_origin]["samples"].append(url)

    def _classify_external_origin(self, origin: str) -> str:
        if any(c in origin for c in ("cdn", "unpkg", "jsdelivr", "cloudflare", "static")):
            return "CDN"
        if any(a in origin for a in ("analytics", "segment", "mixpanel", "hotjar", "clarity", "sentry")):
            return "Analytics"
        if any(f in origin for f in ("fonts", "typekit")):
            return "Fonts"
        if any(s in origin for s in ("facebook", "twitter", "linkedin", "instagram", "tiktok")):
            return "Social"
        if any(ad in origin for ad in ("doubleclick", "adservice", "googleadservices", "ads")):
            return "Advertising"
        if any(auth in origin for auth in ("firebase", "auth0", "okta", "cognito")):
            return "Authentication"
        return "Third-Party Service"

    def _classify_cdn(self, host: Optional[str]) -> Optional[str]:
        if not host:
            return None
        host_lower = host.lower()
        if "cloudflare" in host_lower:
            return "Cloudflare"
        if "jsdelivr" in host_lower:
            return "jsDelivr"
        if "unpkg" in host_lower:
            return "unpkg"
        if "cdnjs" in host_lower:
            return "cdnjs"
        if "googleapis" in host_lower:
            return "Google Hosted Libraries"
        return "External CDN"
