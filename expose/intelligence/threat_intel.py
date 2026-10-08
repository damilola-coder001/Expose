"""Live Threat Intelligence Feed Sync & CISA KEV Exploitation Engine (Phase 34).

Ingests, caches, and correlates real-time CVE exploit streams from the
CISA Known Exploited Vulnerabilities (KEV) catalog against software versions
observed during external website audits.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    ObservationStatus,
    Severity,
)
from expose.core.safety import create_safe_async_client

logger = logging.getLogger("expose.threat_intel")

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_PATH = Path.home() / ".expose" / "cisa_kev_cache.json"

# Curated benchmark of critical in-the-wild zero-days and active KEV entries for offline/airgapped fallback
BUNDLED_KEV_FALLBACK = [
    {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Apache Log4j Remote Code Execution Vulnerability (Log4Shell)",
        "dateAdded": "2021-12-10",
        "shortDescription": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "requiredAction": "Apply updates per vendor instructions or mitigate per CISA guidelines.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
    },
    {
        "cveID": "CVE-2023-38606",
        "vendorProject": "Apple",
        "product": "iOS and macOS",
        "vulnerabilityName": "Apple Multiple Products Memory Corruption Vulnerability",
        "dateAdded": "2023-07-26",
        "shortDescription": "Apple iOS and macOS contain a memory corruption vulnerability allowing app state modification.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2023-08-16",
        "knownRansomwareCampaignUse": "Unknown",
    },
    {
        "cveID": "CVE-2023-48788",
        "vendorProject": "Fortinet",
        "product": "FortiClient EMS",
        "vulnerabilityName": "Fortinet FortiClient EMS SQL Injection Vulnerability",
        "dateAdded": "2024-03-25",
        "shortDescription": "Improper neutralization of special elements used in an SQL command in Fortinet FortiClient EMS allows unauthenticated remote code execution.",
        "requiredAction": "Apply vendor updates immediately.",
        "dueDate": "2024-04-15",
        "knownRansomwareCampaignUse": "Known",
    },
    {
        "cveID": "CVE-2023-22515",
        "vendorProject": "Atlassian",
        "product": "Confluence Data Center and Server",
        "vulnerabilityName": "Atlassian Confluence Broken Access Control Vulnerability",
        "dateAdded": "2023-10-05",
        "shortDescription": "Atlassian Confluence contains a broken access control vulnerability allowing unauthenticated admin account creation.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2023-10-26",
        "knownRansomwareCampaignUse": "Known",
    },
    {
        "cveID": "CVE-2022-22965",
        "vendorProject": "Spring",
        "product": "Framework",
        "vulnerabilityName": "Spring Framework Remote Code Execution Vulnerability (Spring4Shell)",
        "dateAdded": "2022-04-04",
        "shortDescription": "Spring Framework RCE via data binding on JDK 9+ allowing complete system compromise.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2022-04-25",
        "knownRansomwareCampaignUse": "Known",
    },
    {
        "cveID": "CVE-2021-41773",
        "vendorProject": "Apache",
        "product": "HTTP Server",
        "vulnerabilityName": "Apache HTTP Server Path Traversal Vulnerability",
        "dateAdded": "2021-11-03",
        "shortDescription": "A flaw in path normalization in Apache HTTP Server 2.4.49 allows unauthenticated remote attackers to map URLs to files outside the document root.",
        "requiredAction": "Update to Apache HTTP Server 2.4.51 or later.",
        "dueDate": "2021-11-17",
        "knownRansomwareCampaignUse": "Known",
    },
    {
        "cveID": "CVE-2024-3400",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
        "dateAdded": "2024-04-12",
        "shortDescription": "Command injection in the GlobalProtect feature of PAN-OS allows an unauthenticated attacker to execute arbitrary code with root privileges.",
        "requiredAction": "Apply mitigations per vendor advisory.",
        "dueDate": "2024-04-19",
        "knownRansomwareCampaignUse": "Known",
    },
]


class CisaKevVulnerability(BaseModel):
    """Normalized CISA KEV Vulnerability record."""
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_campaign_use: str


class ThreatIntelStore:
    """Indexed store of active in-the-wild threat intelligence."""

    def __init__(self):
        self._cve_map: Dict[str, CisaKevVulnerability] = {}
        self._product_index: Dict[str, List[CisaKevVulnerability]] = {}
        self.last_sync_time: Optional[datetime] = None
        self._load_initial()

    def _load_initial(self):
        """Loads cached feed or fallback dataset."""
        if CACHE_PATH.exists():
            try:
                with open(CACHE_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    vulns = data.get("vulnerabilities", [])
                    self._populate(vulns)
                    self.last_sync_time = datetime.fromisoformat(data.get("synced_at", datetime.now(timezone.utc).isoformat()))
                    return
            except Exception as e:
                logger.warning("Failed loading KEV cache: %s. Using bundled fallback.", e)

        self._populate(BUNDLED_KEV_FALLBACK)
        self.last_sync_time = datetime.now(timezone.utc)

    def _populate(self, raw_list: List[dict]):
        self._cve_map.clear()
        self._product_index.clear()
        for item in raw_list:
            cve = item.get("cveID") or item.get("cve_id")
            if not cve:
                continue
            vuln = CisaKevVulnerability(
                cve_id=cve,
                vendor_project=item.get("vendorProject") or item.get("vendor_project", "Unknown"),
                product=item.get("product", "Unknown"),
                vulnerability_name=item.get("vulnerabilityName") or item.get("vulnerability_name", ""),
                date_added=item.get("dateAdded") or item.get("date_added", ""),
                short_description=item.get("shortDescription") or item.get("short_description", ""),
                required_action=item.get("requiredAction") or item.get("required_action", ""),
                due_date=item.get("dueDate") or item.get("due_date", ""),
                known_ransomware_campaign_use=item.get("knownRansomwareCampaignUse") or item.get("known_ransomware_campaign_use", "Unknown"),
            )
            self._cve_map[cve] = vuln
            key = f"{vuln.vendor_project.lower()} {vuln.product.lower()}"
            if key not in self._product_index:
                self._product_index[key] = []
            self._product_index[key].append(vuln)

    async def sync_live_feed(self) -> Tuple[bool, str, int]:
        """Downloads and refreshes the official CISA KEV catalog."""
        try:
            async with create_safe_async_client(allow_private=False, timeout=12.0) as client:
                res = await client.get(CISA_KEV_FEED_URL)
                if res.status_code == 200:
                    data = res.json()
                    vulns = data.get("vulnerabilities", [])
                    self._populate(vulns)
                    self.last_sync_time = datetime.now(timezone.utc)

                    # Persist cache
                    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
                    with open(CACHE_PATH, "w", encoding="utf-8") as f:
                        json.dump({
                            "synced_at": self.last_sync_time.isoformat(),
                            "count": len(vulns),
                            "vulnerabilities": vulns,
                        }, f)

                    return True, f"Successfully synchronized {len(vulns)} KEV vulnerabilities from CISA.", len(vulns)
                return False, f"CISA KEV endpoint returned HTTP {res.status_code}", len(self._cve_map)
        except Exception as e:
            return False, f"Failed syncing CISA KEV feed: {str(e)}", len(self._cve_map)

    def search_by_product(self, query: str) -> List[CisaKevVulnerability]:
        """Searches KEV index for vulnerabilities affecting a software name or product."""
        q = query.lower().strip()
        matches = []
        for key, vulns in self._product_index.items():
            if q in key or any(q in v.product.lower() or q in v.vendor_project.lower() for v in vulns):
                matches.extend(vulns)
        return matches

    def get_cve(self, cve_id: str) -> Optional[CisaKevVulnerability]:
        return self._cve_map.get(cve_id.upper())

    @property
    def total_count(self) -> int:
        return len(self._cve_map)


# Global singleton instance
_GLOBAL_THREAT_INTEL = ThreatIntelStore()


def get_threat_intel() -> ThreatIntelStore:
    return _GLOBAL_THREAT_INTEL


class ThreatIntelCorrelator:
    """Correlates observed server software signatures against active KEV exploits."""

    @staticmethod
    def correlate_software_banner(banner: str, target_url: str) -> List[Finding]:
        """Analyzes an HTTP Server banner or technology fingerprint against CISA KEV."""
        store = get_threat_intel()
        findings: List[Finding] = []
        clean_banner = banner.strip()

        # Identify software and version (e.g. "Apache/2.4.49", "nginx/1.18.0", "PHP/8.0.0")
        match = re.search(r"([A-Za-z0-9_-]+)/([0-9\.]+)", clean_banner)
        if not match:
            return findings

        software_name, version = match.group(1), match.group(2)
        kev_entries = store.search_by_product(software_name)

        for kev in kev_entries:
            # Check if this specific version is explicitly mentioned in description
            if version in kev.short_description or (software_name.lower() in kev.product.lower()):
                finding = Finding(
                    id=f"EXP-KEV-{kev.cve_id.replace('-', '_')}",
                    rule_id=f"cisa-kev-{kev.cve_id.lower()}",
                    probe="threat_intel",
                    target=target_url,
                    category=Category.CONFIGURATION,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    status=ObservationStatus.CONFIRMED,
                    title=f"Active In-The-Wild Exploit: {kev.cve_id} ({kev.product})",
                    description=(
                        f"Target exposes {software_name}/{version}, which matches an actively exploited vulnerability "
                        f"in the official CISA Known Exploited Vulnerabilities (KEV) catalog: {kev.vulnerability_name}. "
                        f"{kev.short_description}"
                    ),
                    remediation=(
                        f"CISA Directive Action: {kev.required_action} "
                        f"(Remediation Deadline: {kev.due_date}). "
                        f"Ransomware link: {kev.known_ransomware_campaign_use}."
                    ),
                    evidence=Evidence(
                        type=EvidenceType.HTTP_EXCHANGE,
                        summary=f"Server banner '{clean_banner}' matches KEV catalog {kev.cve_id}",
                    ),
                    owasp_top10="A06:2021-Vulnerable and Outdated Components",
                    cwe_id="CWE-1395",
                )
                findings.append(finding)

        return findings
