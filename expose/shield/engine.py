"""High-performance attack inspection rule engine for Expose Shield WAF (Phase 35)."""

from enum import Enum
import re
from typing import Dict, List, Optional
from urllib.parse import unquote, unquote_plus
from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    SQL_INJECTION = "sql_injection"
    CROSS_SITE_SCRIPTING = "cross_site_scripting"
    PATH_TRAVERSAL = "path_traversal"
    MALICIOUS_SCANNER = "malicious_scanner"
    REMOTE_CODE_EXECUTION = "remote_code_execution"


class ShieldInspectionResult(BaseModel):
    """Result of deep request inspection."""
    is_attack: bool = False
    category: Optional[AttackCategory] = None
    rule_name: Optional[str] = None
    matched_pattern: Optional[str] = None
    threat_score: int = 0
    evidence_snippet: Optional[str] = None


# High-precision attack pattern definitions with threat weights
RULES: List[Dict] = [
    # 1. SQL Injection (Weight: 40-50 pts)
    {
        "category": AttackCategory.SQL_INJECTION,
        "name": "SQLi: UNION SELECT injection",
        "pattern": re.compile(r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b"),
        "weight": 50,
    },
    {
        "category": AttackCategory.SQL_INJECTION,
        "name": "SQLi: Boolean condition bypass",
        "pattern": re.compile(r"(?i)(?:'|\")\s*OR\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+"),
        "weight": 40,
    },
    {
        "category": AttackCategory.SQL_INJECTION,
        "name": "SQLi: Time-based blind delay",
        "pattern": re.compile(r"(?i)\b(?:SLEEP\s*\(\s*\d+\s*\)|WAITFOR\s+DELAY\b|BENCHMARK\s*\()"),
        "weight": 45,
    },
    {
        "category": AttackCategory.SQL_INJECTION,
        "name": "SQLi: Stacked statement execution",
        "pattern": re.compile(r"(?i);\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE)\s+\w+"),
        "weight": 50,
    },

    # 2. Cross-Site Scripting (XSS) (Weight: 30-40 pts)
    {
        "category": AttackCategory.CROSS_SITE_SCRIPTING,
        "name": "XSS: Script tag injection",
        "pattern": re.compile(r"(?i)<script\b[^>]*>"),
        "weight": 40,
    },
    {
        "category": AttackCategory.CROSS_SITE_SCRIPTING,
        "name": "XSS: Javascript URI scheme",
        "pattern": re.compile(r"(?i)\bjavascript:[^\s\"'>]+"),
        "weight": 35,
    },
    {
        "category": AttackCategory.CROSS_SITE_SCRIPTING,
        "name": "XSS: DOM Event handler injection",
        "pattern": re.compile(r"(?i)\bon(?:error|load|click|mouseover|focus|blur|mouseenter)\s*="),
        "weight": 35,
    },
    {
        "category": AttackCategory.CROSS_SITE_SCRIPTING,
        "name": "XSS: SVG/Image inline vector",
        "pattern": re.compile(r"(?i)<(?:svg|img|iframe|embed|object)\b[^>]*\bon\w+\s*="),
        "weight": 40,
    },

    # 3. Path Traversal & LFI (Weight: 35-45 pts)
    {
        "category": AttackCategory.PATH_TRAVERSAL,
        "name": "LFI: Directory traversal sequence",
        "pattern": re.compile(r"(?:\.\.[/\\])+"),
        "weight": 35,
    },
    {
        "category": AttackCategory.PATH_TRAVERSAL,
        "name": "LFI: Sensitive Unix system file access",
        "pattern": re.compile(r"(?i)/(?:etc/(?:passwd|shadow|hosts|issue)|proc/self)"),
        "weight": 45,
    },
    {
        "category": AttackCategory.PATH_TRAVERSAL,
        "name": "LFI: Sensitive configuration file probe",
        "pattern": re.compile(r"(?i)(?:\.env|\.git/config|wp-config\.php|id_rsa|configuration\.php)"),
        "weight": 40,
    },

    # 4. Remote Code Execution (RCE) (Weight: 50 pts)
    {
        "category": AttackCategory.REMOTE_CODE_EXECUTION,
        "name": "RCE: JNDI Log4Shell injection",
        "pattern": re.compile(r"(?i)\$\{(?:jndi|lower|upper):[^\}]+\}"),
        "weight": 50,
    },
    {
        "category": AttackCategory.REMOTE_CODE_EXECUTION,
        "name": "RCE: PHP wrapper injection",
        "pattern": re.compile(r"(?i)\b(?:php://filter|php://input|data://text|phar://)"),
        "weight": 45,
    },
    {
        "category": AttackCategory.REMOTE_CODE_EXECUTION,
        "name": "RCE: Direct command execution call",
        "pattern": re.compile(r"(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
        "weight": 50,
    },

    # 5. Malicious Scanners & Fuzzers (Weight: 30 pts)
    {
        "category": AttackCategory.MALICIOUS_SCANNER,
        "name": "Scanner: Hostile automated reconnaissance tool",
        "pattern": re.compile(r"(?i)\b(?:sqlmap|nikto|nuclei|masscan|dirbuster|acunetix|nessus|gobuster|wpscan)\b"),
        "weight": 30,
    },
]


class ShieldRuleEngine:
    """Inspects HTTP requests for offensive payloads."""

    @staticmethod
    def inspect(
        method: str,
        path: str,
        query_string: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
    ) -> ShieldInspectionResult:
        """Runs deep inspection over path, query parameters, headers, and request payload."""
        headers = headers or {}
        # Normalize and unquote strings
        raw_combined = f"{path} {query_string} {body}"
        candidates = [raw_combined]
        try:
            candidates.append(unquote(raw_combined))
        except Exception:
            pass
        try:
            candidates.append(unquote_plus(raw_combined))
        except Exception:
            pass

        # 1. Check User-Agent specifically for known scanner tool signatures
        user_agent = headers.get("user-agent", "") or headers.get("User-Agent", "")
        for rule in RULES:
            if rule["category"] == AttackCategory.MALICIOUS_SCANNER:
                m = rule["pattern"].search(user_agent)
                if m:
                    return ShieldInspectionResult(
                        is_attack=True,
                        category=rule["category"],
                        rule_name=rule["name"],
                        matched_pattern=m.group(0),
                        threat_score=rule["weight"],
                        evidence_snippet=f"User-Agent: {user_agent[:80]}",
                    )

        # 2. Check path, query, and body against all attack patterns
        for text in candidates:
            for rule in RULES:
                if rule["category"] == AttackCategory.MALICIOUS_SCANNER:
                    continue
                match = rule["pattern"].search(text)
                if match:
                    snippet = text[max(0, match.start() - 15) : min(len(text), match.end() + 15)]
                    return ShieldInspectionResult(
                        is_attack=True,
                        category=rule["category"],
                        rule_name=rule["name"],
                        matched_pattern=match.group(0),
                        threat_score=rule["weight"],
                        evidence_snippet=snippet.strip(),
                    )

        return ShieldInspectionResult(is_attack=False)
