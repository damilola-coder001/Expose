"""Domain Ownership Verification Engine (Proof-of-Control).

Allows website owners and security teams to cryptographically prove ownership
of a target domain via:
1. DNS TXT record (_expose-challenge.<domain>)
2. HTTP well-known token (https://<domain>/.well-known/expose-challenge.txt)

Verified domains receive authoritative 'Verified Owner' badges on scan reports
and permission for higher-frequency scheduled assessments.
"""

from datetime import datetime, timezone, timedelta
from enum import Enum
import hashlib
import hmac
import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import dns.asyncresolver
import dns.resolver
from pydantic import BaseModel, Field

from expose.core.safety import create_safe_async_client, is_ip_private, is_restricted_hostname

logger = logging.getLogger("expose.ownership")

# Secret salt for generating unforgeable tokens (can be configured via env)
DEFAULT_VERIFICATION_SECRET = "expose-ownership-secret-v1-production-salt"


class VerificationMethod(str, Enum):
    DNS_TXT = "dns_txt"
    HTTP_WELL_KNOWN = "http_well_known"
    ANY = "any"


class DomainChallenge(BaseModel):
    """Instructions and tokens for a domain ownership challenge."""
    domain: str
    token: str
    dns_record_name: str
    dns_record_type: str = "TXT"
    dns_record_value: str
    http_url: str
    http_expected_content: str
    created_at: str
    expires_at: str
    instructions: Dict[str, str] = Field(default_factory=dict)


class DomainOwnershipRecord(BaseModel):
    """Persistent state of a verified domain."""
    domain: str
    verified: bool
    verified_at: Optional[str] = None
    verification_method: Optional[str] = None
    proof: Optional[str] = None
    expires_at: Optional[str] = None


def normalize_domain(domain_or_url: str) -> str:
    """Extracts and normalizes the apex or hostname from a URL or raw domain string."""
    clean = domain_or_url.strip().lower()
    if "://" in clean:
        parsed = urlparse(clean)
        clean = parsed.hostname or clean
    # Strip any port or trailing slashes
    clean = clean.split(":")[0].rstrip("/")
    return clean


def generate_challenge_token(domain: str, secret: str = DEFAULT_VERIFICATION_SECRET) -> str:
    """Generates a stable, reproducible yet secure challenge token for a domain."""
    norm = normalize_domain(domain)
    digest = hmac.new(secret.encode(), norm.encode(), hashlib.sha256).hexdigest()[:24]
    return f"expose-verification={digest}"


class DomainOwnershipVerifier:
    """Coordinates challenge generation, DNS lookups, and HTTP verification for domain ownership."""

    def __init__(self, secret: str = DEFAULT_VERIFICATION_SECRET):
        self.secret = secret
        self._records: Dict[str, DomainOwnershipRecord] = {}
        self._custom_dns_resolver: Optional[dns.asyncresolver.Resolver] = None

    def get_challenge(self, domain: str) -> DomainChallenge:
        """Generates or retrieves challenge details and instructions for a domain."""
        norm_domain = normalize_domain(domain)
        token = generate_challenge_token(norm_domain, self.secret)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=7)

        dns_record = f"_expose-challenge.{norm_domain}"
        http_url = f"https://{norm_domain}/.well-known/expose-challenge.txt"

        instructions = {
            "dns_txt": f"Create a DNS TXT record for host '{dns_record}' with value '{token}'.",
            "http_well_known": f"Upload a text file to '{http_url}' containing precisely '{token}'.",
        }

        return DomainChallenge(
            domain=norm_domain,
            token=token,
            dns_record_name=dns_record,
            dns_record_type="TXT",
            dns_record_value=token,
            http_url=http_url,
            http_expected_content=token,
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            instructions=instructions,
        )

    async def verify_dns_txt(self, domain: str, expected_token: str) -> Tuple[bool, str]:
        """Queries DNS TXT records for _expose-challenge.<domain> to verify the token."""
        norm_domain = normalize_domain(domain)
        challenge_host = f"_expose-challenge.{norm_domain}"

        resolver = self._custom_dns_resolver or dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0

        try:
            answers = await resolver.resolve(challenge_host, "TXT")
            for rdata in answers:
                for txt_bytes in rdata.strings:
                    txt_str = txt_bytes.decode("utf-8", errors="ignore").strip()
                    if txt_str == expected_token or expected_token in txt_str:
                        return True, f"Verified via DNS TXT record on {challenge_host}: '{txt_str}'"
            return False, f"DNS TXT record found on {challenge_host} but token did not match expected value."
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False, f"No DNS TXT record found at {challenge_host}."
        except Exception as e:
            logger.warning(f"DNS verification error for {challenge_host}: {e}")
            return False, f"DNS query failed: {str(e)}"

    async def verify_http_well_known(self, domain: str, expected_token: str) -> Tuple[bool, str]:
        """Fetches https://<domain>/.well-known/expose-challenge.txt to verify token."""
        norm_domain = normalize_domain(domain)
        if is_restricted_hostname(norm_domain):
            return False, f"Cannot verify ownership of restricted/internal host '{norm_domain}'."

        url = f"https://{norm_domain}/.well-known/expose-challenge.txt"
        try:
            async with create_safe_async_client(allow_private=False, timeout=6.0) as client:
                res = await client.get(url)
                if res.status_code == 200:
                    body = res.text.strip()
                    if expected_token in body:
                        return True, f"Verified via HTTP at {url} (HTTP 200 Match)"
                    return False, f"HTTP request returned 200 but token did not match expected content."
                return False, f"HTTP request to {url} returned status code {res.status_code}."
        except Exception as e:
            # Fallback to HTTP if HTTPS fails
            fallback_url = f"http://{norm_domain}/.well-known/expose-challenge.txt"
            try:
                async with create_safe_async_client(allow_private=False, timeout=6.0) as client:
                    res = await client.get(fallback_url)
                    if res.status_code == 200 and expected_token in res.text.strip():
                        return True, f"Verified via HTTP at {fallback_url} (HTTP 200 Match)"
            except Exception:
                pass
            return False, f"HTTP verification failed for {url}: {str(e)}"

    async def verify_domain(
        self, domain: str, method: VerificationMethod = VerificationMethod.ANY
    ) -> Tuple[bool, str, Optional[DomainOwnershipRecord]]:
        """Executes verification check using DNS, HTTP, or whichever succeeds first."""
        norm_domain = normalize_domain(domain)
        challenge = self.get_challenge(norm_domain)
        expected_token = challenge.token

        success = False
        proof = ""
        resolved_method = None

        if method in (VerificationMethod.DNS_TXT, VerificationMethod.ANY):
            dns_ok, dns_msg = await self.verify_dns_txt(norm_domain, expected_token)
            if dns_ok:
                success = True
                proof = dns_msg
                resolved_method = VerificationMethod.DNS_TXT.value
            else:
                proof = dns_msg

        if not success and method in (VerificationMethod.HTTP_WELL_KNOWN, VerificationMethod.ANY):
            http_ok, http_msg = await self.verify_http_well_known(norm_domain, expected_token)
            if http_ok:
                success = True
                proof = http_msg
                resolved_method = VerificationMethod.HTTP_WELL_KNOWN.value
            else:
                proof = f"{proof}; {http_msg}" if proof else http_msg

        if success:
            now = datetime.now(timezone.utc)
            record = DomainOwnershipRecord(
                domain=norm_domain,
                verified=True,
                verified_at=now.isoformat(),
                verification_method=resolved_method,
                proof=proof,
                expires_at=(now + timedelta(days=30)).isoformat(),
            )
            self._records[norm_domain] = record
            return True, proof, record

        return False, proof, None

    def is_verified(self, domain: str) -> bool:
        """Returns True if the domain has a valid, non-expired verification record."""
        norm_domain = normalize_domain(domain)
        record = self._records.get(norm_domain)
        if not record or not record.verified:
            return False
        if record.expires_at:
            try:
                exp = datetime.fromisoformat(record.expires_at)
                if datetime.now(timezone.utc) > exp:
                    return False
            except Exception:
                pass
        return True

    def get_record(self, domain: str) -> Optional[DomainOwnershipRecord]:
        """Returns the domain ownership record if verified."""
        norm_domain = normalize_domain(domain)
        if self.is_verified(norm_domain):
            return self._records.get(norm_domain)
        return None

    def record_manual_verification(
        self, domain: str, method: str = "manual_admin", proof: str = "Admin verified"
    ) -> DomainOwnershipRecord:
        """Allows test suites or administrators to mark a domain as verified."""
        norm_domain = normalize_domain(domain)
        now = datetime.now(timezone.utc)
        record = DomainOwnershipRecord(
            domain=norm_domain,
            verified=True,
            verified_at=now.isoformat(),
            verification_method=method,
            proof=proof,
            expires_at=(now + timedelta(days=30)).isoformat(),
        )
        self._records[norm_domain] = record
        return record


# Global singleton instance
_GLOBAL_OWNERSHIP_VERIFIER: Optional[DomainOwnershipVerifier] = None


def get_ownership_verifier() -> DomainOwnershipVerifier:
    """Returns the singleton instance of DomainOwnershipVerifier."""
    global _GLOBAL_OWNERSHIP_VERIFIER
    if _GLOBAL_OWNERSHIP_VERIFIER is None:
        _GLOBAL_OWNERSHIP_VERIFIER = DomainOwnershipVerifier()
    return _GLOBAL_OWNERSHIP_VERIFIER
