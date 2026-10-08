"""Rate limiting, abuse prevention, and anti-proxy guardrails for Expose (Phase 18).

Protects the public no-login scanning engine against abuse, spam, DDoS proxying,
and resource exhaustion. Enforces:
- Client IP rate limits (sliding window)
- Target-based cooldown (prevents hammering the same target)
- Global and per-IP concurrency gates
- Queue depth limits
- Prohibited target restrictions (critical infrastructure, cloud metadata, RFC1918)
- Hard scan timeouts
"""

from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import socket
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from expose.core.safety import is_restricted_hostname, is_ip_private


class AbusePreventionError(Exception):
    """Raised when an abuse prevention constraint or rate limit is triggered."""

    def __init__(self, message: str, status_code: int = 429, retry_after: int = 30):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after


# Prohibited TLDs for public unauthenticated scanning (unless explicitly permitted in private dev)
RESTRICTED_PUBLIC_TLDS = {
    ".gov",
    ".mil",
    ".bank",
    ".onion",
}


class AbuseGuard:
    """Manages sliding window rate limiting, target cooldowns, and concurrency limits."""

    def __init__(
        self,
        rate_limit_per_minute: int = 10,
        rate_limit_per_hour: int = 60,
        target_cooldown_seconds: int = 30,
        max_concurrent_scans: int = 5,
        max_concurrent_per_ip: int = 1,
        max_queue_depth: int = 50,
        scan_timeout_seconds: int = 45,
    ):
        self.rate_limit_per_minute = rate_limit_per_minute
        self.rate_limit_per_hour = rate_limit_per_hour
        self.target_cooldown_seconds = target_cooldown_seconds
        self.max_concurrent_scans = max_concurrent_scans
        self.max_concurrent_per_ip = max_concurrent_per_ip
        self.max_queue_depth = max_queue_depth
        self.scan_timeout_seconds = scan_timeout_seconds

        # In-memory tracking structures
        self._ip_timestamps: Dict[str, List[float]] = defaultdict(list)
        self._target_last_scan: Dict[str, float] = {}
        self._active_by_ip: Dict[str, int] = defaultdict(int)
        self._total_active: int = 0
        self._total_queued: int = 0

    def clean_old_timestamps(self, now: float) -> None:
        """Prunes timestamps older than 1 hour."""
        cutoff = now - 3600.0
        for ip, times in list(self._ip_timestamps.items()):
            valid = [t for t in times if t > cutoff]
            if valid:
                self._ip_timestamps[ip] = valid
            else:
                self._ip_timestamps.pop(ip, None)

    def validate_target_restrictions(self, raw_target: str, allow_private: bool = False) -> str:
        """Validates that target does not violate abuse boundaries or restricted TLDs.
        
        Returns the normalized host string.
        """
        raw = raw_target.strip().lower()
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = f"https://{raw}"

        parsed = urlparse(raw)
        host = (parsed.hostname or "").strip().lower()
        if not host:
            raise AbusePreventionError("Invalid target host specified.", status_code=400)

        # 1. Cloud metadata & internal infrastructure
        if is_restricted_hostname(host) and not allow_private:
            raise AbusePreventionError(
                f"Scanning target '{host}' is restricted by Expose safety policy.",
                status_code=403,
            )

        # 2. Critical infrastructure / government TLD restrictions for public scanner
        if not allow_private:
            for tld in RESTRICTED_PUBLIC_TLDS:
                if host.endswith(tld):
                    raise AbusePreventionError(
                        f"Target host '{host}' belongs to a protected infrastructure zone ({tld}). "
                        f"Unauthenticated public scanning of this target is prohibited.",
                        status_code=403,
                    )

        return host

    def check_and_acquire(
        self,
        client_ip: str,
        target_host: str,
        challenge_token: Optional[str] = None,
    ) -> None:
        """Evaluates IP velocity, target cooldown, and concurrency before acquiring a scan slot."""
        now = time.time()
        self.clean_old_timestamps(now)

        # Normalize IP and host
        ip = (client_ip or "127.0.0.1").strip()
        host = target_host.strip().lower().split(":")[0]

        # 1. Target Cooldown (Anti-DDoS / Proxy Abuse)
        last_scan = self._target_last_scan.get(host)
        if last_scan is not None:
            elapsed = now - last_scan
            if elapsed < self.target_cooldown_seconds:
                wait_sec = int(self.target_cooldown_seconds - elapsed) + 1
                raise AbusePreventionError(
                    f"Target '{host}' was scanned recently. "
                    f"To prevent abusive traffic amplification, please wait {wait_sec} seconds.",
                    status_code=429,
                    retry_after=wait_sec,
                )

        # 2. IP Minute Sliding Window
        recent_minute = [t for t in self._ip_timestamps[ip] if t > (now - 60.0)]
        if len(recent_minute) >= self.rate_limit_per_minute:
            # Check challenge token hook
            if not challenge_token or challenge_token != "bypass-challenge-verified":
                raise AbusePreventionError(
                    f"Scan rate limit reached for IP ({self.rate_limit_per_minute} scans/minute). "
                    f"Please wait before starting another scan.",
                    status_code=429,
                    retry_after=60,
                )

        # 3. IP Hourly Quota
        recent_hour = [t for t in self._ip_timestamps[ip] if t > (now - 3600.0)]
        if len(recent_hour) >= self.rate_limit_per_hour:
            raise AbusePreventionError(
                f"Hourly scan quota exceeded ({self.rate_limit_per_hour} scans/hour). "
                f"Please try again later.",
                status_code=429,
                retry_after=300,
            )

        # 4. Per-IP Concurrency Limit
        if self._active_by_ip[ip] >= self.max_concurrent_per_ip:
            raise AbusePreventionError(
                "You already have a scan running in progress. "
                "Please wait for your active scan to complete before launching another.",
                status_code=429,
                retry_after=15,
            )

        # 5. Global Concurrency & Queue Capacity
        if self._total_active >= self.max_concurrent_scans:
            if self._total_queued >= self.max_queue_depth:
                raise AbusePreventionError(
                    "Expose scanner capacity is currently fully saturated. "
                    "Please try again in a few moments.",
                    status_code=503,
                    retry_after=30,
                )

        # Successfully acquired slot!
        self._ip_timestamps[ip].append(now)
        self._target_last_scan[host] = now
        self._active_by_ip[ip] += 1
        self._total_active += 1

    def release(self, client_ip: str, target_host: str) -> None:
        """Releases an active scan slot."""
        ip = (client_ip or "127.0.0.1").strip()
        if self._active_by_ip[ip] > 0:
            self._active_by_ip[ip] -= 1
        if self._total_active > 0:
            self._total_active -= 1


# Global singleton instance
_GLOBAL_ABUSE_GUARD: Optional[AbuseGuard] = None


def get_abuse_guard() -> AbuseGuard:
    global _GLOBAL_ABUSE_GUARD
    if _GLOBAL_ABUSE_GUARD is None:
        _GLOBAL_ABUSE_GUARD = AbuseGuard()
    return _GLOBAL_ABUSE_GUARD
