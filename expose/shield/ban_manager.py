"""Adaptive threat score accumulator and dynamic IP/device ban manager (Phase 35)."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from expose.shield.engine import ShieldInspectionResult
from expose.shield.fingerprint import ClientFingerprint

logger = logging.getLogger("expose.shield.ban_manager")


class BanRecord(BaseModel):
    """Record of an active or historical ban."""
    identifier: str  # IP address or device_hash
    target_type: str  # "ip" or "device_fingerprint"
    reason: str
    attack_category: str
    violation_count: int = 1
    threat_score: int
    banned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    is_active: bool = True


class ShieldTelemetry(BaseModel):
    """Aggregate real-time metrics for the inline shield."""
    total_requests_inspected: int = 0
    total_attacks_blocked: int = 0
    active_ip_bans: int = 0
    active_device_bans: int = 0
    recent_incidents: List[Dict] = Field(default_factory=list)


class AdaptiveBanManager:
    """Tracks threat points and dynamically enforces temporary and permanent bans."""

    def __init__(
        self,
        ban_threshold: int = 100,
        default_ban_duration_seconds: int = 3600,
    ):
        self.ban_threshold = ban_threshold
        self.default_ban_duration = default_ban_duration_seconds

        # identifier -> accumulated threat score
        self._threat_scores: Dict[str, int] = {}
        # identifier -> violation counter
        self._violation_counts: Dict[str, int] = {}
        # identifier -> BanRecord
        self._active_bans: Dict[str, BanRecord] = {}
        # Whitelisted IPs/patterns
        self._whitelist: Set[str] = {"127.0.0.1", "::1"}

        self.telemetry = ShieldTelemetry()

    def record_attack(
        self,
        fingerprint: ClientFingerprint,
        inspection: ShieldInspectionResult,
    ) -> Optional[BanRecord]:
        """Records an attack event, increments threat scores, and triggers ban if threshold exceeded."""
        self.telemetry.total_attacks_blocked += 1

        identifiers = [fingerprint.client_ip, fingerprint.device_hash]
        triggered_ban: Optional[BanRecord] = None

        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=self.default_ban_duration)

        for ident in identifiers:
            if ident in self._whitelist:
                continue

            current_score = self._threat_scores.get(ident, 0) + inspection.threat_score
            self._threat_scores[ident] = current_score
            violations = self._violation_counts.get(ident, 0) + 1
            self._violation_counts[ident] = violations

            if current_score >= self.ban_threshold and ident not in self._active_bans:
                target_type = "ip" if ident == fingerprint.client_ip else "device_fingerprint"
                ban = BanRecord(
                    identifier=ident,
                    target_type=target_type,
                    reason=f"Exceeded threat threshold ({current_score}/{self.ban_threshold}) via {inspection.rule_name}",
                    attack_category=inspection.category.value if inspection.category else "unknown",
                    violation_count=violations,
                    threat_score=current_score,
                    banned_at=now,
                    expires_at=expires,
                    is_active=True,
                )
                self._active_bans[ident] = ban
                triggered_ban = ban
                logger.warning(
                    "SHIELD AUTO-BAN: %s %s banned for %ds: %s",
                    target_type.upper(),
                    ident,
                    self.default_ban_duration,
                    ban.reason,
                )

        # Log incident for telemetry
        incident = {
            "timestamp": now.isoformat(),
            "ip": fingerprint.client_ip,
            "device_hash": fingerprint.device_hash,
            "category": inspection.category.value if inspection.category else "unknown",
            "rule": inspection.rule_name,
            "snippet": inspection.evidence_snippet,
            "score_added": inspection.threat_score,
            "was_banned": triggered_ban is not None,
        }
        self.telemetry.recent_incidents.insert(0, incident)
        if len(self.telemetry.recent_incidents) > 100:
            self.telemetry.recent_incidents.pop()

        return triggered_ban

    def is_banned(self, client_ip: str, device_hash: Optional[str] = None) -> Tuple[bool, Optional[BanRecord]]:
        """Checks if an incoming client IP or device fingerprint is currently banned."""
        now = datetime.now(timezone.utc)
        candidates = [client_ip]
        if device_hash:
            candidates.append(device_hash)

        for ident in candidates:
            if ident in self._whitelist:
                continue

            ban = self._active_bans.get(ident)
            if ban and ban.is_active:
                if ban.expires_at and now > ban.expires_at:
                    # Expired ban
                    ban.is_active = False
                    del self._active_bans[ident]
                    self._threat_scores[ident] = 0
                    continue
                return True, ban

        return False, None

    def unban(self, identifier: str) -> bool:
        """Manually removes an IP or device fingerprint from active bans."""
        clean = identifier.strip()
        if clean in self._active_bans:
            del self._active_bans[clean]
            self._threat_scores[clean] = 0
            logger.info("Unbanned identifier: %s", clean)
            return True
        return False

    def manual_ban(self, identifier: str, reason: str = "Manual admin block", duration_seconds: int = 86400) -> BanRecord:
        """Manually blocks an IP or fingerprint."""
        now = datetime.now(timezone.utc)
        ban = BanRecord(
            identifier=identifier,
            target_type="ip" if "." in identifier or ":" in identifier else "device_fingerprint",
            reason=reason,
            attack_category="manual_admin_ban",
            violation_count=1,
            threat_score=999,
            banned_at=now,
            expires_at=now + timedelta(seconds=duration_seconds),
            is_active=True,
        )
        self._active_bans[identifier] = ban
        return ban

    def list_active_bans(self) -> List[BanRecord]:
        """Returns all currently active bans."""
        # Cleanup expired on access
        now = datetime.now(timezone.utc)
        active = []
        for ident, ban in list(self._active_bans.items()):
            if ban.expires_at and now > ban.expires_at:
                ban.is_active = False
                del self._active_bans[ident]
            else:
                active.append(ban)
        return active

    def get_telemetry(self) -> ShieldTelemetry:
        """Returns current shield protection stats."""
        active = self.list_active_bans()
        self.telemetry.active_ip_bans = sum(1 for b in active if b.target_type == "ip")
        self.telemetry.active_device_bans = sum(1 for b in active if b.target_type == "device_fingerprint")
        return self.telemetry


# Global singleton instance
_GLOBAL_BAN_MANAGER = AdaptiveBanManager()


def get_ban_manager() -> AdaptiveBanManager:
    return _GLOBAL_BAN_MANAGER
