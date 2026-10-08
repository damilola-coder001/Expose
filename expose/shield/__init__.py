"""Expose Shield — Inline Web Application Firewall (WAF) & Adaptive Defense (Phase 35)."""

from expose.shield.engine import AttackCategory, ShieldInspectionResult, ShieldRuleEngine
from expose.shield.fingerprint import AttackerFingerprinter
from expose.shield.ban_manager import AdaptiveBanManager, BanRecord, get_ban_manager
from expose.shield.proxy import ShieldReverseProxy, ExposeShieldMiddleware

__all__ = [
    "AttackCategory",
    "ShieldInspectionResult",
    "ShieldRuleEngine",
    "AttackerFingerprinter",
    "AdaptiveBanManager",
    "BanRecord",
    "get_ban_manager",
    "ShieldReverseProxy",
    "ExposeShieldMiddleware",
]
