"""Tests for Expose Shield Inline WAF & Adaptive Attacker Banning (Phase 35)."""

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.testclient import TestClient

from expose.shield.engine import AttackCategory, ShieldRuleEngine
from expose.shield.fingerprint import AttackerFingerprinter
from expose.shield.ban_manager import AdaptiveBanManager
from expose.shield.proxy import ExposeShieldMiddleware


def test_shield_rule_engine_sqli():
    """Validates SQL injection payload detection."""
    # UNION SELECT
    res = ShieldRuleEngine.inspect("GET", "/products", query_string="id=1 UNION SELECT null, username, password FROM users--")
    assert res.is_attack is True
    assert res.category == AttackCategory.SQL_INJECTION
    assert res.threat_score >= 40

    # OR 1=1
    res2 = ShieldRuleEngine.inspect("POST", "/login", body="username=admin' OR 1=1--")
    assert res2.is_attack is True
    assert res2.category == AttackCategory.SQL_INJECTION


def test_shield_rule_engine_xss():
    """Validates Cross-Site Scripting (XSS) payload detection."""
    # Script tag
    res = ShieldRuleEngine.inspect("GET", "/search", query_string="q=<script>alert(document.cookie)</script>")
    assert res.is_attack is True
    assert res.category == AttackCategory.CROSS_SITE_SCRIPTING

    # Inline event handler
    res2 = ShieldRuleEngine.inspect("GET", "/avatar", query_string="url=test\" onerror=alert(1)")
    assert res2.is_attack is True
    assert res2.category == AttackCategory.CROSS_SITE_SCRIPTING


def test_shield_rule_engine_path_traversal():
    """Validates directory traversal and sensitive file access probing."""
    # Directory traversal
    res = ShieldRuleEngine.inspect("GET", "/download", query_string="file=../../../../etc/passwd")
    assert res.is_attack is True
    assert res.category == AttackCategory.PATH_TRAVERSAL

    # Configuration file probe
    res2 = ShieldRuleEngine.inspect("GET", "/.env")
    assert res2.is_attack is True
    assert res2.category == AttackCategory.PATH_TRAVERSAL


def test_shield_rule_engine_scanner_user_agent():
    """Validates detection of hostile scanner user agents."""
    headers = {"User-Agent": "sqlmap/1.6.4#stable (https://sqlmap.org)"}
    res = ShieldRuleEngine.inspect("GET", "/api/users", headers=headers)
    assert res.is_attack is True
    assert res.category == AttackCategory.MALICIOUS_SCANNER


def test_shield_rule_engine_clean_request():
    """Validates benign requests are never blocked."""
    res = ShieldRuleEngine.inspect("GET", "/about", query_string="page=2", headers={"User-Agent": "Mozilla/5.0 Chrome/120.0"})
    assert res.is_attack is False


def test_attacker_fingerprinting_stability():
    """Validates that attacker device fingerprint is deterministic."""
    headers1 = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua-Platform": "Windows",
    }
    headers2 = dict(headers1)

    fp1 = AttackerFingerprinter.fingerprint("198.51.100.5", headers1)
    fp2 = AttackerFingerprinter.fingerprint("198.51.100.5", headers2)

    assert fp1.device_hash == fp2.device_hash
    assert len(fp1.device_hash) > 10


def test_adaptive_ban_manager_threat_accumulation():
    """Validates sliding window threat scoring and automatic IP/device ban enforcement."""
    manager = AdaptiveBanManager(ban_threshold=80, default_ban_duration_seconds=600)
    client_ip = "203.0.113.99"
    fp = AttackerFingerprinter.fingerprint(client_ip, {"User-Agent": "AttackerBrowser/1.0"})

    # Attack 1: SQLi (+50 pts) -> score = 50 -> not banned yet
    insp1 = ShieldRuleEngine.inspect("GET", "/items", query_string="id=1 UNION SELECT 1,2,3")
    ban1 = manager.record_attack(fp, insp1)
    assert ban1 is None
    is_banned, _ = manager.is_banned(client_ip)
    assert is_banned is False

    # Attack 2: Another SQLi (+50 pts) -> score = 100 -> reaches threshold -> BANNED
    insp2 = ShieldRuleEngine.inspect("POST", "/data", body="admin' OR 1=1")
    ban2 = manager.record_attack(fp, insp2)
    assert ban2 is not None
    assert ban2.identifier in (client_ip, fp.device_hash)

    # Subsequent check confirms ban is active
    is_banned_now, ban_rec = manager.is_banned(client_ip)
    assert is_banned_now is True
    assert ban_rec is not None

    # Unban identifier
    assert manager.unban(client_ip) is True
    is_banned_after, _ = manager.is_banned(client_ip)
    assert is_banned_after is False


def test_expose_shield_asgi_middleware():
    """Validates end-to-end ASGI middleware blocking attacks with HTTP 403."""
    from fastapi import FastAPI
    app = FastAPI()
    app.add_middleware(ExposeShieldMiddleware)

    @app.get("/api/data")
    async def data_handler(filter: str = ""):
        return PlainTextResponse("Hello, secure world!")

    client = TestClient(app)

    # 1. Clean request succeeds
    clean_res = client.get("/api/data?filter=active")
    assert clean_res.status_code == 200
    assert clean_res.text == "Hello, secure world!"

    # 2. Attack request is intercepted and receives 403
    attack_res = client.get("/api/data?filter=1' UNION SELECT username, password FROM users--")
    assert attack_res.status_code == 403
    assert attack_res.headers.get("X-Shield-Action") == "BLOCK"
    assert "Expose Shield WAF" in attack_res.json()["error"]
