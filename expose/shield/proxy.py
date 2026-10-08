"""Inline WAF reverse proxy and ASGI security middleware for Expose Shield (Phase 35)."""

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Callable, Dict, Optional
import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from expose.shield.engine import ShieldRuleEngine
from expose.shield.fingerprint import AttackerFingerprinter
from expose.shield.ban_manager import AdaptiveBanManager, get_ban_manager

logger = logging.getLogger("expose.shield.proxy")


def create_block_response(ban_reason: str, client_ip: str, rule_name: Optional[str] = None) -> JSONResponse:
    """Generates a standardized, security-hardened HTTP 403 Forbidden payload."""
    payload = {
        "error": "Access Denied by Expose Shield WAF",
        "status_code": 403,
        "client_ip": client_ip,
        "reason": ban_reason,
        "triggered_rule": rule_name or "Active Threat Protection Policy",
        "incident_timestamp": datetime.now(timezone.utc).isoformat(),
        "support_note": "If you believe this request was blocked in error, contact the site security team.",
    }
    return JSONResponse(
        status_code=403,
        content=payload,
        headers={
            "X-Shield-Protection": "EXPOSE-SHIELD-ACTIVE",
            "X-Shield-Action": "BLOCK",
            "Cache-Control": "no-store, no-cache, must-revalidate",
        },
    )


class ExposeShieldMiddleware(BaseHTTPMiddleware):
    """ASGI middleware for inline WAF protection and dynamic banning."""

    def __init__(self, app, ban_manager: Optional[AdaptiveBanManager] = None):
        super().__init__(app)
        self.ban_manager = ban_manager or get_ban_manager()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        forwarded = request.headers.get("x-forwarded-for", "")
        client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "127.0.0.1")
        headers_dict = dict(request.headers)

        # 1. Compute client device fingerprint
        fingerprint = AttackerFingerprinter.fingerprint(client_ip, headers_dict)
        self.ban_manager.telemetry.total_requests_inspected += 1

        # 2. Check if client or device fingerprint is already banned
        is_banned, ban_rec = self.ban_manager.is_banned(client_ip, fingerprint.device_hash)
        if is_banned and ban_rec:
            logger.warning("SHIELD BLOCKED BANNED CLIENT: %s (%s)", client_ip, ban_rec.reason)
            return create_block_response(ban_rec.reason, client_ip)

        # 3. Read body safely for inspection
        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8", errors="ignore")[:4096]

        # 4. Deep inspection for hostile payloads
        query_str = str(request.url.query) if request.url.query else str(request.query_params)
        inspection = ShieldRuleEngine.inspect(
            method=request.method,
            path=request.url.path,
            query_string=query_str,
            headers=headers_dict,
            body=body_str,
        )

        if inspection.is_attack:
            ban_rec = self.ban_manager.record_attack(fingerprint, inspection)
            reason = ban_rec.reason if ban_rec else f"Hostile payload detected: {inspection.rule_name}"
            logger.warning("SHIELD INTERCEPTED ATTACK from %s: %s", client_ip, inspection.rule_name)
            return create_block_response(reason, client_ip, rule_name=inspection.rule_name)

        # 5. Pass clean traffic forward
        return await call_next(request)


class ShieldReverseProxy:
    """Standalone async HTTP reverse proxy with inline attack defense."""

    def __init__(
        self,
        upstream_url: str,
        ban_manager: Optional[AdaptiveBanManager] = None,
        timeout_seconds: float = 30.0,
    ):
        self.upstream_url = upstream_url.rstrip("/")
        self.ban_manager = ban_manager or get_ban_manager()
        self.timeout = timeout_seconds

    async def handle_request(
        self,
        method: str,
        path: str,
        query_string: str,
        headers: Dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> Response:
        """Inspects, blocks, or forwards an incoming HTTP request."""
        fingerprint = AttackerFingerprinter.fingerprint(client_ip, headers)
        self.ban_manager.telemetry.total_requests_inspected += 1

        # Check ban status
        is_banned, ban_rec = self.ban_manager.is_banned(client_ip, fingerprint.device_hash)
        if is_banned and ban_rec:
            return create_block_response(ban_rec.reason, client_ip)

        # Inspect request
        body_str = body.decode("utf-8", errors="ignore")[:4096]
        inspection = ShieldRuleEngine.inspect(
            method=method,
            path=path,
            query_string=query_string,
            headers=headers,
            body=body_str,
        )

        if inspection.is_attack:
            ban_rec = self.ban_manager.record_attack(fingerprint, inspection)
            reason = ban_rec.reason if ban_rec else f"Blocked by rule: {inspection.rule_name}"
            return create_block_response(reason, client_ip, rule_name=inspection.rule_name)

        # Forward clean traffic to upstream
        target_url = f"{self.upstream_url}{path}"
        if query_string:
            target_url = f"{target_url}?{query_string}"

        fwd_headers = {k: v for k, v in headers.items() if k.lower() not in ("host", "content-length")}
        fwd_headers["X-Forwarded-For"] = client_ip
        fwd_headers["X-Shield-Inspected"] = "true"

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                res = await client.request(
                    method=method,
                    url=target_url,
                    headers=fwd_headers,
                    content=body,
                )
                resp_headers = dict(res.headers)
                resp_headers["X-Shield-Protection"] = "EXPOSE-SHIELD-ACTIVE"
                return Response(
                    content=res.content,
                    status_code=res.status_code,
                    headers=resp_headers,
                )
        except Exception as e:
            logger.error("Upstream connection failure: %s", e)
            return JSONResponse(
                status_code=502,
                content={"error": "Bad Gateway", "details": f"Failed connecting to upstream {self.upstream_url}"},
            )
