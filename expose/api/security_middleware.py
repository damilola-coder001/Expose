"""Security hardening, defense-in-depth headers, and audit logging for Expose (Phase 22).

Expose is a security product and therefore must itself be treated as a high-value target.
Guarantees:
- Zero Trust on scanner input
- Zero Trust on target responses
- Zero Trust on AI output
- Zero Trust on browser content
- Secure HTTP headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy)
- Request ID tracing
- Output encoding / sanitization
- Audit logging
"""

import html
import re
import time
from typing import Callable, Optional
import uuid

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from expose.core.observability import StructuredLogger


_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")


def sanitize_text(value: Optional[str]) -> str:
    """Sanitizes untrusted text strings to prevent reflected XSS, HTML injection, and control characters."""
    if value is None:
        return ""
    # Strip null bytes and control characters (except newline, tab, carriage return)
    cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", str(value))
    return html.escape(cleaned)


def sanitize_target_url(raw_target: str) -> str:
    """Validates and sanitizes raw user input URL."""
    if not raw_target:
        return ""
    # Strip null bytes, tabs, newlines, leading/trailing whitespace
    cleaned = re.sub(r"[\x00-\x1F\x7F]", "", raw_target.strip())
    # Block path traversal attempts in target host
    if ".." in cleaned:
        cleaned = cleaned.replace("..", "")
    return cleaned


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects defensive HTTP headers into all Expose HTTP responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate or capture X-Request-ID for distributed tracing
        supplied_request_id = request.headers.get("x-request-id", "")
        request_id = (
            supplied_request_id
            if _REQUEST_ID_PATTERN.fullmatch(supplied_request_id)
            else f"req_{uuid.uuid4().hex[:10]}"
        )
        request.state.request_id = request_id

        t0 = time.perf_counter()
        response: Response = await call_next(request)
        duration_ms = (time.perf_counter() - t0) * 1000.0

        # Inject tracing header
        response.headers["X-Request-ID"] = request_id

        # 1. Content Security Policy (Restricts scripts and styles to self and trusted Google Fonts)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'; "
            "worker-src 'none';"
        )

        # 2. Defense against MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 3. Defense against Clickjacking / UI Redress attacks
        response.headers["X-Frame-Options"] = "DENY"

        # 4. Referrer Policy (Strict privacy on cross-origin requests)
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 5. Restrictive Permissions Policy (Zero access to sensitive device APIs)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "camera=(), "
            "microphone=(), "
            "payment=(), "
            "usb=(), "
            "interest-cohort=()"
        )

        # 6. Strict Transport Security (HSTS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # 7. Cross-Domain Policy
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # Prevent an untrusted origin from opening this interface with a live
        # scripting reference, and prevent this app from being embedded as a
        # cross-origin subresource.
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # Scan results can reveal target metadata and evidence. API responses
        # must never be retained by browser or intermediary caches.
        if request.url.path.startswith("/api/") or request.url.path in {"/health", "/ready"}:
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"

        # Structured Audit Log for mutating endpoints
        client_ip = request.client.host if request.client else "127.0.0.1"
        if request.method in ("POST", "PUT", "DELETE"):
            StructuredLogger.log_audit_event(
                action=f"{request.method} {request.url.path}",
                client_ip=client_ip,
                target=request.url.path,
                details={
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "duration_ms": round(duration_ms, 2),
                }
            )

        return response
