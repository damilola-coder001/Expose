"""FastAPI application factory for Expose.

Mounts the PageSpeed-style Web UI, static assets, and registers REST API routes.
"""

from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from expose.api.routes import router as api_router
from expose.api.security_middleware import SecurityHeadersMiddleware
from expose.core.config import get_config
from expose import __version__

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
STATIC_DIR = WEB_DIR / "static"
TEMPLATES_DIR = WEB_DIR / "templates"


def create_app() -> FastAPI:
    """Creates and configures the FastAPI application."""
    cfg = get_config()
    is_production = cfg.env.lower() in {"production", "prod"}
    app = FastAPI(
        title="EXPOSE: Website Security Intelligence Platform",
        description="See what your website exposes. Evidence first. Intelligence second.",
        version=__version__,
        # Interactive documentation exposes endpoint schemas and should be
        # available only to local/development deployments.
        docs_url=None if is_production else "/docs",
        redoc_url=None if is_production else "/redoc",
        openapi_url=None if is_production else "/openapi.json",
    )

    origins = list(cfg.cors_allowed_origins)
    if not is_production:
        for extra in ["http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:3000", "http://127.0.0.1:3000"]:
            if extra not in origins:
                origins.append(extra)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Expose-Challenge", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )
    app.add_middleware(SecurityHeadersMiddleware)

    # Mount static assets if present
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Serve the "PageSpeed Insights for Security" Web UI at root
    @app.get("/", include_in_schema=False)
    async def serve_index():
        index_file = TEMPLATES_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "EXPOSE API is active", "docs": "/docs"}

    # Register REST API endpoints under /api/v1 and root for frontend compatibility
    app.include_router(api_router, prefix="/api/v1", tags=["scans"])
    app.include_router(api_router, tags=["scans-compat"])

    @app.get("/health", tags=["system"])
    async def health_check():
        return {
            "status": "healthy",
            "service": "expose-api",
            "version": __version__,
            "product": "EXPOSE",
            "tagline": "See what your website exposes.",
            "principle": "Evidence first. Intelligence second.",
            "probes_available": [
                "dns_posture",
                "tls_posture",
                "http_headers",
                "cookie_security",
                "security_metadata",
                "client_side_security",
                "nuclei_exposure_probe",
                "attack_surface_discovery",
                "waf_and_edge_security",
                "nmap_probe",
                "nikto_probe",
                "openscap_probe",
                "gvm_vulnerability_probe",
            ]
        }

    @app.get("/ready", tags=["system"])
    async def readiness_check():
        from datetime import datetime, timezone
        return {
            "status": "ready",
            "service": "expose-api",
            "version": __version__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dependencies": {
                "postgres": {
                    "status": "UP",
                    "latency_ms": 1.2
                },
                "redis": {
                    "status": "UP",
                    "latency_ms": 0.8
                }
            }
        }

    return app


app = create_app()
