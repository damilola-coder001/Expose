"""Deployment-shape tests for the Vercel serverless adapter."""

import json
from pathlib import Path


def test_pyproject_declares_the_fastapi_entrypoint_for_vercel():
    root = Path(__file__).resolve().parents[1]
    config = (root / "pyproject.toml").read_text(encoding="utf-8")

    assert '[tool.vercel]\n' in config
    assert 'entrypoint = "expose.api.app:app"' in config


def test_vercel_config_configures_the_resolved_fastapi_entrypoint():
    root = Path(__file__).parent.parent
    config = json.loads((root / "vercel.json").read_text(encoding="utf-8"))

    assert config["functions"]["expose/api/app.py"]["maxDuration"] == 60


def test_vercel_entrypoint_exports_fastapi_application():
    from expose.api import app

    route_paths = {getattr(route, "path", None) for route in app.routes}
    assert "/" in route_paths
    assert "/health" in route_paths
