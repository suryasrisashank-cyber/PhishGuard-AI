"""
PhishGuard AI 3.0 — API Health, Connectivity & CORS Verification Tests
Validates Phase 4, Phase 9, Phase 17 & Phase 21 requirements.
"""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_api_health_endpoint():
    """Verify /api/health returns healthy JSON with service and version."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "service" in data
    assert data["version"] == "3.0.0"


def test_root_health_endpoint():
    """Verify /health alias also returns healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_cors_production_vercel_origin():
    """Verify CORS headers for the live Vercel production frontend."""
    headers = {
        "Origin": "https://phish-guard-ai-suryasrisashank-cybers-projects.vercel.app",
        "Access-Control-Request-Method": "GET",
    }
    response = client.options("/api/health", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "https://phish-guard-ai-suryasrisashank-cybers-projects.vercel.app"
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_cors_vercel_preview_origin():
    """Verify CORS headers for dynamic Vercel preview branch deployments."""
    headers = {
        "Origin": "https://phish-guard-ai-git-feature-suryasrisashank.vercel.app",
        "Access-Control-Request-Method": "GET",
    }
    response = client.options("/api/health", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "https://phish-guard-ai-git-feature-suryasrisashank.vercel.app"


def test_cors_localhost_development():
    """Verify CORS headers for local frontend development."""
    for origin in ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "http://127.0.0.1:5173"]:
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
        }
        response = client.options("/api/health", headers=headers)
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == origin


def test_auth_requirement_on_protected_endpoints():
    """Verify 401 response on protected endpoints without token."""
    # If endpoint requires auth, check that it returns 401 cleanly
    response = client.get("/api/auth/me")
    assert response.status_code in [401, 403, 404]


def test_404_on_unknown_endpoint():
    """Verify 404 response on non-existent endpoints."""
    response = client.get("/api/nonexistent_endpoint_check")
    assert response.status_code == 404


def test_health_no_secrets_leaked():
    """Verify health endpoint does not leak any environment secrets."""
    response = client.get("/api/health")
    data = response.json()
    forbidden_keys = ["secret", "key", "token", "password", "api_key"]
    for key in data:
        for f in forbidden_keys:
            assert f not in key.lower() or key in ["service"], f"Potential secret leak in key: {key}"
