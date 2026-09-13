"""
PhishGuard AI — Strict SSRF Protection Security Test Suite
Validates that internal addresses, loopbacks, link-local, cloud metadata, and invalid schemes
are strictly blocked by the website and URL analysis pipelines.
"""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.scanner_service import _validate_safe_url_for_fetch

client = TestClient(app)

SSRF_PAYLOADS = [
    ("http://127.0.0.1:8000/admin", "Direct loopback IPv4"),
    ("http://localhost:3000", "Localhost hostname"),
    ("http://0.0.0.0:80", "All-zeros IPv4"),
    ("http://[::1]:8080", "IPv6 loopback"),
    ("http://169.254.169.254/latest/meta-data/", "AWS/Cloud metadata IP"),
    ("http://10.0.0.1/internal", "RFC 1918 10.0.0.0/8 private network"),
    ("http://172.16.0.1/admin", "RFC 1918 172.16.0.0/12 private network"),
    ("http://192.168.1.1/router", "RFC 1918 192.168.0.0/16 private network"),
    ("http://internal-service.local", "mDNS .local suffix"),
    ("http://gateway.lan", "Internal .lan suffix"),
    ("file:///etc/passwd", "Non-HTTP file scheme"),
    ("ftp://malicious-server.xyz", "Non-HTTP ftp scheme"),
]


@pytest.mark.parametrize("target_url,description", SSRF_PAYLOADS)
def test_direct_ssrf_validation_function(target_url: str, description: str):
    """Directly test the SSRF validation engine with malicious internal payloads."""
    is_safe, reason = _validate_safe_url_for_fetch(target_url)
    assert not is_safe, f"SSRF bypass detected for {description} ({target_url}): {reason}"


@pytest.mark.parametrize("target_url,description", SSRF_PAYLOADS[:4])
def test_website_scanner_ssrf_api_blocking(target_url: str, description: str):
    """Verify website analysis endpoint rejects SSRF targets with Blocked verdict."""
    response = client.post("/api/scans/website", json={"scan_type": "website", "target": target_url})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Blocked"
    assert "SSRF Guard" in data["summary"]
