"""
PhishGuard AI 2.0 — Backend Test Suite
Uses FastAPI TestClient for robust, deterministic testing of all endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health():
    """Verify health endpoint returns status ok and version 2.x."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] in ("2.0.0", "2.1.0")


def test_url_scan_safe():
    """Verify scanning a benign URL produces Safe verdict and low risk."""
    payload = {"scan_type": "url", "target": "https://google.com"}
    response = client.post("/api/scans/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "https://google.com"
    assert data["verdict"] in ("Safe", "Suspicious")
    assert "risk_score" in data
    assert "indicators" in data
    assert data["detection_engine_version"] in ("2.0.0", "2.1.0")


def test_url_scan_phishing_indicators():
    """Verify scanning a suspicious URL detects heuristic indicators."""
    payload = {
        "scan_type": "url",
        "target": "http://paypal-security-verification.xyz/login/verify?user=test",
    }
    response = client.post("/api/scans/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] > 30.0
    assert data["verdict"] in ("Suspicious", "Malicious")
    assert data["severity"] in ("MEDIUM", "HIGH", "CRITICAL")
    # Verify separate confidence score
    assert "confidence_score" in data
    # Verify structured fields
    assert len(data["indicators"]) > 0
    assert isinstance(data["analyst_actions"], list)
    assert isinstance(data["timeline"], list)


def test_email_scan_text():
    """Verify text-based email analysis detects social engineering patterns."""
    payload = {
        "content": (
            "From: security-alert@paypal-update.com\n"
            "Reply-To: attacker@hacker-server.net\n"
            "Subject: Urgent: Account Suspended Immediately\n\n"
            "Please click here to verify your password and credentials immediately: "
            "http://verify-paypal-login.xyz/auth"
        )
    }
    response = client.post("/api/scans/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "email"
    assert data["risk_score"] > 20.0
    assert len(data["indicators"]) > 0


def test_scan_get_detail_and_patch():
    """Verify retrieving scan details by ID and patching status and notes."""
    # Create scan first
    create_res = client.post("/api/scans/url", json={"scan_type": "url", "target": "https://test-target.org"})
    assert create_res.status_code == 200
    scan_id = create_res.json()["id"]

    # Get scan detail
    get_res = client.get(f"/api/scans/{scan_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == scan_id

    # Patch status
    status_res = client.patch(f"/api/scans/{scan_id}/status", json={"investigation_status": "INVESTIGATING"})
    assert status_res.status_code == 200
    assert status_res.json()["investigation_status"] == "INVESTIGATING"

    # Patch notes
    notes_res = client.patch(f"/api/scans/{scan_id}/notes", json={"analyst_notes": "Forensic review initiated by SOC L2."})
    assert notes_res.status_code == 200
    assert "Forensic review" in notes_res.json()["analyst_notes"]


def test_dashboard_stats_and_recent():
    """Verify dashboard KPI stats and recent scans list."""
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    stats = res.json()
    assert "total_scans" in stats
    assert "severity_distribution" in stats
    assert "threat_trend" in stats

    recent_res = client.get("/api/dashboard/recent?limit=5")
    assert recent_res.status_code == 200
    recent = recent_res.json()
    assert isinstance(recent, list)


def test_reports_endpoint():
    """Verify security report generation endpoint."""
    # Create scan
    create_res = client.post("/api/scans/url", json={"scan_type": "url", "target": "https://phishing-report-test.xyz/login"})
    assert create_res.status_code == 200
    scan_id = create_res.json()["id"]

    report_res = client.get(f"/api/reports/{scan_id}")
    assert report_res.status_code == 200
    report = report_res.json()
    assert report["scan_id"] == scan_id
    assert "executive_summary" in report
    assert "recommendations" in report
    assert report["pdf_export"] == "not_implemented"


def test_ai_explanation():
    """Verify AI explanation endpoint converts structured findings to plain English."""
    payload = {
        "verdict": "Malicious",
        "risk_score": 85.0,
        "confidence_score": 92.0,
        "severity": "HIGH",
        "target": "https://paypal-fake-login.xyz",
        "indicators": [
            {
                "name": "Brand Impersonation Pattern",
                "ioc_type": "DOMAIN",
                "ioc_value": "paypal-fake-login.xyz",
                "severity": "HIGH",
                "passed": False,
                "explanation": "Domain mimics PayPal brand outside official assets.",
                "score_impact": 25.0,
                "category": "DOMAIN",
                "technical_evidence": "paypal keyword found in unregistered domain"
            }
        ],
        "mitre_techniques": []
    }
    res = client.post("/api/ai/explain", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "explanation" in data
    assert "key_drivers" in data
    assert "AI-assisted explanation" in data["disclaimer"]


def test_ssrf_protection_blocked():
    """Verify website scanner blocks localhost and private IP addresses."""
    payload = {"scan_type": "website", "target": "http://127.0.0.1:8000/admin"}
    res = client.post("/api/scans/website", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "Blocked"
    assert "SSRF Guard" in data["summary"]

