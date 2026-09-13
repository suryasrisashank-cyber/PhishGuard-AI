"""
PhishGuard AI — IOC Engine & SOC Investigation Lifecycle Test Suite
Validates IOC indexing, correlation queries, CSV exports, case workflows, and Burp Suite findings attachment.
"""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_ioc_creation_and_listing():
    """Verify manual IOC indexing and filterable list query."""
    payload = {
        "value": "threat-domain-test.xyz",
        "ioc_type": "DOMAIN",
        "severity": "HIGH",
        "confidence": 85.0,
        "reputation": "MALICIOUS",
        "source": "SOC Test Analyst",
        "notes": "Verified C2 domain in sandbox.",
    }
    create_res = client.post("/api/iocs", json=payload)
    assert create_res.status_code == 200
    assert create_res.json()["status"] == "created"

    list_res = client.get("/api/iocs?search=threat-domain-test.xyz")
    assert list_res.status_code == 200
    data = list_res.json()
    assert data["total"] >= 1
    assert any(i["value"] == "threat-domain-test.xyz" for i in data["iocs"])


def test_ioc_csv_export():
    """Verify IOC export endpoint produces valid CSV headers and content."""
    res = client.get("/api/iocs/export/csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers.get("content-type", "")
    content = res.text
    assert "Type,Value,Severity" in content or "ID,Type,Value" in content


def test_investigation_lifecycle_and_burp_attachment():
    """Verify full case lifecycle and attachment of external Burp Suite findings."""
    # 1. Create scan
    scan_res = client.post("/api/scans/url", json={"scan_type": "url", "target": "https://phish-investigate-target.xyz/login"})
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["id"]

    # 2. Escalate scan to investigation case
    case_res = client.post("/api/investigations/from-scan", json={"scan_id": scan_id, "title": "Investigation of Phishing Link"})
    assert case_res.status_code == 200
    case_data = case_res.json()
    case_id = case_data["case_id"]
    assert case_data["status"] == "NEW"

    # 3. Transition case: NEW -> INVESTIGATING -> CONFIRMED_THREAT
    patch_res = client.patch(f"/api/investigations/{case_id}", json={"status": "INVESTIGATING", "analyst_notes": "Triage started."})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "INVESTIGATING"

    # 4. Attach external authorized Burp Suite observation
    burp_payload = {
        "issue_name": "Cleartext Submission of Password",
        "severity": "High",
        "confidence": "Certain",
        "host": "phish-investigate-target.xyz",
        "path": "/login",
        "detail": "Form action posts credentials over unencrypted channel.",
        "remediation": "Enforce TLS and strict transport security.",
    }
    burp_res = client.post(f"/api/investigations/{case_id}/burp-finding", json=burp_payload)
    assert burp_res.status_code == 200
    burp_data = burp_res.json()
    assert burp_data["status"] == "attached"
    assert len(burp_data["case"]["burp_findings"]) >= 1

    # 5. Check correlation endpoint
    corr_res = client.get("/api/iocs/correlate/phish-investigate-target.xyz")
    assert corr_res.status_code == 200
    assert "correlation" in corr_res.json()


def test_soc_alerts_and_campaigns_endpoints():
    """Verify alerts triage queue and campaign correlation clustering."""
    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    assert "counts" in alerts_res.json()
    assert "alerts" in alerts_res.json()

    campaigns_res = client.get("/api/campaigns")
    assert campaigns_res.status_code == 200
    assert "campaigns" in campaigns_res.json()
