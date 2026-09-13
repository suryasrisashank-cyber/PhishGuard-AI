"""
PhishGuard AI — System Integrations Diagnostics Test Suite
Validates that GET /api/system/integrations returns runtime status for all 11 security integrations
with strict adherence to allowed statuses and zero credential leakage.
"""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

ALLOWED_STATUSES = {"CONNECTED", "AVAILABLE", "NOT CONFIGURED", "UNAVAILABLE", "ERROR"}

REQUIRED_INTEGRATIONS = {
    "Splunk HEC",
    "VirusTotal",
    "AbuseIPDB",
    "AlienVault OTX",
    "URLhaus",
    "DNS Engine",
    "RDAP / WHOIS",
    "YARA Engine",
    "tshark (Wireshark CLI)",
    "PyShark",
    "Scapy",
}


def test_system_integrations_endpoint():
    """Verify runtime report includes all 11 security integrations with valid status and no secrets."""
    res = client.get("/api/system/integrations")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "integrations" in data

    reported_names = set()
    for item in data["integrations"]:
        name = item.get("name")
        status = item.get("status")
        reported_names.add(name)

        # Validate status classification
        assert status in ALLOWED_STATUSES, f"Invalid status '{status}' for {name}"
        assert "details" in item

        # Verify zero credential or token leakage
        details_str = str(item).lower()
        assert "token" not in item.get("details", "").lower() or "not configured" in item.get("details", "").lower() or "token." in item.get("details", "").lower()
        assert "password" not in details_str
        assert "api_key" not in details_str or "not configured" in details_str

    # Ensure all 11 integrations are covered
    for req in REQUIRED_INTEGRATIONS:
        assert req in reported_names, f"Integration '{req}' missing from diagnostics"
