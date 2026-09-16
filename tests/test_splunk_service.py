"""
PhishGuard AI — Splunk HEC Service & SPL Test Suite
Tests Splunk status reporting, offline tolerance, and verified SPL queries.
"""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_splunk_status_endpoint():
    """Verify Splunk status endpoint returns clean dictionary without credentials."""
    res = client.get("/api/splunk/status")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "index" in data
    assert "token" not in data
    assert "splunk_hec_token" not in data
    assert "token" not in str(data).lower()


def test_splunk_spl_examples():
    """Verify SPL query library returns structured, executable search strings."""
    res = client.get("/api/splunk/spl-examples")
    assert res.status_code == 200
    data = res.json()
    assert "searches" in data
    assert len(data["searches"]) >= 4

    for item in data["searches"]:
        assert "title" in item
        assert "spl" in item
        assert "index=" in item["spl"]


def test_splunk_send_unconfigured_graceful():
    """Verify sending event to unconfigured Splunk does not crash the system."""
    payload = {
        "event_type": "test_event",
        "data": {"sample": "telemetry", "risk": 75.0}
    }
    res = client.post("/api/splunk/send", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
