"""
PhishGuard AI — System Integrations Diagnostics Test Suite
Validates runtime diagnostics endpoints with 100% mocked provider responses.
Guarantees zero consumption of external API quotas during pytest execution.
Verifies status taxonomy, individual provider testing, and zero credential leakage.
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import requests

from backend.app.main import app
from backend.app.services.integrations_service import (
    ALL_ALLOWED_STATUSES,
    STATUS_CONNECTED,
    STATUS_NOT_CONFIGURED,
    STATUS_NOT_VERIFIED,
    STATUS_UNAVAILABLE,
    STATUS_INVALID_CREDENTIALS,
    STATUS_RATE_LIMITED,
    STATUS_TLS_ERROR,
    STATUS_TIMEOUT,
    STATUS_PROVIDER_ERROR,
    STATUS_AVAILABLE,
    STATUS_MANUAL,
    probe_virustotal,
    probe_abuseipdb,
    probe_splunk,
    get_unverified_fallback,
    sanitize_secrets,
)

client = TestClient(app)


def test_allowed_status_taxonomy():
    """Verify all 12 operational statuses are explicitly accounted for."""
    expected_statuses = {
        "CONNECTED",
        "NOT CONFIGURED",
        "NOT VERIFIED",
        "UNAVAILABLE",
        "INVALID CREDENTIALS",
        "RATE LIMITED",
        "QUOTA EXCEEDED",
        "TLS ERROR",
        "TIMEOUT",
        "PROVIDER ERROR",
        "AVAILABLE",
        "MANUAL",
    }
    assert expected_statuses == ALL_ALLOWED_STATUSES


@patch("requests.get")
@patch("requests.post")
@patch("requests.head")
@patch("socket.create_connection")
def test_system_integrations_endpoints_mocked(mock_sock, mock_head, mock_post, mock_get):
    """Verify GET and POST /api/system/integrations with mocked external calls."""
    # Mock socket
    mock_sock.return_value = MagicMock()

    # Mock Splunk health and event
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"text": "HEC is healthy", "code": 17}

    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"text": "Success", "code": 0}

    mock_head.return_value.status_code = 200

    # 1. Test GET /api/system/integrations
    res = client.get("/api/system/integrations")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "integrations" in data
    assert len(data["integrations"]) >= 11

    for item in data["integrations"]:
        assert item["status"] in ALL_ALLOWED_STATUSES
        # Verify secret absence
        dump = str(item).lower()
        assert "splunk_hec_token" not in dump
        assert "password" not in dump

    # 2. Test POST /api/system/integrations/test-all
    res_all = client.post("/api/system/integrations/test-all")
    assert res_all.status_code == 200
    data_all = res_all.json()
    assert data_all["status"] == "ok"
    assert len(data_all["integrations"]) >= 11


@patch("requests.get")
def test_virustotal_mocked_statuses(mock_get):
    """Verify VirusTotal status mappings without hitting real API."""
    # 200 OK -> CONNECTED
    mock_get.return_value.status_code = 200
    res = probe_virustotal()
    assert res["status"] == STATUS_CONNECTED
    assert res["tested"] is True

    # 401 Unauthorized -> INVALID CREDENTIALS
    mock_get.return_value.status_code = 401
    res = probe_virustotal()
    assert res["status"] == STATUS_INVALID_CREDENTIALS

    # 429 Too Many Requests -> RATE LIMITED
    mock_get.return_value.status_code = 429
    res = probe_virustotal()
    assert res["status"] == STATUS_RATE_LIMITED

    # Timeout -> TIMEOUT
    mock_get.side_effect = requests.exceptions.Timeout()
    res = probe_virustotal()
    assert res["status"] == STATUS_TIMEOUT

    # SSLError -> TLS ERROR
    mock_get.side_effect = requests.exceptions.SSLError()
    res = probe_virustotal()
    assert res["status"] == STATUS_TLS_ERROR


@patch("requests.get")
def test_abuseipdb_mocked_statuses(mock_get):
    """Verify AbuseIPDB status mappings without hitting real API."""
    # 200 OK -> CONNECTED
    mock_get.side_effect = None
    mock_get.return_value.status_code = 200
    res = probe_abuseipdb()
    assert res["status"] == STATUS_CONNECTED

    # 403 Forbidden -> INVALID CREDENTIALS
    mock_get.return_value.status_code = 403
    res = probe_abuseipdb()
    assert res["status"] == STATUS_INVALID_CREDENTIALS

    # 429 -> RATE LIMITED
    mock_get.return_value.status_code = 429
    res = probe_abuseipdb()
    assert res["status"] == STATUS_RATE_LIMITED

    # ConnectionError -> UNAVAILABLE
    mock_get.side_effect = requests.exceptions.ConnectionError()
    res = probe_abuseipdb()
    assert res["status"] == STATUS_UNAVAILABLE


@patch("socket.create_connection")
def test_splunk_tcp_failure(mock_sock):
    """Verify Splunk reports UNAVAILABLE when TCP connection fails."""
    mock_sock.side_effect = ConnectionRefusedError("Connection refused")
    res = probe_splunk()
    assert res["status"] == STATUS_UNAVAILABLE
    assert res["tcp"] == "FAIL"


@patch("requests.get")
def test_individual_provider_test_endpoints(mock_get):
    """Verify POST /api/system/integrations/{provider_id}/test works for individual providers."""
    mock_get.return_value.status_code = 200

    # VirusTotal
    res_vt = client.post("/api/system/integrations/virustotal/test")
    assert res_vt.status_code == 200
    assert res_vt.json()["provider"]["id"] == "virustotal"

    # Burp Suite
    res_burp = client.post("/api/system/integrations/burpsuite/test")
    assert res_burp.status_code == 200
    assert res_burp.json()["provider"]["status"] == STATUS_MANUAL

    # Non-existent provider
    res_unknown = client.post("/api/system/integrations/unknownprovider/test")
    assert res_unknown.status_code == 404


def test_unverified_fallback():
    """Verify configured providers without probe run report NOT VERIFIED."""
    fb = get_unverified_fallback("virustotal")
    assert fb["status"] in (STATUS_NOT_VERIFIED, STATUS_NOT_CONFIGURED)
    assert fb["tested"] is False


def test_secret_sanitization():
    """Verify sanitize_secrets strips out real credentials, auth headers, and tokens."""
    dirty = {
        "details": "Authorization failed with Splunk 293c7801-560b-4157-82b4-c83a05b65166",
        "error": "Failed Key 1c33721f3e6f519017517b3c5f652162b7c808229400977bbb141ee520407d289e1314853ff51231",
        "nested": {"token": "Bearer abc123def456xyz789"},
    }
    clean = sanitize_secrets(dirty)
    assert "293c7801" not in str(clean)
    assert "1c33721f" not in str(clean)
    assert "abc123def456xyz789" not in str(clean)
    assert "[REDACTED" in str(clean)
