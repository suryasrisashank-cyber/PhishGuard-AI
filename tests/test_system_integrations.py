"""
PhishGuard AI — System Integrations Diagnostics Test Suite
Validates runtime diagnostics endpoints and professional error handling with 100% mocked responses.
Guarantees hermetic execution in CI environments (GitHub Actions) without requiring local .env files.
Zero external API quota consumption during pytest execution.
Verifies status taxonomy, friendly SOC error messages, actionable guidance, technical details,
and zero credential or raw exception leakage.
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
    STATUS_ACCESS_DENIED,
    STATUS_RATE_LIMITED,
    STATUS_QUOTA_EXCEEDED,
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

MOCK_VT_KEY = "mock_virustotal_api_key_value_12345678"
MOCK_ABUSE_KEY = "mock_abuseipdb_api_key_value_12345678"
MOCK_SPLUNK_TOKEN = "mock-splunk-token-uuid-1234-5678-9012"


@pytest.fixture(autouse=True)
def mock_integration_credentials(monkeypatch):
    """Provide dummy test credentials to ensure hermetic execution in CI without .env."""
    from backend.app.core.config import settings
    monkeypatch.setattr(settings, "virus_total_api_key", MOCK_VT_KEY)
    monkeypatch.setattr(settings, "virustotal_api_key", MOCK_VT_KEY)
    monkeypatch.setattr(settings, "abuseipdb_api_key", MOCK_ABUSE_KEY)
    monkeypatch.setattr(settings, "otx_api_key", "mock_otx_api_key_value_12345678")
    monkeypatch.setattr(settings, "splunk_hec_url", "https://127.0.0.1:8088/services/collector")
    monkeypatch.setattr(settings, "splunk_hec_token", MOCK_SPLUNK_TOKEN)
    monkeypatch.setattr(settings, "splunk_index", "phishguard")


def test_allowed_status_taxonomy():
    """Verify all operational statuses are explicitly accounted for."""
    expected_statuses = {
        "CONNECTED",
        "NOT CONFIGURED",
        "NOT VERIFIED",
        "UNAVAILABLE",
        "INVALID CREDENTIALS",
        "ACCESS DENIED",
        "RATE LIMITED",
        "QUOTA EXCEEDED",
        "TLS ERROR",
        "TIMEOUT",
        "PROVIDER ERROR",
        "AVAILABLE",
        "MANUAL",
        "ERROR",
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
        # Verify secret absence (no actual secret token or key values)
        dump = str(item).lower()
        assert MOCK_SPLUNK_TOKEN.lower() not in dump
        assert MOCK_VT_KEY.lower() not in dump
        assert MOCK_ABUSE_KEY.lower() not in dump
        assert "password" not in dump
        # Verify no raw python exceptions
        assert "requests.exceptions" not in dump
        assert "traceback" not in dump
        assert "winerror" not in dump

    # 2. Test POST /api/system/integrations/test-all
    res_all = client.post("/api/system/integrations/test-all")
    assert res_all.status_code == 200
    data_all = res_all.json()
    assert data_all["status"] == "ok"
    assert len(data_all["integrations"]) >= 11


@patch("requests.get")
def test_virustotal_mocked_statuses(mock_get):
    """Verify VirusTotal status mappings and friendly messages without hitting real API."""
    # 200 OK -> CONNECTED
    mock_get.return_value.status_code = 200
    res = probe_virustotal()
    assert res["status"] == STATUS_CONNECTED
    assert res["tested"] is True
    assert "operational" in res["message"].lower()

    # 401 Unauthorized -> INVALID CREDENTIALS
    mock_get.return_value.status_code = 401
    res = probe_virustotal()
    assert res["status"] == STATUS_INVALID_CREDENTIALS
    assert "rejected" in res["message"].lower() or "credentials" in res["message"].lower()
    assert res["guidance"] is not None
    assert "requests.exceptions" not in res["message"]

    # 403 Forbidden -> ACCESS DENIED
    mock_get.return_value.status_code = 403
    res = probe_virustotal()
    assert res["status"] == STATUS_ACCESS_DENIED
    assert "denied" in res["message"].lower()
    assert res["guidance"] is not None

    # 429 Too Many Requests -> RATE LIMITED
    mock_get.return_value.status_code = 429
    res = probe_virustotal()
    assert res["status"] == STATUS_RATE_LIMITED
    assert "limit" in res["message"].lower()
    assert "requests.exceptions" not in res["message"]

    # 503 Server Error -> PROVIDER ERROR
    mock_get.return_value.status_code = 503
    res = probe_virustotal()
    assert res["status"] == STATUS_PROVIDER_ERROR
    assert "service error" in res["message"].lower() or "provider" in res["message"].lower()

    # Timeout -> TIMEOUT with friendly message
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out (fake)")
    res = probe_virustotal()
    assert res["status"] == STATUS_TIMEOUT
    assert "time" in res["message"].lower()
    assert "requests.exceptions" not in res["message"]
    assert res["technical_details"]["failure_type"] == "PROVIDER_TIMEOUT"
    assert res["technical_details"]["request_id"].startswith("vir_")

    # SSLError -> TLS ERROR
    mock_get.side_effect = requests.exceptions.SSLError("CERTIFICATE_VERIFY_FAILED")
    res = probe_virustotal()
    assert res["status"] == STATUS_TLS_ERROR
    assert "secure connection" in res["message"].lower()
    assert "requests.exceptions" not in res["message"]


@patch("requests.get")
def test_abuseipdb_mocked_statuses(mock_get):
    """Verify AbuseIPDB status mappings and sanitized technical details."""
    # 200 OK -> CONNECTED
    mock_get.side_effect = None
    mock_get.return_value.status_code = 200
    res = probe_abuseipdb()
    assert res["status"] == STATUS_CONNECTED

    # 401 -> INVALID CREDENTIALS
    mock_get.return_value.status_code = 401
    res = probe_abuseipdb()
    assert res["status"] == STATUS_INVALID_CREDENTIALS

    # 403 -> ACCESS DENIED
    mock_get.return_value.status_code = 403
    res = probe_abuseipdb()
    assert res["status"] == STATUS_ACCESS_DENIED
    assert "denied" in res["message"].lower()

    # 429 -> RATE LIMITED
    mock_get.return_value.status_code = 429
    res = probe_abuseipdb()
    assert res["status"] == STATUS_RATE_LIMITED

    # ConnectionError -> UNAVAILABLE
    mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused by target")
    res = probe_abuseipdb()
    assert res["status"] == STATUS_UNAVAILABLE
    assert "requests.exceptions" not in res["message"]
    assert res["technical_details"]["request_id"] is not None


@patch("socket.create_connection")
def test_splunk_tcp_failure_no_raw_exception(mock_sock):
    """Verify Splunk reports UNAVAILABLE when TCP connection fails without leaking WinError."""
    mock_sock.side_effect = ConnectionRefusedError("[WinError 10061] No connection could be made")
    res = probe_splunk()
    assert res["status"] == STATUS_UNAVAILABLE
    assert res["tcp"] == "FAIL"
    assert "WinError" not in res["message"]
    assert "could not be reached" in res["message"]
    assert "splunk enterprise" in res["guidance"].lower() or "port 8088" in res["guidance"].lower()
    assert res["technical_details"]["failure_type"] == "CONNECTION_REFUSED"


@patch("requests.get")
def test_individual_provider_test_endpoints(mock_get):
    """Verify POST /api/system/integrations/{provider_id}/test works for individual providers."""
    mock_get.return_value.status_code = 200

    # VirusTotal
    res_vt = client.post("/api/system/integrations/virustotal/test")
    assert res_vt.status_code == 200
    assert res_vt.json()["provider"]["id"] == "virustotal"
    assert "technical_details" in res_vt.json()["provider"]

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


def test_providers_unconfigured(monkeypatch):
    """Verify providers return NOT CONFIGURED when credentials are empty."""
    from backend.app.core.config import settings
    monkeypatch.setattr(settings, "virus_total_api_key", "")
    monkeypatch.setattr(settings, "virustotal_api_key", "")
    monkeypatch.setattr(settings, "abuseipdb_api_key", "")
    monkeypatch.setattr(settings, "splunk_hec_url", "")
    monkeypatch.setattr(settings, "splunk_hec_token", "")

    vt = probe_virustotal()
    assert vt["status"] == STATUS_NOT_CONFIGURED
    assert vt["configured"] is False

    aip = probe_abuseipdb()
    assert aip["status"] == STATUS_NOT_CONFIGURED
    assert aip["configured"] is False

    spk = probe_splunk()
    assert spk["status"] == STATUS_NOT_CONFIGURED
    assert spk["configured"] is False


def test_secret_sanitization():
    """Verify sanitize_secrets strips out real credentials, auth headers, tokens, and raw tracebacks."""
    dirty = {
        "details": "Authorization failed with Splunk 293c7801-560b-4157-82b4-c83a05b65166",
        "error": "Failed Key 1c33721f3e6f519017517b3c5f652162b7c808229400977bbb141ee520407d289e1314853ff51231",
        "nested": {"token": "Bearer abc123def456xyz789"},
        "stack": 'File "C:\\backend\\app.py", line 42, in test',
    }
    clean = sanitize_secrets(dirty)
    assert "293c7801" not in str(clean)
    assert "1c33721f" not in str(clean)
    assert "abc123def456xyz789" not in str(clean)
    assert "[REDACTED" in str(clean)
