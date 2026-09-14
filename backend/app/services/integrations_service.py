"""
PhishGuard AI — Professional Security Integrations Diagnostics Service
Evaluates genuine runtime operational status for all 12 security integrations.
Strictly distinguishes:
  CONNECTED, NOT CONFIGURED, NOT VERIFIED, UNAVAILABLE, INVALID CREDENTIALS,
  ACCESS DENIED, RATE LIMITED, QUOTA EXCEEDED, TIMEOUT, TLS ERROR,
  PROVIDER ERROR, AVAILABLE, MANUAL, and ERROR.

Provides professional SOC-level messages, actionable guidance, and collapsed,
sanitized technical details without raw exceptions or credential leakage.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import shutil
import socket
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
import requests

from ..core.config import settings

logger = logging.getLogger(__name__)

# Strict runtime status taxonomy
STATUS_CONNECTED = "CONNECTED"
STATUS_NOT_CONFIGURED = "NOT CONFIGURED"
STATUS_NOT_VERIFIED = "NOT VERIFIED"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_INVALID_CREDENTIALS = "INVALID CREDENTIALS"
STATUS_ACCESS_DENIED = "ACCESS DENIED"
STATUS_RATE_LIMITED = "RATE LIMITED"
STATUS_QUOTA_EXCEEDED = "QUOTA EXCEEDED"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_TLS_ERROR = "TLS ERROR"
STATUS_PROVIDER_ERROR = "PROVIDER ERROR"
STATUS_AVAILABLE = "AVAILABLE"
STATUS_MANUAL = "MANUAL"
STATUS_ERROR = "ERROR"

ALL_ALLOWED_STATUSES = {
    STATUS_CONNECTED,
    STATUS_NOT_CONFIGURED,
    STATUS_NOT_VERIFIED,
    STATUS_UNAVAILABLE,
    STATUS_INVALID_CREDENTIALS,
    STATUS_ACCESS_DENIED,
    STATUS_RATE_LIMITED,
    STATUS_QUOTA_EXCEEDED,
    STATUS_TIMEOUT,
    STATUS_TLS_ERROR,
    STATUS_PROVIDER_ERROR,
    STATUS_AVAILABLE,
    STATUS_MANUAL,
    STATUS_ERROR,
}

# Status labels mapping for UI display
STATUS_LABELS = {
    STATUS_CONNECTED: "Healthy",
    STATUS_NOT_CONFIGURED: "Setup Required",
    STATUS_NOT_VERIFIED: "Verification Required",
    STATUS_UNAVAILABLE: "Temporarily Unavailable",
    STATUS_INVALID_CREDENTIALS: "Authentication Required",
    STATUS_ACCESS_DENIED: "Access Denied",
    STATUS_RATE_LIMITED: "Rate Limit Reached",
    STATUS_QUOTA_EXCEEDED: "Quota Exhausted",
    STATUS_TIMEOUT: "Provider Timeout",
    STATUS_TLS_ERROR: "Secure Connection Error",
    STATUS_PROVIDER_ERROR: "Provider Issue",
    STATUS_AVAILABLE: "Ready",
    STATUS_MANUAL: "Manual Finding Ingestion",
    STATUS_ERROR: "Integration Error",
}

# In-memory runtime cache for diagnostics
_DIAGNOSTICS_CACHE: dict[str, dict[str, Any]] = {}


def generate_request_id(prefix: str = "req") -> str:
    """Generate a short, safe random request ID for diagnostics telemetry."""
    return f"{prefix}_{secrets.token_hex(4)}"


def sanitize_secrets(data: Any) -> Any:
    """Recursively redact any sensitive credentials from diagnostic dictionaries and strings."""
    secrets_list = [
        (settings.virus_total_api_key or "").strip(),
        (settings.virustotal_api_key or "").strip(),
        (settings.abuseipdb_api_key or "").strip(),
        (settings.otx_api_key or "").strip(),
        (settings.splunk_hec_token or "").strip(),
        (settings.secret_key or "").strip(),
    ]
    valid_secrets = [s for s in secrets_list if len(s) >= 8]

    if isinstance(data, str):
        cleaned = data
        for s in valid_secrets:
            cleaned = cleaned.replace(s, "[REDACTED_SECRET]")
        cleaned = re.sub(r"Splunk\s+[0-9a-fA-F-]{16,}", "Splunk [REDACTED_TOKEN]", cleaned)
        cleaned = re.sub(r"Key\s+[0-9a-fA-F]{16,}", "Key [REDACTED_KEY]", cleaned)
        cleaned = re.sub(r"Bearer\s+[^\s]+", "Bearer [REDACTED_TOKEN]", cleaned)
        cleaned = re.sub(r"x-apikey:\s*[^\s]+", "x-apikey: [REDACTED_KEY]", cleaned, flags=re.IGNORECASE)
        # Also clean raw tracebacks, internal filepaths or WinError if accidentally passed
        cleaned = re.sub(r'File ".*?", line \d+.*', "[REDACTED_TRACEBACK]", cleaned)
        return cleaned
    elif isinstance(data, dict):
        return {k: sanitize_secrets(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_secrets(item) for item in data]
    return data


def format_error_state(
    provider_id: str,
    provider_name: str,
    category: str,
    critical: bool,
    error_type: str,
    http_status: int | None = None,
    latency_ms: int | None = None,
    custom_message: str | None = None,
    custom_guidance: str | None = None,
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Centralized error formatter: maps technical failures to professional SOC-style messages,
    actionable guidance, and sanitized technical details without raw exceptions.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    req_id = generate_request_id(provider_id[:3])

    # Status mapping
    if error_type == "TIMEOUT":
        status = STATUS_TIMEOUT
        default_msg = "The provider did not respond within the expected time."
        default_guidance = "Retry the integration test or verify network connectivity."
        failure_code = "PROVIDER_TIMEOUT"
    elif error_type == "CONNECTION_REFUSED":
        status = STATUS_UNAVAILABLE
        default_msg = "Unable to connect to the configured service."
        default_guidance = "Confirm the service is running and the configured host and port are correct."
        failure_code = "CONNECTION_REFUSED"
    elif error_type == "INVALID_CREDENTIALS":
        status = STATUS_INVALID_CREDENTIALS
        default_msg = "The provider rejected the configured credentials."
        default_guidance = "Verify the API key or token in backend settings."
        failure_code = "AUTH_REJECTED"
    elif error_type == "ACCESS_DENIED":
        status = STATUS_ACCESS_DENIED
        default_msg = "The provider denied access to this request."
        default_guidance = "Check account permissions, API plan, or credential access."
        failure_code = "ACCESS_FORBIDDEN"
    elif error_type == "RATE_LIMITED":
        status = STATUS_RATE_LIMITED
        default_msg = "The provider's request limit has been reached."
        default_guidance = "Wait before retrying."
        failure_code = "RATE_LIMIT_EXCEEDED"
    elif error_type == "QUOTA_EXCEEDED":
        status = STATUS_QUOTA_EXCEEDED
        default_msg = "The current API quota has been exhausted."
        default_guidance = "Review provider usage dashboard and billing tier."
        failure_code = "QUOTA_EXHAUSTED"
    elif error_type == "TLS_ERROR":
        status = STATUS_TLS_ERROR
        default_msg = "A secure connection to the provider could not be verified."
        default_guidance = "Review the TLS configuration for this integration."
        failure_code = "TLS_VERIFICATION_FAILED"
    elif error_type == "DNS_ERROR":
        status = STATUS_UNAVAILABLE
        default_msg = "The provider hostname could not be resolved."
        default_guidance = "Verify DNS server configuration and internet connectivity."
        failure_code = "DNS_RESOLUTION_FAILED"
    elif error_type == "SERVER_ERROR":
        status = STATUS_PROVIDER_ERROR
        default_msg = "The external provider is currently experiencing a service error."
        default_guidance = "Provider upstream issue; retry in a few moments."
        failure_code = f"HTTP_{http_status}" if http_status else "PROVIDER_5XX"
    elif error_type == "MALFORMED_RESPONSE":
        status = STATUS_PROVIDER_ERROR
        default_msg = "The provider returned an unexpected response."
        default_guidance = "Verify provider API version compatibility."
        failure_code = "MALFORMED_PAYLOAD"
    elif error_type == "NOT_INSTALLED":
        status = STATUS_UNAVAILABLE
        default_msg = "The required local component is not installed."
        default_guidance = "Install the missing binary or package on the host system."
        failure_code = "COMPONENT_MISSING"
    else:
        status = STATUS_ERROR
        default_msg = "The integration test could not be completed."
        default_guidance = "Verify network availability and platform configuration."
        failure_code = "UNKNOWN_ERROR"

    msg = custom_message or default_msg
    guidance = custom_guidance or default_guidance

    doc = {
        "id": provider_id,
        "name": provider_name,
        "category": category,
        "critical": critical,
        "status": status,
        "status_label": STATUS_LABELS.get(status, "Issue Detected"),
        "configured": True if error_type != "NOT_CONFIGURED" else False,
        "tested": True,
        "latency_ms": latency_ms,
        "last_checked": now_iso,
        "message": msg,
        "guidance": guidance,
        "technical_details": {
            "provider": provider_name,
            "http_status": http_status,
            "failure_type": failure_code,
            "latency_ms": latency_ms,
            "last_checked": now_iso,
            "request_id": req_id,
        },
    }

    if extra_fields:
        doc.update(extra_fields)

    return sanitize_secrets(doc)


# ==========================================
# 1. Splunk HEC Probe
# ==========================================
def probe_splunk() -> dict[str, Any]:
    """
    Test Splunk HTTP Event Collector (HEC) operational state:
    - Reasonable timeout: 2.0s connect, 4.0s read
    - TCP socket check
    - /services/collector/health check
    - integration_test event submission with ACK detection
    - Friendly SOC messages for timeout, connection refused, invalid token, etc.
    """
    hec_url = (settings.splunk_hec_url or "").strip().rstrip("/")
    for suffix in ["/services/collector/event", "/services/collector/raw", "/services/collector"]:
        if hec_url.endswith(suffix):
            hec_url = hec_url[:-len(suffix)].rstrip("/")
    token = (settings.splunk_hec_token or "").strip()

    if not hec_url or not token:
        return {
            "id": "splunk",
            "name": "Splunk HEC",
            "category": "SIEM",
            "critical": True,
            "status": STATUS_NOT_CONFIGURED,
            "status_label": STATUS_LABELS[STATUS_NOT_CONFIGURED],
            "configured": False,
            "tested": False,
            "endpoint": "Not configured",
            "tcp": "NOT TESTED",
            "hec_health": "NOT TESTED",
            "authentication": "NOT TESTED",
            "test_event": "NOT TESTED",
            "ack_status": "NOT TESTED",
            "latency_ms": None,
            "last_checked": None,
            "message": "Splunk HEC URL or Token not configured in environment.",
            "guidance": "Add SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN to backend .env.",
            "technical_details": {
                "provider": "Splunk HEC",
                "http_status": None,
                "failure_type": "NOT_CONFIGURED",
                "latency_ms": None,
                "last_checked": None,
                "request_id": generate_request_id("spk"),
            },
        }

    parsed = urlparse(hec_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 8088)
    endpoint_display = f"{host}:{port}"

    # Step 1: TCP Connectivity probe (2.0s timeout)
    t0 = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=2.0)
        sock.close()
        tcp_res = "PASS"
    except Exception:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="splunk",
            provider_name="Splunk HEC",
            category="SIEM",
            critical=True,
            error_type="CONNECTION_REFUSED",
            latency_ms=latency,
            custom_message="Splunk HEC could not be reached. Confirm that HEC is enabled and the configured port is active.",
            custom_guidance="Confirm Splunk Enterprise is running and port 8088 is listening in Global Settings.",
            extra_fields={
                "endpoint": endpoint_display,
                "tcp": "FAIL",
                "hec_health": "SKIPPED",
                "authentication": "SKIPPED",
                "test_event": "REJECTED",
                "ack_status": "NOT TESTED",
            },
        )

    # Step 2: HEC Health Check (tuple timeout: 2.0s connect, 4.0s read)
    health_url = f"{hec_url}/services/collector/health"
    try:
        health_resp = requests.get(
            health_url,
            headers={"Authorization": f"Splunk {token}"},
            timeout=(2.0, 4.0),
            verify=settings.splunk_verify_tls,
        )
        if health_resp.status_code in (401, 403):
            latency = round((time.time() - t0) * 1000)
            return format_error_state(
                provider_id="splunk",
                provider_name="Splunk HEC",
                category="SIEM",
                critical=True,
                error_type="INVALID_CREDENTIALS",
                http_status=health_resp.status_code,
                latency_ms=latency,
                custom_message="Splunk HEC rejected the configured token.",
                custom_guidance="Verify the SPLUNK_HEC_TOKEN in backend settings and ensure the token is enabled in Splunk Web.",
                extra_fields={
                    "endpoint": endpoint_display,
                    "tcp": "PASS",
                    "hec_health": "FAIL",
                    "authentication": "FAIL",
                    "test_event": "REJECTED",
                    "ack_status": "NOT TESTED",
                },
            )
        hec_health_res = "PASS" if health_resp.status_code == 200 else "DEGRADED"
    except requests.exceptions.SSLError:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="splunk",
            provider_name="Splunk HEC",
            category="SIEM",
            critical=True,
            error_type="TLS_ERROR",
            latency_ms=latency,
            custom_message="A secure connection to Splunk HEC could not be verified.",
            custom_guidance="Review the SPLUNK_VERIFY_TLS configuration or certificate trust store.",
            extra_fields={
                "endpoint": endpoint_display,
                "tcp": "PASS",
                "hec_health": "FAIL",
                "authentication": "SKIPPED",
                "test_event": "REJECTED",
                "ack_status": "NOT TESTED",
            },
        )
    except requests.exceptions.Timeout:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="splunk",
            provider_name="Splunk HEC",
            category="SIEM",
            critical=True,
            error_type="TIMEOUT",
            latency_ms=latency,
            custom_message="Splunk HEC did not respond within the expected time.",
            custom_guidance="Confirm Splunk server load and network latency on port 8088.",
            extra_fields={
                "endpoint": endpoint_display,
                "tcp": "PASS",
                "hec_health": "TIMEOUT",
                "authentication": "SKIPPED",
                "test_event": "REJECTED",
                "ack_status": "NOT TESTED",
            },
        )
    except Exception:
        hec_health_res = "FAIL"

    # Step 3: Transmit integration_test event
    event_url = f"{hec_url}/services/collector/event"
    event_payload = {
        "event": {
            "action": "integration_test",
            "service": "PhishGuard AI System Diagnostics",
            "status": "PASS",
            "test": True,
            "timestamp": time.time(),
        },
        "sourcetype": settings.splunk_sourcetype or "phishguard:scan",
        "index": settings.splunk_index or "phishguard",
    }

    try:
        event_resp = requests.post(
            event_url,
            headers={"Authorization": f"Splunk {token}"},
            json=event_payload,
            timeout=(2.0, 4.0),
            verify=settings.splunk_verify_tls,
        )
        latency = round((time.time() - t0) * 1000)

        if event_resp.status_code == 200:
            try:
                resp_json = event_resp.json()
            except Exception:
                resp_json = {}

            if "ackId" in resp_json:
                ack_status = f"CONFIRMED (ackId: {resp_json['ackId']})"
            else:
                ack_status = "DISABLED (Indexer ACK disabled on token)"

            now_iso = datetime.now(timezone.utc).isoformat()
            return sanitize_secrets({
                "id": "splunk",
                "name": "Splunk HEC",
                "category": "SIEM",
                "critical": True,
                "status": STATUS_CONNECTED,
                "status_label": STATUS_LABELS[STATUS_CONNECTED],
                "configured": True,
                "tested": True,
                "endpoint": endpoint_display,
                "tcp": "PASS",
                "hec_health": hec_health_res,
                "authentication": "PASS",
                "test_event": "ACCEPTED",
                "ack_status": ack_status,
                "latency_ms": latency,
                "last_checked": now_iso,
                "message": f"Connected to Splunk HEC (Index: {settings.splunk_index}). Test event accepted.",
                "guidance": None,
                "technical_details": {
                    "provider": "Splunk HEC",
                    "http_status": 200,
                    "failure_type": "NONE",
                    "latency_ms": latency,
                    "last_checked": now_iso,
                    "request_id": generate_request_id("spk"),
                },
            })
        elif event_resp.status_code in (401, 403):
            return format_error_state(
                provider_id="splunk",
                provider_name="Splunk HEC",
                category="SIEM",
                critical=True,
                error_type="INVALID_CREDENTIALS",
                http_status=event_resp.status_code,
                latency_ms=latency,
                custom_message="Splunk HEC rejected the configured token.",
                custom_guidance="Verify the SPLUNK_HEC_TOKEN in backend settings.",
                extra_fields={
                    "endpoint": endpoint_display,
                    "tcp": "PASS",
                    "hec_health": hec_health_res,
                    "authentication": "FAIL",
                    "test_event": "REJECTED",
                    "ack_status": "NOT TESTED",
                },
            )
        else:
            return format_error_state(
                provider_id="splunk",
                provider_name="Splunk HEC",
                category="SIEM",
                critical=True,
                error_type="SERVER_ERROR",
                http_status=event_resp.status_code,
                latency_ms=latency,
                custom_message="The external provider is currently experiencing a service error.",
                custom_guidance="Check Splunk internal logs for ingestion issues.",
                extra_fields={
                    "endpoint": endpoint_display,
                    "tcp": "PASS",
                    "hec_health": hec_health_res,
                    "authentication": "UNKNOWN",
                    "test_event": "REJECTED",
                    "ack_status": "NOT TESTED",
                },
            )
    except requests.exceptions.Timeout:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="splunk",
            provider_name="Splunk HEC",
            category="SIEM",
            critical=True,
            error_type="TIMEOUT",
            latency_ms=latency,
            custom_message="Splunk HEC did not respond within the expected time.",
            custom_guidance="Check Splunk HEC queue and network latency.",
            extra_fields={
                "endpoint": endpoint_display,
                "tcp": "PASS",
                "hec_health": hec_health_res,
                "authentication": "TIMEOUT",
                "test_event": "TIMEOUT",
                "ack_status": "NOT TESTED",
            },
        )
    except Exception:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="splunk",
            provider_name="Splunk HEC",
            category="SIEM",
            critical=True,
            error_type="UNKNOWN",
            latency_ms=latency,
            custom_message="The integration test could not be completed.",
            custom_guidance="Verify Splunk HEC configuration and connectivity.",
            extra_fields={
                "endpoint": endpoint_display,
                "tcp": "PASS",
                "hec_health": "FAIL",
                "authentication": "ERROR",
                "test_event": "ERROR",
                "ack_status": "NOT TESTED",
            },
        )


# ==========================================
# 2. VirusTotal Probe
# ==========================================
def probe_virustotal() -> dict[str, Any]:
    """
    Perform a safe read-only API probe against VirusTotal v3:
    - Reasonable timeout: 3.5s connect, 7.0s read
    - Respects free tier limits (4 requests/min)
    - Friendly provider-specific message on timeout
    - Handles 200, 401, 403, 404, 429, 5xx, timeout, SSLError, ConnectionError
    """
    api_key = (settings.virus_total_api_key or settings.virustotal_api_key or "").strip()
    if not api_key:
        return {
            "id": "virustotal",
            "name": "VirusTotal",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_NOT_CONFIGURED,
            "status_label": STATUS_LABELS[STATUS_NOT_CONFIGURED],
            "configured": False,
            "tested": False,
            "real_probe": "NOT CONFIGURED",
            "latency_ms": None,
            "last_checked": None,
            "message": "VIRUS_TOTAL_API_KEY not configured in environment.",
            "guidance": "Add VIRUS_TOTAL_API_KEY to backend settings to enable multi-engine URL/hash analysis.",
            "technical_details": {
                "provider": "VirusTotal",
                "http_status": None,
                "failure_type": "NOT_CONFIGURED",
                "latency_ms": None,
                "last_checked": None,
                "request_id": generate_request_id("vt"),
            },
        }

    t0 = time.time()
    try:
        resp = requests.get(
            "https://www.virustotal.com/api/v3/domains/example.com",
            headers={"x-apikey": api_key, "User-Agent": "PhishGuard-AI-Diagnostics/3.0"},
            timeout=(3.5, 7.0),
        )
        latency = round((time.time() - t0) * 1000)

        if resp.status_code == 200:
            now_iso = datetime.now(timezone.utc).isoformat()
            return sanitize_secrets({
                "id": "virustotal",
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_CONNECTED,
                "status_label": STATUS_LABELS[STATUS_CONNECTED],
                "configured": True,
                "tested": True,
                "real_probe": "PASS",
                "latency_ms": latency,
                "last_checked": now_iso,
                "message": "VirusTotal v3 API operational and authenticated.",
                "guidance": None,
                "technical_details": {
                    "provider": "VirusTotal",
                    "http_status": 200,
                    "failure_type": "NONE",
                    "latency_ms": latency,
                    "last_checked": now_iso,
                    "request_id": generate_request_id("vt"),
                },
            })
        elif resp.status_code == 401:
            return format_error_state(
                provider_id="virustotal",
                provider_name="VirusTotal",
                category="Threat Intelligence",
                critical=True,
                error_type="INVALID_CREDENTIALS",
                http_status=401,
                latency_ms=latency,
                custom_message="The provider rejected the configured credentials.",
                custom_guidance="Verify the VirusTotal API key in backend settings.",
                extra_fields={"real_probe": "FAIL"},
            )
        elif resp.status_code == 403:
            return format_error_state(
                provider_id="virustotal",
                provider_name="VirusTotal",
                category="Threat Intelligence",
                critical=True,
                error_type="ACCESS_DENIED",
                http_status=403,
                latency_ms=latency,
                custom_message="The provider denied access to this request.",
                custom_guidance="Check account permissions, API plan, or credential access.",
                extra_fields={"real_probe": "FAIL"},
            )
        elif resp.status_code == 429:
            return format_error_state(
                provider_id="virustotal",
                provider_name="VirusTotal",
                category="Threat Intelligence",
                critical=True,
                error_type="RATE_LIMITED",
                http_status=429,
                latency_ms=latency,
                custom_message="The provider's request limit has been reached.",
                custom_guidance="Wait before retrying (free tier allows 4 queries per minute).",
                extra_fields={"real_probe": "RATE LIMITED"},
            )
        elif resp.status_code >= 500:
            return format_error_state(
                provider_id="virustotal",
                provider_name="VirusTotal",
                category="Threat Intelligence",
                critical=True,
                error_type="SERVER_ERROR",
                http_status=resp.status_code,
                latency_ms=latency,
                custom_message="The external provider is currently experiencing a service error.",
                custom_guidance="VirusTotal upstream service issue; retry in a few moments.",
                extra_fields={"real_probe": "FAIL"},
            )
        else:
            return format_error_state(
                provider_id="virustotal",
                provider_name="VirusTotal",
                category="Threat Intelligence",
                critical=True,
                error_type="MALFORMED_RESPONSE",
                http_status=resp.status_code,
                latency_ms=latency,
                custom_message="The provider returned an unexpected response.",
                custom_guidance="Verify API version compatibility.",
                extra_fields={"real_probe": "FAIL"},
            )
    except requests.exceptions.Timeout:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="virustotal",
            provider_name="VirusTotal",
            category="Threat Intelligence",
            critical=True,
            error_type="TIMEOUT",
            latency_ms=latency,
            custom_message="VirusTotal did not respond in time. The rest of PhishGuard remains operational.",
            custom_guidance="Retry the integration test or verify network connectivity.",
            extra_fields={"real_probe": "TIMEOUT"},
        )
    except requests.exceptions.SSLError:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="virustotal",
            provider_name="VirusTotal",
            category="Threat Intelligence",
            critical=True,
            error_type="TLS_ERROR",
            latency_ms=latency,
            custom_message="A secure connection to the provider could not be verified.",
            custom_guidance="Review the TLS configuration for this integration.",
            extra_fields={"real_probe": "TLS ERROR"},
        )
    except requests.exceptions.ConnectionError:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="virustotal",
            provider_name="VirusTotal",
            category="Threat Intelligence",
            critical=True,
            error_type="CONNECTION_REFUSED",
            latency_ms=latency,
            custom_message="Unable to connect to the configured service.",
            custom_guidance="Confirm the service is running and internet connectivity is available.",
            extra_fields={"real_probe": "UNREACHABLE"},
        )
    except Exception:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="virustotal",
            provider_name="VirusTotal",
            category="Threat Intelligence",
            critical=True,
            error_type="UNKNOWN",
            latency_ms=latency,
            custom_message="The integration test could not be completed.",
            custom_guidance="Retry the integration test or inspect network gateway.",
            extra_fields={"real_probe": "ERROR"},
        )


# ==========================================
# 3. AbuseIPDB Probe
# ==========================================
def probe_abuseipdb() -> dict[str, Any]:
    """
    Perform a real APIv2 check request against AbuseIPDB:
    - Reasonable timeout: 3.5s connect, 7.0s read
    - Friendly provider-specific message on timeout
    - Handles 200, 401, 403, 429, 5xx, timeout, SSLError, ConnectionError
    """
    api_key = (settings.abuseipdb_api_key or "").strip()
    if not api_key:
        return {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_NOT_CONFIGURED,
            "status_label": STATUS_LABELS[STATUS_NOT_CONFIGURED],
            "configured": False,
            "tested": False,
            "real_probe": "NOT CONFIGURED",
            "latency_ms": None,
            "last_checked": None,
            "message": "ABUSEIPDB_API_KEY not configured in environment.",
            "guidance": "Add ABUSEIPDB_API_KEY to backend settings for IP reputation checking.",
            "technical_details": {
                "provider": "AbuseIPDB",
                "http_status": None,
                "failure_type": "NOT_CONFIGURED",
                "latency_ms": None,
                "last_checked": None,
                "request_id": generate_request_id("aip"),
            },
        }

    t0 = time.time()
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": "127.0.0.1", "maxAgeInDays": "30"},
            headers={"Key": api_key, "Accept": "application/json", "User-Agent": "PhishGuard-AI-Diagnostics/3.0"},
            timeout=(3.5, 7.0),
        )
        latency = round((time.time() - t0) * 1000)

        if resp.status_code == 200:
            now_iso = datetime.now(timezone.utc).isoformat()
            return sanitize_secrets({
                "id": "abuseipdb",
                "name": "AbuseIPDB",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_CONNECTED,
                "status_label": STATUS_LABELS[STATUS_CONNECTED],
                "configured": True,
                "tested": True,
                "real_probe": "PASS",
                "latency_ms": latency,
                "last_checked": now_iso,
                "message": "AbuseIPDB v2 API authenticated and active.",
                "guidance": None,
                "technical_details": {
                    "provider": "AbuseIPDB",
                    "http_status": 200,
                    "failure_type": "NONE",
                    "latency_ms": latency,
                    "last_checked": now_iso,
                    "request_id": generate_request_id("aip"),
                },
            })
        elif resp.status_code == 401:
            return format_error_state(
                provider_id="abuseipdb",
                provider_name="AbuseIPDB",
                category="Threat Intelligence",
                critical=True,
                error_type="INVALID_CREDENTIALS",
                http_status=401,
                latency_ms=latency,
                custom_message="The provider rejected the configured credentials.",
                custom_guidance="Verify the ABUSEIPDB_API_KEY in backend settings.",
                extra_fields={"real_probe": "FAIL"},
            )
        elif resp.status_code == 403:
            return format_error_state(
                provider_id="abuseipdb",
                provider_name="AbuseIPDB",
                category="Threat Intelligence",
                critical=True,
                error_type="ACCESS_DENIED",
                http_status=403,
                latency_ms=latency,
                custom_message="The provider denied access to this request.",
                custom_guidance="Check account permissions, API plan, or credential access.",
                extra_fields={"real_probe": "FAIL"},
            )
        elif resp.status_code == 429:
            return format_error_state(
                provider_id="abuseipdb",
                provider_name="AbuseIPDB",
                category="Threat Intelligence",
                critical=True,
                error_type="RATE_LIMITED",
                http_status=429,
                latency_ms=latency,
                custom_message="The provider's request limit has been reached.",
                custom_guidance="Wait before retrying (daily quota or per-minute rate limit reached).",
                extra_fields={"real_probe": "RATE LIMITED"},
            )
        elif resp.status_code >= 500:
            return format_error_state(
                provider_id="abuseipdb",
                provider_name="AbuseIPDB",
                category="Threat Intelligence",
                critical=True,
                error_type="SERVER_ERROR",
                http_status=resp.status_code,
                latency_ms=latency,
                custom_message="The external provider is currently experiencing a service error.",
                custom_guidance="AbuseIPDB upstream service issue; retry in a few moments.",
                extra_fields={"real_probe": "FAIL"},
            )
        else:
            return format_error_state(
                provider_id="abuseipdb",
                provider_name="AbuseIPDB",
                category="Threat Intelligence",
                critical=True,
                error_type="MALFORMED_RESPONSE",
                http_status=resp.status_code,
                latency_ms=latency,
                custom_message="The provider returned an unexpected response.",
                custom_guidance="Verify API payload compatibility.",
                extra_fields={"real_probe": "FAIL"},
            )
    except requests.exceptions.Timeout:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="abuseipdb",
            provider_name="AbuseIPDB",
            category="Threat Intelligence",
            critical=True,
            error_type="TIMEOUT",
            latency_ms=latency,
            custom_message="AbuseIPDB did not respond in time. IP reputation enrichment is temporarily unavailable.",
            custom_guidance="Retry the integration test or verify network connectivity.",
            extra_fields={"real_probe": "TIMEOUT"},
        )
    except requests.exceptions.SSLError:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="abuseipdb",
            provider_name="AbuseIPDB",
            category="Threat Intelligence",
            critical=True,
            error_type="TLS_ERROR",
            latency_ms=latency,
            custom_message="A secure connection to the provider could not be verified.",
            custom_guidance="Review the TLS configuration for this integration.",
            extra_fields={"real_probe": "TLS ERROR"},
        )
    except requests.exceptions.ConnectionError:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="abuseipdb",
            provider_name="AbuseIPDB",
            category="Threat Intelligence",
            critical=True,
            error_type="CONNECTION_REFUSED",
            latency_ms=latency,
            custom_message="Unable to connect to the configured service.",
            custom_guidance="Confirm internet connectivity is available.",
            extra_fields={"real_probe": "UNREACHABLE"},
        )
    except Exception:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="abuseipdb",
            provider_name="AbuseIPDB",
            category="Threat Intelligence",
            critical=True,
            error_type="UNKNOWN",
            latency_ms=latency,
            custom_message="The integration test could not be completed.",
            custom_guidance="Retry the integration test or inspect backend logs.",
            extra_fields={"real_probe": "ERROR"},
        )


# ==========================================
# 4. AlienVault OTX Probe
# ==========================================
def probe_otx() -> dict[str, Any]:
    """Test AlienVault OTX API operational state."""
    api_key = (settings.otx_api_key or "").strip()
    if not api_key:
        return {
            "id": "otx",
            "name": "AlienVault OTX",
            "category": "Threat Intelligence",
            "critical": False,
            "status": STATUS_NOT_CONFIGURED,
            "status_label": STATUS_LABELS[STATUS_NOT_CONFIGURED],
            "configured": False,
            "tested": False,
            "latency_ms": None,
            "last_checked": None,
            "message": "OTX_API_KEY not configured in environment.",
            "guidance": "Add OTX_API_KEY to backend settings for AlienVault threat pulse correlation.",
            "technical_details": {
                "provider": "AlienVault OTX",
                "http_status": None,
                "failure_type": "NOT_CONFIGURED",
                "latency_ms": None,
                "last_checked": None,
                "request_id": generate_request_id("otx"),
            },
        }

    t0 = time.time()
    try:
        resp = requests.get(
            "https://otx.alienvault.com/api/v1/user/me",
            headers={"X-OTX-API-KEY": api_key, "User-Agent": "PhishGuard-AI-Diagnostics/3.0"},
            timeout=(3.5, 7.0),
        )
        latency = round((time.time() - t0) * 1000)
        if resp.status_code == 200:
            now_iso = datetime.now(timezone.utc).isoformat()
            return sanitize_secrets({
                "id": "otx",
                "name": "AlienVault OTX",
                "category": "Threat Intelligence",
                "critical": False,
                "status": STATUS_CONNECTED,
                "status_label": STATUS_LABELS[STATUS_CONNECTED],
                "configured": True,
                "tested": True,
                "latency_ms": latency,
                "last_checked": now_iso,
                "message": "AlienVault OTX API authenticated and active.",
                "guidance": None,
                "technical_details": {
                    "provider": "AlienVault OTX",
                    "http_status": 200,
                    "failure_type": "NONE",
                    "latency_ms": latency,
                    "last_checked": now_iso,
                    "request_id": generate_request_id("otx"),
                },
            })
        elif resp.status_code in (401, 403):
            return format_error_state(
                provider_id="otx",
                provider_name="AlienVault OTX",
                category="Threat Intelligence",
                critical=False,
                error_type="INVALID_CREDENTIALS" if resp.status_code == 401 else "ACCESS_DENIED",
                http_status=resp.status_code,
                latency_ms=latency,
                custom_message="The provider rejected the configured credentials.",
                custom_guidance="Verify the OTX_API_KEY in backend settings.",
            )
        elif resp.status_code == 429:
            return format_error_state(
                provider_id="otx",
                provider_name="AlienVault OTX",
                category="Threat Intelligence",
                critical=False,
                error_type="RATE_LIMITED",
                http_status=429,
                latency_ms=latency,
                custom_message="The provider's request limit has been reached.",
                custom_guidance="Wait before retrying.",
            )
        else:
            return format_error_state(
                provider_id="otx",
                provider_name="AlienVault OTX",
                category="Threat Intelligence",
                critical=False,
                error_type="SERVER_ERROR",
                http_status=resp.status_code,
                latency_ms=latency,
            )
    except requests.exceptions.Timeout:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="otx",
            provider_name="AlienVault OTX",
            category="Threat Intelligence",
            critical=False,
            error_type="TIMEOUT",
            latency_ms=latency,
            custom_message="AlienVault OTX did not respond in time. Threat intelligence enrichment is temporarily unavailable.",
            custom_guidance="Retry the integration test or verify network connectivity.",
        )
    except requests.exceptions.SSLError:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="otx",
            provider_name="AlienVault OTX",
            category="Threat Intelligence",
            critical=False,
            error_type="TLS_ERROR",
            latency_ms=latency,
        )
    except Exception:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="otx",
            provider_name="AlienVault OTX",
            category="Threat Intelligence",
            critical=False,
            error_type="CONNECTION_REFUSED",
            latency_ms=latency,
        )


# ==========================================
# 5. URLhaus Probe
# ==========================================
def probe_urlhaus() -> dict[str, Any]:
    """Test abuse.ch URLhaus public feed operational state."""
    t0 = time.time()
    try:
        resp = requests.head(
            "https://urlhaus.abuse.ch",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard-Diagnostics"},
            timeout=(3.5, 6.0),
        )
        latency = round((time.time() - t0) * 1000)
        if resp.status_code in (200, 301, 302):
            now_iso = datetime.now(timezone.utc).isoformat()
            return sanitize_secrets({
                "id": "urlhaus",
                "name": "URLhaus",
                "category": "Threat Intelligence",
                "critical": False,
                "status": STATUS_CONNECTED,
                "status_label": STATUS_LABELS[STATUS_CONNECTED],
                "configured": True,
                "tested": True,
                "latency_ms": latency,
                "last_checked": now_iso,
                "message": "Abuse.ch URLhaus threat feed reachable and active.",
                "guidance": None,
                "technical_details": {
                    "provider": "URLhaus",
                    "http_status": resp.status_code,
                    "failure_type": "NONE",
                    "latency_ms": latency,
                    "last_checked": now_iso,
                    "request_id": generate_request_id("url"),
                },
            })
        return format_error_state(
            provider_id="urlhaus",
            provider_name="URLhaus",
            category="Threat Intelligence",
            critical=False,
            error_type="SERVER_ERROR",
            http_status=resp.status_code,
            latency_ms=latency,
        )
    except requests.exceptions.Timeout:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="urlhaus",
            provider_name="URLhaus",
            category="Threat Intelligence",
            critical=False,
            error_type="TIMEOUT",
            latency_ms=latency,
            custom_message="URLhaus is temporarily unavailable.",
            custom_guidance="Retry the integration test or verify internet connectivity.",
        )
    except Exception:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="urlhaus",
            provider_name="URLhaus",
            category="Threat Intelligence",
            critical=False,
            error_type="CONNECTION_REFUSED",
            latency_ms=latency,
            custom_message="Unable to connect to the configured service.",
        )


# ==========================================
# 6. DNS Probe
# ==========================================
def probe_dns() -> dict[str, Any]:
    """Test DNS resolution engine via dnspython."""
    t0 = time.time()
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        resolver.resolve("one.one.one.one", "A")
        latency = round((time.time() - t0) * 1000)
        now_iso = datetime.now(timezone.utc).isoformat()
        return sanitize_secrets({
            "id": "dns",
            "name": "DNS",
            "category": "Network & DNS",
            "critical": False,
            "status": STATUS_CONNECTED,
            "status_label": STATUS_LABELS[STATUS_CONNECTED],
            "configured": True,
            "tested": True,
            "latency_ms": latency,
            "last_checked": now_iso,
            "message": "dnspython active; live queries resolved successfully.",
            "guidance": None,
            "technical_details": {
                "provider": "DNS",
                "http_status": None,
                "failure_type": "NONE",
                "latency_ms": latency,
                "last_checked": now_iso,
                "request_id": generate_request_id("dns"),
            },
        })
    except Exception:
        latency = round((time.time() - t0) * 1000)
        return format_error_state(
            provider_id="dns",
            provider_name="DNS",
            category="Network & DNS",
            critical=False,
            error_type="DNS_ERROR",
            latency_ms=latency,
            custom_message="DNS lookup could not be completed.",
            custom_guidance="Verify system DNS configuration and network gateway.",
        )


# ==========================================
# 7. RDAP/WHOIS Probe
# ==========================================
def probe_whois() -> dict[str, Any]:
    """Test WHOIS / RDAP python inspection module."""
    try:
        import whois
        now_iso = datetime.now(timezone.utc).isoformat()
        return sanitize_secrets({
            "id": "whois",
            "name": "RDAP/WHOIS",
            "category": "Network & DNS",
            "critical": False,
            "status": STATUS_AVAILABLE,
            "status_label": STATUS_LABELS[STATUS_AVAILABLE],
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": now_iso,
            "message": "python-whois module active for domain lifecycle inspection.",
            "guidance": None,
            "technical_details": {
                "provider": "RDAP/WHOIS",
                "http_status": None,
                "failure_type": "NONE",
                "latency_ms": None,
                "last_checked": now_iso,
                "request_id": generate_request_id("who"),
            },
        })
    except ImportError:
        return format_error_state(
            provider_id="whois",
            provider_name="RDAP/WHOIS",
            category="Network & DNS",
            critical=False,
            error_type="NOT_INSTALLED",
            custom_message="Domain registration information is temporarily unavailable.",
            custom_guidance="Install python-whois module in the virtual environment.",
        )


# ==========================================
# 8. YARA Probe
# ==========================================
def probe_yara() -> dict[str, Any]:
    """Check YARA static analysis engine availability."""
    try:
        import yara
        now_iso = datetime.now(timezone.utc).isoformat()
        return sanitize_secrets({
            "id": "yara",
            "name": "YARA",
            "category": "File Analysis",
            "critical": False,
            "status": STATUS_AVAILABLE,
            "status_label": STATUS_LABELS[STATUS_AVAILABLE],
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": now_iso,
            "message": "yara-python active for static file rule matching.",
            "guidance": None,
            "technical_details": {
                "provider": "YARA",
                "http_status": None,
                "failure_type": "NONE",
                "latency_ms": None,
                "last_checked": now_iso,
                "request_id": generate_request_id("yar"),
            },
        })
    except ImportError:
        return format_error_state(
            provider_id="yara",
            provider_name="YARA",
            category="File Analysis",
            critical=False,
            error_type="NOT_INSTALLED",
            custom_message="The required local component is not installed.",
            custom_guidance="Install yara-python in backend environment to enable static rule matching.",
        )


# ==========================================
# 9. tshark Probe
# ==========================================
def probe_tshark() -> dict[str, Any]:
    """Check Wireshark tshark CLI binary availability."""
    custom_path = (settings.tshark_path or "").strip()
    binary = None
    if custom_path and os.path.exists(custom_path):
        binary = custom_path
    else:
        binary = shutil.which("tshark") or shutil.which("tshark.exe")

    if binary:
        now_iso = datetime.now(timezone.utc).isoformat()
        return sanitize_secrets({
            "id": "tshark",
            "name": "tshark",
            "category": "PCAP Analysis",
            "critical": False,
            "status": STATUS_AVAILABLE,
            "status_label": STATUS_LABELS[STATUS_AVAILABLE],
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": now_iso,
            "message": f"tshark binary detected at {binary}",
            "guidance": None,
            "technical_details": {
                "provider": "tshark",
                "http_status": None,
                "failure_type": "NONE",
                "latency_ms": None,
                "last_checked": now_iso,
                "request_id": generate_request_id("tsh"),
            },
        })
    return format_error_state(
        provider_id="tshark",
        provider_name="tshark",
        category="PCAP Analysis",
        critical=False,
        error_type="NOT_INSTALLED",
        custom_message="The required local component is not installed.",
        custom_guidance="Install Wireshark / tshark on the host system to enable advanced dissection.",
    )


# ==========================================
# 10. PyShark Probe
# ==========================================
def probe_pyshark() -> dict[str, Any]:
    """Check PyShark python wrapper availability."""
    try:
        import pyshark
        now_iso = datetime.now(timezone.utc).isoformat()
        return sanitize_secrets({
            "id": "pyshark",
            "name": "PyShark",
            "category": "PCAP Analysis",
            "critical": False,
            "status": STATUS_AVAILABLE,
            "status_label": STATUS_LABELS[STATUS_AVAILABLE],
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": now_iso,
            "message": "PyShark active.",
            "guidance": None,
            "technical_details": {
                "provider": "PyShark",
                "http_status": None,
                "failure_type": "NONE",
                "latency_ms": None,
                "last_checked": now_iso,
                "request_id": generate_request_id("pys"),
            },
        })
    except ImportError:
        return format_error_state(
            provider_id="pyshark",
            provider_name="PyShark",
            category="PCAP Analysis",
            critical=False,
            error_type="NOT_INSTALLED",
            custom_message="The required local component is not installed.",
            custom_guidance="Install pyshark in virtual environment.",
        )


# ==========================================
# 11. Scapy Probe
# ==========================================
def probe_scapy() -> dict[str, Any]:
    """Check Scapy offline packet analysis engine."""
    try:
        import scapy
        version = getattr(scapy, "__version__", "active")
        now_iso = datetime.now(timezone.utc).isoformat()
        return sanitize_secrets({
            "id": "scapy",
            "name": "Scapy",
            "category": "PCAP Analysis",
            "critical": False,
            "status": STATUS_AVAILABLE,
            "status_label": STATUS_LABELS[STATUS_AVAILABLE],
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": now_iso,
            "message": f"Scapy {version} active for defensive offline PCAP parsing.",
            "guidance": None,
            "technical_details": {
                "provider": "Scapy",
                "http_status": None,
                "failure_type": "NONE",
                "latency_ms": None,
                "last_checked": now_iso,
                "request_id": generate_request_id("scp"),
            },
        })
    except ImportError:
        return format_error_state(
            provider_id="scapy",
            provider_name="Scapy",
            category="PCAP Analysis",
            critical=False,
            error_type="NOT_INSTALLED",
            custom_message="The required local component is not installed.",
            custom_guidance="Install scapy in virtual environment.",
        )


# ==========================================
# 12. Burp Suite Probe
# ==========================================
def probe_burpsuite() -> dict[str, Any]:
    """Burp Suite external finding ingestion capability."""
    now_iso = datetime.now(timezone.utc).isoformat()
    return sanitize_secrets({
        "id": "burpsuite",
        "name": "Burp Suite",
        "category": "Web Security",
        "critical": False,
        "status": STATUS_MANUAL,
        "status_label": STATUS_LABELS[STATUS_MANUAL],
        "configured": True,
        "tested": True,
        "latency_ms": None,
        "last_checked": now_iso,
        "message": "External authorized testing tool; manual finding import enabled.",
        "guidance": None,
        "technical_details": {
            "provider": "Burp Suite",
            "http_status": None,
            "failure_type": "MANUAL_INGESTION",
            "latency_ms": None,
            "last_checked": now_iso,
            "request_id": generate_request_id("brp"),
        },
    })


PROBERS = {
    "virustotal": probe_virustotal,
    "abuseipdb": probe_abuseipdb,
    "splunk": probe_splunk,
    "otx": probe_otx,
    "urlhaus": probe_urlhaus,
    "dns": probe_dns,
    "whois": probe_whois,
    "yara": probe_yara,
    "tshark": probe_tshark,
    "pyshark": probe_pyshark,
    "scapy": probe_scapy,
    "burpsuite": probe_burpsuite,
}

ORDERED_PROVIDER_IDS = [
    "virustotal",
    "abuseipdb",
    "splunk",
    "otx",
    "urlhaus",
    "dns",
    "whois",
    "yara",
    "tshark",
    "pyshark",
    "scapy",
    "burpsuite",
]


def get_unverified_fallback(provider_id: str) -> dict[str, Any]:
    """Return default diagnostic entry if configured but not yet tested."""
    if provider_id == "splunk":
        configured = bool(settings.splunk_hec_url and settings.splunk_hec_token)
        st = STATUS_NOT_VERIFIED if configured else STATUS_NOT_CONFIGURED
        return {
            "id": "splunk",
            "name": "Splunk HEC",
            "category": "SIEM",
            "critical": True,
            "status": st,
            "status_label": STATUS_LABELS[st],
            "configured": configured,
            "tested": False,
            "endpoint": settings.splunk_hec_url or "Not configured",
            "tcp": "NOT TESTED",
            "hec_health": "NOT TESTED",
            "authentication": "NOT TESTED",
            "test_event": "NOT TESTED",
            "ack_status": "NOT TESTED",
            "latency_ms": None,
            "last_checked": None,
            "message": "Configured in environment, awaiting verification probe." if configured else "Splunk HEC not configured.",
            "guidance": "Click [ Test ] to execute live verification probe." if configured else "Configure SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN.",
            "technical_details": {
                "provider": "Splunk HEC",
                "http_status": None,
                "failure_type": "NOT_VERIFIED" if configured else "NOT_CONFIGURED",
                "latency_ms": None,
                "last_checked": None,
                "request_id": generate_request_id("spk"),
            },
        }
    elif provider_id == "virustotal":
        configured = bool(settings.virus_total_api_key or settings.virustotal_api_key)
        st = STATUS_NOT_VERIFIED if configured else STATUS_NOT_CONFIGURED
        return {
            "id": "virustotal",
            "name": "VirusTotal",
            "category": "Threat Intelligence",
            "critical": True,
            "status": st,
            "status_label": STATUS_LABELS[st],
            "configured": configured,
            "tested": False,
            "real_probe": "NOT TESTED",
            "latency_ms": None,
            "last_checked": None,
            "message": "API key present, awaiting verification probe." if configured else "VirusTotal API key not configured.",
            "guidance": "Click [ Test ] to verify credentials with a safe read-only probe." if configured else "Add VIRUS_TOTAL_API_KEY to settings.",
            "technical_details": {
                "provider": "VirusTotal",
                "http_status": None,
                "failure_type": "NOT_VERIFIED" if configured else "NOT_CONFIGURED",
                "latency_ms": None,
                "last_checked": None,
                "request_id": generate_request_id("vt"),
            },
        }
    elif provider_id == "abuseipdb":
        configured = bool(settings.abuseipdb_api_key)
        st = STATUS_NOT_VERIFIED if configured else STATUS_NOT_CONFIGURED
        return {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "category": "Threat Intelligence",
            "critical": True,
            "status": st,
            "status_label": STATUS_LABELS[st],
            "configured": configured,
            "tested": False,
            "real_probe": "NOT TESTED",
            "latency_ms": None,
            "last_checked": None,
            "message": "API key present, awaiting verification probe." if configured else "AbuseIPDB API key not configured.",
            "guidance": "Click [ Test ] to verify credentials." if configured else "Add ABUSEIPDB_API_KEY to settings.",
            "technical_details": {
                "provider": "AbuseIPDB",
                "http_status": None,
                "failure_type": "NOT_VERIFIED" if configured else "NOT_CONFIGURED",
                "latency_ms": None,
                "last_checked": None,
                "request_id": generate_request_id("aip"),
            },
        }
    elif provider_id == "otx":
        configured = bool(settings.otx_api_key)
        st = STATUS_NOT_VERIFIED if configured else STATUS_NOT_CONFIGURED
        return {
            "id": "otx",
            "name": "AlienVault OTX",
            "category": "Threat Intelligence",
            "critical": False,
            "status": st,
            "status_label": STATUS_LABELS[st],
            "configured": configured,
            "tested": False,
            "latency_ms": None,
            "last_checked": None,
            "message": "API key present, awaiting verification probe." if configured else "AlienVault OTX key not configured.",
            "guidance": "Click [ Test ] to verify credentials." if configured else "Add OTX_API_KEY to settings.",
            "technical_details": {
                "provider": "AlienVault OTX",
                "http_status": None,
                "failure_type": "NOT_VERIFIED" if configured else "NOT_CONFIGURED",
                "latency_ms": None,
                "last_checked": None,
                "request_id": generate_request_id("otx"),
            },
        }

    # For local tools, probe directly
    prober = PROBERS.get(provider_id)
    if prober:
        return prober()

    return {
        "id": provider_id,
        "name": provider_id.capitalize(),
        "category": "General",
        "critical": False,
        "status": STATUS_NOT_CONFIGURED,
        "status_label": STATUS_LABELS[STATUS_NOT_CONFIGURED],
        "configured": False,
        "tested": False,
        "latency_ms": None,
        "last_checked": None,
        "message": "Provider unknown.",
        "guidance": None,
        "technical_details": {
            "provider": provider_id,
            "http_status": None,
            "failure_type": "UNKNOWN_PROVIDER",
            "latency_ms": None,
            "last_checked": None,
            "request_id": generate_request_id("unk"),
        },
    }


def test_single_provider(provider_id: str) -> dict[str, Any]:
    """Execute live probe for a single provider, update cache, and return sanitized diagnostic."""
    pid = provider_id.lower().replace("-", "").replace("_", "")
    alias_map = {
        "vt": "virustotal",
        "virustotal": "virustotal",
        "abuseipdb": "abuseipdb",
        "splunk": "splunk",
        "splunkhec": "splunk",
        "otx": "otx",
        "alienvault": "otx",
        "alienvaultotx": "otx",
        "urlhaus": "urlhaus",
        "dns": "dns",
        "whois": "whois",
        "rdap": "whois",
        "rdapwhois": "whois",
        "yara": "yara",
        "tshark": "tshark",
        "pyshark": "pyshark",
        "scapy": "scapy",
        "burp": "burpsuite",
        "burpsuite": "burpsuite",
    }
    normalized_id = alias_map.get(pid, pid)
    prober = PROBERS.get(normalized_id)
    if not prober:
        raise ValueError(f"Unknown provider '{provider_id}'")

    result = prober()
    sanitized = sanitize_secrets(result)
    _DIAGNOSTICS_CACHE[normalized_id] = sanitized
    return sanitized


def get_all_integration_diagnostics(run_probe: bool = True) -> list[dict[str, Any]]:
    """
    Return diagnostic reports for all 12 security integrations.
    If run_probe is True, probes execute in parallel.
    One provider failure does NOT fail or cancel other integrations.
    """
    from concurrent.futures import ThreadPoolExecutor

    if run_probe:
        with ThreadPoolExecutor(max_workers=len(ORDERED_PROVIDER_IDS)) as executor:
            future_to_id = {executor.submit(PROBERS[pid]): pid for pid in ORDERED_PROVIDER_IDS}
            for future in future_to_id:
                pid = future_to_id[future]
                try:
                    res = future.result()
                except Exception as exc:
                    logger.warning("Diagnostics probe failed for %s: %s", pid, type(exc).__name__)
                    res = format_error_state(
                        provider_id=pid,
                        provider_name=pid.capitalize(),
                        category="Error",
                        critical=pid in ("virustotal", "abuseipdb", "splunk"),
                        error_type="UNKNOWN",
                        custom_message="The integration test could not be completed.",
                        custom_guidance="Retry the test for this provider.",
                    )
                _DIAGNOSTICS_CACHE[pid] = sanitize_secrets(res)

    results = []
    for pid in ORDERED_PROVIDER_IDS:
        if pid in _DIAGNOSTICS_CACHE:
            results.append(_DIAGNOSTICS_CACHE[pid])
        else:
            fallback = get_unverified_fallback(pid)
            results.append(sanitize_secrets(fallback))

    return results
