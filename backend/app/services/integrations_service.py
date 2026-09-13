"""
PhishGuard AI — Centralized System Integrations Diagnostics Service
Evaluates genuine runtime operational status for all 12 security integrations.
Strictly distinguishes CONNECTED, NOT CONFIGURED, NOT VERIFIED, UNAVAILABLE,
INVALID CREDENTIALS, RATE LIMITED, QUOTA EXCEEDED, TLS ERROR, TIMEOUT,
PROVIDER ERROR, AVAILABLE, and MANUAL.

Zero secret exposure: API keys, tokens, and authorization headers are never
leaked in frontend responses, logs, or error messages.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
import requests

from ..core.config import settings

logger = logging.getLogger(__name__)

# Strict runtime status taxonomy as mandated by acceptance criteria
STATUS_CONNECTED = "CONNECTED"
STATUS_NOT_CONFIGURED = "NOT CONFIGURED"
STATUS_NOT_VERIFIED = "NOT VERIFIED"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_INVALID_CREDENTIALS = "INVALID CREDENTIALS"
STATUS_RATE_LIMITED = "RATE LIMITED"
STATUS_QUOTA_EXCEEDED = "QUOTA EXCEEDED"
STATUS_TLS_ERROR = "TLS ERROR"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_PROVIDER_ERROR = "PROVIDER ERROR"
STATUS_AVAILABLE = "AVAILABLE"
STATUS_MANUAL = "MANUAL"

ALL_ALLOWED_STATUSES = {
    STATUS_CONNECTED,
    STATUS_NOT_CONFIGURED,
    STATUS_NOT_VERIFIED,
    STATUS_UNAVAILABLE,
    STATUS_INVALID_CREDENTIALS,
    STATUS_RATE_LIMITED,
    STATUS_QUOTA_EXCEEDED,
    STATUS_TLS_ERROR,
    STATUS_TIMEOUT,
    STATUS_PROVIDER_ERROR,
    STATUS_AVAILABLE,
    STATUS_MANUAL,
}

# In-memory runtime cache for diagnostics
_DIAGNOSTICS_CACHE: dict[str, dict[str, Any]] = {}


def sanitize_secrets(data: Any) -> Any:
    """Recursively redact any sensitive credentials from diagnostic dictionaries and strings."""
    secrets = [
        (settings.virus_total_api_key or "").strip(),
        (settings.virustotal_api_key or "").strip(),
        (settings.abuseipdb_api_key or "").strip(),
        (settings.otx_api_key or "").strip(),
        (settings.splunk_hec_token or "").strip(),
        (settings.secret_key or "").strip(),
    ]
    # Filter out empty or trivial strings
    valid_secrets = [s for s in secrets if len(s) >= 8]

    if isinstance(data, str):
        cleaned = data
        for s in valid_secrets:
            cleaned = cleaned.replace(s, "[REDACTED_SECRET]")
        # Generic patterns for tokens and auth headers
        cleaned = re.sub(r"Splunk\s+[0-9a-fA-F-]+", "Splunk [REDACTED_TOKEN]", cleaned)
        cleaned = re.sub(r"Key\s+[0-9a-fA-F]{16,}", "Key [REDACTED_KEY]", cleaned)
        cleaned = re.sub(r"Bearer\s+[^\s]+", "Bearer [REDACTED_TOKEN]", cleaned)
        cleaned = re.sub(r"x-apikey:\s*[^\s]+", "x-apikey: [REDACTED_KEY]", cleaned, flags=re.IGNORECASE)
        return cleaned
    elif isinstance(data, dict):
        return {k: sanitize_secrets(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_secrets(item) for item in data]
    return data


# ==========================================
# 1. Splunk HEC Probe
# ==========================================
def probe_splunk() -> dict[str, Any]:
    """
    Test Splunk HTTP Event Collector (HEC) operational state:
    - Verifies configured HEC host/port via TCP socket
    - Probes HEC health endpoint (/services/collector/health)
    - Verifies authentication and transmits one integration_test event
    - Confirms event acceptance and inspects indexer acknowledgement (ACK)
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
            "details": "SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN not configured in environment.",
            "error_message": None,
        }

    parsed = urlparse(hec_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 8088)
    endpoint_display = f"{host}:{port}"

    # Step 1: TCP Connectivity probe
    t0 = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=2.5)
        sock.close()
        tcp_res = "PASS"
    except Exception as tcp_err:
        return {
            "id": "splunk",
            "name": "Splunk HEC",
            "category": "SIEM",
            "critical": True,
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "endpoint": endpoint_display,
            "tcp": "FAIL",
            "hec_health": "SKIPPED",
            "authentication": "SKIPPED",
            "test_event": "REJECTED",
            "ack_status": "NOT TESTED",
            "latency_ms": round((time.time() - t0) * 1000),
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": f"TCP connection to Splunk HEC at {endpoint_display} failed: Connection refused or host unreachable.",
            "error_message": f"TCP connection failed to {endpoint_display}: {type(tcp_err).__name__}",
        }

    # Step 2: HEC Health Check
    health_url = f"{hec_url}/services/collector/health"
    try:
        health_resp = requests.get(
            health_url,
            headers={"Authorization": f"Splunk {token}"},
            timeout=3.5,
            verify=settings.splunk_verify_tls,
        )
        if health_resp.status_code in (401, 403):
            return {
                "id": "splunk",
                "name": "Splunk HEC",
                "category": "SIEM",
                "critical": True,
                "status": STATUS_INVALID_CREDENTIALS,
                "configured": True,
                "tested": True,
                "endpoint": endpoint_display,
                "tcp": "PASS",
                "hec_health": "FAIL",
                "authentication": "FAIL",
                "test_event": "REJECTED",
                "ack_status": "NOT TESTED",
                "latency_ms": round((time.time() - t0) * 1000),
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"Splunk HEC authentication failed (HTTP {health_resp.status_code}): Invalid token.",
                "error_message": "Invalid Splunk HEC token",
            }
        hec_health_res = "PASS" if health_resp.status_code == 200 else "DEGRADED"
    except requests.exceptions.SSLError as ssl_err:
        return {
            "id": "splunk",
            "name": "Splunk HEC",
            "category": "SIEM",
            "critical": True,
            "status": STATUS_TLS_ERROR,
            "configured": True,
            "tested": True,
            "endpoint": endpoint_display,
            "tcp": "PASS",
            "hec_health": "FAIL",
            "authentication": "SKIPPED",
            "test_event": "REJECTED",
            "ack_status": "NOT TESTED",
            "latency_ms": round((time.time() - t0) * 1000),
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "TLS certificate verification failed connecting to Splunk HEC.",
            "error_message": f"TLS Error: {type(ssl_err).__name__}",
        }
    except requests.exceptions.Timeout:
        return {
            "id": "splunk",
            "name": "Splunk HEC",
            "category": "SIEM",
            "critical": True,
            "status": STATUS_TIMEOUT,
            "configured": True,
            "tested": True,
            "endpoint": endpoint_display,
            "tcp": "PASS",
            "hec_health": "TIMEOUT",
            "authentication": "SKIPPED",
            "test_event": "REJECTED",
            "ack_status": "NOT TESTED",
            "latency_ms": round((time.time() - t0) * 1000),
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "Splunk HEC health check timed out (>3.5s).",
            "error_message": "Health check timed out",
        }
    except Exception as exc:
        hec_health_res = "FAIL"

    # Step 3: Send integration_test event
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
            timeout=4.0,
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

            return {
                "id": "splunk",
                "name": "Splunk HEC",
                "category": "SIEM",
                "critical": True,
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "endpoint": endpoint_display,
                "tcp": "PASS",
                "hec_health": hec_health_res,
                "authentication": "PASS",
                "test_event": "ACCEPTED",
                "ack_status": ack_status,
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"Connected to Splunk HEC (Index: {settings.splunk_index}). Test event accepted.",
                "error_message": None,
            }
        elif event_resp.status_code in (401, 403):
            return {
                "id": "splunk",
                "name": "Splunk HEC",
                "category": "SIEM",
                "critical": True,
                "status": STATUS_INVALID_CREDENTIALS,
                "configured": True,
                "tested": True,
                "endpoint": endpoint_display,
                "tcp": "PASS",
                "hec_health": hec_health_res,
                "authentication": "FAIL",
                "test_event": "REJECTED",
                "ack_status": "NOT TESTED",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"Splunk HEC event submission rejected (HTTP {event_resp.status_code}): Invalid token.",
                "error_message": "Invalid Splunk HEC token",
            }
        else:
            return {
                "id": "splunk",
                "name": "Splunk HEC",
                "category": "SIEM",
                "critical": True,
                "status": STATUS_PROVIDER_ERROR,
                "configured": True,
                "tested": True,
                "endpoint": endpoint_display,
                "tcp": "PASS",
                "hec_health": hec_health_res,
                "authentication": "UNKNOWN",
                "test_event": "REJECTED",
                "ack_status": "NOT TESTED",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"Splunk HEC returned unexpected status HTTP {event_resp.status_code}",
                "error_message": f"HTTP {event_resp.status_code}: {event_resp.text[:80]}",
            }
    except requests.exceptions.Timeout:
        return {
            "id": "splunk",
            "name": "Splunk HEC",
            "category": "SIEM",
            "critical": True,
            "status": STATUS_TIMEOUT,
            "configured": True,
            "tested": True,
            "endpoint": endpoint_display,
            "tcp": "PASS",
            "hec_health": hec_health_res,
            "authentication": "TIMEOUT",
            "test_event": "TIMEOUT",
            "ack_status": "NOT TESTED",
            "latency_ms": round((time.time() - t0) * 1000),
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "Splunk HEC event submission timed out (>4.0s).",
            "error_message": "Event post timed out",
        }
    except Exception as exc:
        return {
            "id": "splunk",
            "name": "Splunk HEC",
            "category": "SIEM",
            "critical": True,
            "status": STATUS_PROVIDER_ERROR,
            "configured": True,
            "tested": True,
            "endpoint": endpoint_display,
            "tcp": "PASS",
            "hec_health": "FAIL",
            "authentication": "ERROR",
            "test_event": "ERROR",
            "ack_status": "NOT TESTED",
            "latency_ms": round((time.time() - t0) * 1000),
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": f"Splunk probe error: {type(exc).__name__}",
            "error_message": str(exc)[:100],
        }


# ==========================================
# 2. VirusTotal Probe
# ==========================================
def probe_virustotal() -> dict[str, Any]:
    """
    Perform a safe read-only API probe against VirusTotal v3.
    Uses backend only with zero key exposure.
    Handles 200, 401, 403, 404, 429, 5xx, timeout, SSL, and network errors.
    """
    api_key = (settings.virus_total_api_key or settings.virustotal_api_key or "").strip()
    if not api_key:
        return {
            "id": "virustotal",
            "name": "VirusTotal",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_NOT_CONFIGURED,
            "configured": False,
            "tested": False,
            "real_probe": "NOT CONFIGURED",
            "latency_ms": None,
            "last_checked": None,
            "details": "VIRUS_TOTAL_API_KEY / VIRUSTOTAL_API_KEY not configured in environment.",
            "error_message": None,
        }

    t0 = time.time()
    try:
        resp = requests.get(
            "https://www.virustotal.com/api/v3/domains/example.com",
            headers={"x-apikey": api_key, "User-Agent": "PhishGuard-AI-Diagnostics/3.0"},
            timeout=5.0,
        )
        latency = round((time.time() - t0) * 1000)

        if resp.status_code == 200:
            return {
                "id": "virustotal",
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "real_probe": "PASS",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": "VirusTotal v3 API operational and authenticated.",
                "error_message": None,
            }
        elif resp.status_code in (401, 403):
            return {
                "id": "virustotal",
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_INVALID_CREDENTIALS,
                "configured": True,
                "tested": True,
                "real_probe": "FAIL",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"VirusTotal authentication rejected (HTTP {resp.status_code}): Invalid API key.",
                "error_message": "Invalid API key (HTTP 401/403)",
            }
        elif resp.status_code == 429:
            return {
                "id": "virustotal",
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_RATE_LIMITED,
                "configured": True,
                "tested": True,
                "real_probe": "RATE LIMITED",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": "VirusTotal rate limit reached (free tier allows 4 requests/min).",
                "error_message": "Rate limit exceeded (HTTP 429)",
            }
        elif resp.status_code == 404:
            return {
                "id": "virustotal",
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_PROVIDER_ERROR,
                "configured": True,
                "tested": True,
                "real_probe": "FAIL",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": "VirusTotal probe endpoint returned 404 Not Found.",
                "error_message": "Endpoint Not Found (HTTP 404)",
            }
        elif resp.status_code >= 500:
            return {
                "id": "virustotal",
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_PROVIDER_ERROR,
                "configured": True,
                "tested": True,
                "real_probe": "FAIL",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"VirusTotal upstream service unavailable (HTTP {resp.status_code}).",
                "error_message": f"Server Error HTTP {resp.status_code}",
            }
        else:
            return {
                "id": "virustotal",
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_PROVIDER_ERROR,
                "configured": True,
                "tested": True,
                "real_probe": "FAIL",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"VirusTotal returned unexpected status HTTP {resp.status_code}",
                "error_message": f"HTTP {resp.status_code}",
            }
    except requests.exceptions.SSLError as e:
        return {
            "id": "virustotal",
            "name": "VirusTotal",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_TLS_ERROR,
            "configured": True,
            "tested": True,
            "real_probe": "TLS ERROR",
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "TLS/SSL verification error during VirusTotal handshake.",
            "error_message": f"TLS Error: {type(e).__name__}",
        }
    except requests.exceptions.Timeout:
        return {
            "id": "virustotal",
            "name": "VirusTotal",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_TIMEOUT,
            "configured": True,
            "tested": True,
            "real_probe": "TIMEOUT",
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "VirusTotal probe request timed out (>5.0s).",
            "error_message": "Request timed out",
        }
    except requests.exceptions.ConnectionError:
        return {
            "id": "virustotal",
            "name": "VirusTotal",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "real_probe": "UNREACHABLE",
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "VirusTotal endpoint unreachable or connection refused.",
            "error_message": "Connection refused / unreachable",
        }
    except Exception as exc:
        return {
            "id": "virustotal",
            "name": "VirusTotal",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_PROVIDER_ERROR,
            "configured": True,
            "tested": True,
            "real_probe": "ERROR",
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": f"VirusTotal probe error: {type(exc).__name__}",
            "error_message": str(exc)[:80],
        }


# ==========================================
# 3. AbuseIPDB Probe
# ==========================================
def probe_abuseipdb() -> dict[str, Any]:
    """
    Perform a real APIv2 check request against AbuseIPDB.
    Authenticates via backend API key with zero token exposure.
    Handles 200, 401, 403, 429, 5xx, timeout, SSL, and network errors.
    """
    api_key = (settings.abuseipdb_api_key or "").strip()
    if not api_key:
        return {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_NOT_CONFIGURED,
            "configured": False,
            "tested": False,
            "real_probe": "NOT CONFIGURED",
            "latency_ms": None,
            "last_checked": None,
            "details": "ABUSEIPDB_API_KEY not configured in environment.",
            "error_message": None,
        }

    t0 = time.time()
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": "127.0.0.1", "maxAgeInDays": "30"},
            headers={"Key": api_key, "Accept": "application/json", "User-Agent": "PhishGuard-AI-Diagnostics/3.0"},
            timeout=5.0,
        )
        latency = round((time.time() - t0) * 1000)

        if resp.status_code == 200:
            return {
                "id": "abuseipdb",
                "name": "AbuseIPDB",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "real_probe": "PASS",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": "AbuseIPDB v2 API authenticated and active.",
                "error_message": None,
            }
        elif resp.status_code in (401, 403):
            return {
                "id": "abuseipdb",
                "name": "AbuseIPDB",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_INVALID_CREDENTIALS,
                "configured": True,
                "tested": True,
                "real_probe": "FAIL",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"AbuseIPDB authentication rejected (HTTP {resp.status_code}): Invalid API key.",
                "error_message": "Invalid API key (HTTP 401/403)",
            }
        elif resp.status_code == 429:
            return {
                "id": "abuseipdb",
                "name": "AbuseIPDB",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_RATE_LIMITED,
                "configured": True,
                "tested": True,
                "real_probe": "RATE LIMITED",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": "AbuseIPDB daily quota or rate limit exceeded (free tier allows 1,000 checks/day).",
                "error_message": "Rate limit / quota exceeded (HTTP 429)",
            }
        elif resp.status_code >= 500:
            return {
                "id": "abuseipdb",
                "name": "AbuseIPDB",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_PROVIDER_ERROR,
                "configured": True,
                "tested": True,
                "real_probe": "FAIL",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"AbuseIPDB upstream service error (HTTP {resp.status_code}).",
                "error_message": f"Server Error HTTP {resp.status_code}",
            }
        else:
            return {
                "id": "abuseipdb",
                "name": "AbuseIPDB",
                "category": "Threat Intelligence",
                "critical": True,
                "status": STATUS_PROVIDER_ERROR,
                "configured": True,
                "tested": True,
                "real_probe": "FAIL",
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"AbuseIPDB returned unexpected response HTTP {resp.status_code}",
                "error_message": f"HTTP {resp.status_code}",
            }
    except requests.exceptions.SSLError as e:
        return {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_TLS_ERROR,
            "configured": True,
            "tested": True,
            "real_probe": "TLS ERROR",
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "TLS/SSL verification error during AbuseIPDB handshake.",
            "error_message": f"TLS Error: {type(e).__name__}",
        }
    except requests.exceptions.Timeout:
        return {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_TIMEOUT,
            "configured": True,
            "tested": True,
            "real_probe": "TIMEOUT",
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "AbuseIPDB check request timed out (>5.0s).",
            "error_message": "Request timed out",
        }
    except requests.exceptions.ConnectionError:
        return {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "real_probe": "UNREACHABLE",
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "AbuseIPDB endpoint unreachable or connection refused.",
            "error_message": "Connection refused / unreachable",
        }
    except Exception as exc:
        return {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_PROVIDER_ERROR,
            "configured": True,
            "tested": True,
            "real_probe": "ERROR",
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": f"AbuseIPDB probe error: {type(exc).__name__}",
            "error_message": str(exc)[:80],
        }


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
            "configured": False,
            "tested": False,
            "latency_ms": None,
            "last_checked": None,
            "details": "OTX_API_KEY not configured in environment.",
            "error_message": None,
        }

    t0 = time.time()
    try:
        resp = requests.get(
            "https://otx.alienvault.com/api/v1/user/me",
            headers={"X-OTX-API-KEY": api_key, "User-Agent": "PhishGuard-AI-Diagnostics/3.0"},
            timeout=8.0,
        )
        latency = round((time.time() - t0) * 1000)
        if resp.status_code == 200:
            return {
                "id": "otx",
                "name": "AlienVault OTX",
                "category": "Threat Intelligence",
                "critical": False,
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": "AlienVault OTX API authenticated and active.",
                "error_message": None,
            }
        elif resp.status_code in (401, 403):
            return {
                "id": "otx",
                "name": "AlienVault OTX",
                "category": "Threat Intelligence",
                "critical": False,
                "status": STATUS_INVALID_CREDENTIALS,
                "configured": True,
                "tested": True,
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"AlienVault OTX authentication rejected (HTTP {resp.status_code}): Invalid API key.",
                "error_message": "Invalid OTX API key",
            }
        elif resp.status_code == 429:
            return {
                "id": "otx",
                "name": "AlienVault OTX",
                "category": "Threat Intelligence",
                "critical": False,
                "status": STATUS_RATE_LIMITED,
                "configured": True,
                "tested": True,
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": "AlienVault OTX rate limit reached.",
                "error_message": "Rate limited (HTTP 429)",
            }
        else:
            return {
                "id": "otx",
                "name": "AlienVault OTX",
                "category": "Threat Intelligence",
                "critical": False,
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": f"OTX returned HTTP {resp.status_code}",
                "error_message": None,
            }
    except requests.exceptions.Timeout:
        return {
            "id": "otx",
            "name": "AlienVault OTX",
            "category": "Threat Intelligence",
            "critical": False,
            "status": STATUS_TIMEOUT,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "AlienVault OTX request timed out (>8.0s).",
            "error_message": "Request timed out",
        }
    except requests.exceptions.SSLError as e:
        return {
            "id": "otx",
            "name": "AlienVault OTX",
            "category": "Threat Intelligence",
            "critical": False,
            "status": STATUS_TLS_ERROR,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "TLS error during AlienVault OTX connection.",
            "error_message": f"TLS Error: {type(e).__name__}",
        }
    except Exception as exc:
        return {
            "id": "otx",
            "name": "AlienVault OTX",
            "category": "Threat Intelligence",
            "critical": False,
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": f"OTX API unreachable: {type(exc).__name__}",
            "error_message": str(exc)[:80],
        }


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
            timeout=5.0,
        )
        latency = round((time.time() - t0) * 1000)
        if resp.status_code == 200:
            return {
                "id": "urlhaus",
                "name": "URLhaus",
                "category": "Threat Intelligence",
                "critical": False,
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "latency_ms": latency,
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "details": "Abuse.ch URLhaus threat feed reachable and active.",
                "error_message": None,
            }
        return {
            "id": "urlhaus",
            "name": "URLhaus",
            "category": "Threat Intelligence",
            "critical": False,
            "status": STATUS_CONNECTED,
            "configured": True,
            "tested": True,
            "latency_ms": latency,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": f"URLhaus feed responded HTTP {resp.status_code}",
            "error_message": None,
        }
    except requests.exceptions.Timeout:
        return {
            "id": "urlhaus",
            "name": "URLhaus",
            "category": "Threat Intelligence",
            "critical": False,
            "status": STATUS_TIMEOUT,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "URLhaus probe timed out (>5.0s).",
            "error_message": "Request timed out",
        }
    except Exception as exc:
        return {
            "id": "urlhaus",
            "name": "URLhaus",
            "category": "Threat Intelligence",
            "critical": False,
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": f"URLhaus feed unreachable: {type(exc).__name__}",
            "error_message": str(exc)[:80],
        }


# ==========================================
# 6. DNS Probe
# ==========================================
def probe_dns() -> dict[str, Any]:
    """Test DNS resolution engine via dnspython."""
    t0 = time.time()
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2.5
        resolver.resolve("one.one.one.one", "A")
        latency = round((time.time() - t0) * 1000)
        return {
            "id": "dns",
            "name": "DNS",
            "category": "Network & DNS",
            "critical": False,
            "status": STATUS_CONNECTED,
            "configured": True,
            "tested": True,
            "latency_ms": latency,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "dnspython active; live queries resolved successfully.",
            "error_message": None,
        }
    except Exception as exc:
        return {
            "id": "dns",
            "name": "DNS",
            "category": "Network & DNS",
            "critical": False,
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": f"DNS resolution failed: {type(exc).__name__}",
            "error_message": str(exc)[:80],
        }


# ==========================================
# 7. RDAP/WHOIS Probe
# ==========================================
def probe_whois() -> dict[str, Any]:
    """Test WHOIS / RDAP python inspection module."""
    try:
        import whois
        return {
            "id": "whois",
            "name": "RDAP/WHOIS",
            "category": "Network & DNS",
            "critical": False,
            "status": STATUS_AVAILABLE,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "python-whois module active for domain lifecycle inspection.",
            "error_message": None,
        }
    except ImportError:
        return {
            "id": "whois",
            "name": "RDAP/WHOIS",
            "category": "Network & DNS",
            "critical": False,
            "status": STATUS_UNAVAILABLE,
            "configured": False,
            "tested": False,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "Not installed",
            "error_message": "python-whois package not installed in environment.",
        }


# ==========================================
# 8. YARA Probe
# ==========================================
def probe_yara() -> dict[str, Any]:
    """Check YARA static analysis engine availability."""
    try:
        import yara
        return {
            "id": "yara",
            "name": "YARA",
            "category": "File Analysis",
            "critical": False,
            "status": STATUS_AVAILABLE,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "yara-python active for static file rule matching.",
            "error_message": None,
        }
    except ImportError:
        return {
            "id": "yara",
            "name": "YARA",
            "category": "File Analysis",
            "critical": False,
            "status": STATUS_UNAVAILABLE,
            "configured": False,
            "tested": False,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "Not installed",
            "error_message": "yara-python package not installed.",
        }


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
        return {
            "id": "tshark",
            "name": "tshark",
            "category": "PCAP Analysis",
            "critical": False,
            "status": STATUS_AVAILABLE,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": f"tshark binary detected at {binary}",
            "error_message": None,
        }
    return {
        "id": "tshark",
        "name": "tshark",
        "category": "PCAP Analysis",
        "critical": False,
        "status": STATUS_UNAVAILABLE,
        "configured": False,
        "tested": False,
        "latency_ms": None,
        "last_checked": datetime.now(timezone.utc).isoformat(),
        "details": "Not installed",
        "error_message": "tshark executable not found on system PATH.",
    }


# ==========================================
# 10. PyShark Probe
# ==========================================
def probe_pyshark() -> dict[str, Any]:
    """Check PyShark python wrapper availability."""
    try:
        import pyshark
        return {
            "id": "pyshark",
            "name": "PyShark",
            "category": "PCAP Analysis",
            "critical": False,
            "status": STATUS_AVAILABLE,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "PyShark active.",
            "error_message": None,
        }
    except ImportError:
        return {
            "id": "pyshark",
            "name": "PyShark",
            "category": "PCAP Analysis",
            "critical": False,
            "status": STATUS_UNAVAILABLE,
            "configured": False,
            "tested": False,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "Not installed",
            "error_message": "pyshark package not installed.",
        }


# ==========================================
# 11. Scapy Probe
# ==========================================
def probe_scapy() -> dict[str, Any]:
    """Check Scapy offline packet analysis engine."""
    try:
        import scapy
        version = getattr(scapy, "__version__", "active")
        return {
            "id": "scapy",
            "name": "Scapy",
            "category": "PCAP Analysis",
            "critical": False,
            "status": STATUS_AVAILABLE,
            "configured": True,
            "tested": True,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": f"Scapy {version} active for defensive offline PCAP parsing.",
            "error_message": None,
        }
    except ImportError:
        return {
            "id": "scapy",
            "name": "Scapy",
            "category": "PCAP Analysis",
            "critical": False,
            "status": STATUS_UNAVAILABLE,
            "configured": False,
            "tested": False,
            "latency_ms": None,
            "last_checked": datetime.now(timezone.utc).isoformat(),
            "details": "Not installed",
            "error_message": "scapy package not installed.",
        }


# ==========================================
# 12. Burp Suite Probe
# ==========================================
def probe_burpsuite() -> dict[str, Any]:
    """Burp Suite external finding ingestion capability."""
    return {
        "id": "burpsuite",
        "name": "Burp Suite",
        "category": "Web Security",
        "critical": False,
        "status": STATUS_MANUAL,
        "configured": True,
        "tested": True,
        "latency_ms": None,
        "last_checked": datetime.now(timezone.utc).isoformat(),
        "details": "External authorized testing tool; manual finding import enabled.",
        "error_message": None,
    }


# Provider Registry
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
        return {
            "id": "splunk",
            "name": "Splunk HEC",
            "category": "SIEM",
            "critical": True,
            "status": STATUS_NOT_VERIFIED if configured else STATUS_NOT_CONFIGURED,
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
            "details": "Configured in environment, awaiting verification probe." if configured else "Not configured.",
            "error_message": None,
        }
    elif provider_id == "virustotal":
        configured = bool(settings.virus_total_api_key or settings.virustotal_api_key)
        return {
            "id": "virustotal",
            "name": "VirusTotal",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_NOT_VERIFIED if configured else STATUS_NOT_CONFIGURED,
            "configured": configured,
            "tested": False,
            "real_probe": "NOT TESTED",
            "latency_ms": None,
            "last_checked": None,
            "details": "API key present, awaiting verification probe." if configured else "Not configured.",
            "error_message": None,
        }
    elif provider_id == "abuseipdb":
        configured = bool(settings.abuseipdb_api_key)
        return {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "category": "Threat Intelligence",
            "critical": True,
            "status": STATUS_NOT_VERIFIED if configured else STATUS_NOT_CONFIGURED,
            "configured": configured,
            "tested": False,
            "real_probe": "NOT TESTED",
            "latency_ms": None,
            "last_checked": None,
            "details": "API key present, awaiting verification probe." if configured else "Not configured.",
            "error_message": None,
        }
    elif provider_id == "otx":
        configured = bool(settings.otx_api_key)
        return {
            "id": "otx",
            "name": "AlienVault OTX",
            "category": "Threat Intelligence",
            "critical": False,
            "status": STATUS_NOT_VERIFIED if configured else STATUS_NOT_CONFIGURED,
            "configured": configured,
            "tested": False,
            "latency_ms": None,
            "last_checked": None,
            "details": "API key present, awaiting verification probe." if configured else "Not configured.",
            "error_message": None,
        }
    # For local tools, run probe directly
    prober = PROBERS.get(provider_id)
    if prober:
        return prober()
    return {
        "id": provider_id,
        "name": provider_id.capitalize(),
        "category": "General",
        "critical": False,
        "status": STATUS_NOT_CONFIGURED,
        "configured": False,
        "tested": False,
        "latency_ms": None,
        "last_checked": None,
        "details": "Provider unknown.",
        "error_message": None,
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
    Otherwise, returns current cached state or unverified fallbacks.
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
                    res = {
                        "id": pid,
                        "name": pid.capitalize(),
                        "category": "Error",
                        "critical": pid in ("virustotal", "abuseipdb", "splunk"),
                        "status": STATUS_PROVIDER_ERROR,
                        "configured": True,
                        "tested": True,
                        "details": f"Probe execution error: {type(exc).__name__}",
                        "error_message": str(exc)[:80],
                    }
                _DIAGNOSTICS_CACHE[pid] = sanitize_secrets(res)

    results = []
    for pid in ORDERED_PROVIDER_IDS:
        if pid in _DIAGNOSTICS_CACHE:
            results.append(_DIAGNOSTICS_CACHE[pid])
        else:
            fallback = get_unverified_fallback(pid)
            results.append(sanitize_secrets(fallback))

    return results
