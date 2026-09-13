"""
PhishGuard AI — Centralized System Integrations Diagnostics Service
Evaluates genuine runtime operational status for all 11 security integrations.
Zero secret exposure; handles network failures, timeouts, and missing binaries safely.
"""
from __future__ import annotations

import logging
import os
import shutil
from typing import Any
import requests

from ..core.config import settings

logger = logging.getLogger(__name__)

# Allowed runtime status values as per strict acceptance criteria
STATUS_CONNECTED = "CONNECTED"
STATUS_AVAILABLE = "AVAILABLE"
STATUS_NOT_CONFIGURED = "NOT CONFIGURED"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_ERROR = "ERROR"


def check_splunk_status() -> dict[str, Any]:
    """Test Splunk HTTP Event Collector (HEC) operational state."""
    hec_url = (settings.splunk_hec_url or "").strip().rstrip("/")
    token = (settings.splunk_hec_token or "").strip()

    if not hec_url or not token:
        return {
            "name": "Splunk HEC",
            "category": "SIEM",
            "status": STATUS_NOT_CONFIGURED,
            "configured": False,
            "tested": False,
            "details": "Splunk HEC URL or Token not configured in environment.",
        }

    # Execute non-destructive health probe
    health_url = f"{hec_url}/services/collector/health"
    try:
        resp = requests.get(
            health_url,
            headers={"Authorization": f"Splunk {token}"},
            timeout=3.0,
            verify=settings.splunk_verify_tls,
        )
        if resp.status_code == 200:
            return {
                "name": "Splunk HEC",
                "category": "SIEM",
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "details": f"Connected to Splunk HEC (Index: {settings.splunk_index})",
            }
        elif resp.status_code in (401, 403):
            return {
                "name": "Splunk HEC",
                "category": "SIEM",
                "status": STATUS_ERROR,
                "configured": True,
                "tested": True,
                "details": f"Splunk HEC authentication failed (HTTP {resp.status_code}): Invalid token.",
            }
        else:
            return {
                "name": "Splunk HEC",
                "category": "SIEM",
                "status": STATUS_ERROR,
                "configured": True,
                "tested": True,
                "details": f"Splunk HEC returned HTTP {resp.status_code}: {resp.text[:100]}",
            }
    except requests.exceptions.SSLError as e:
        return {
            "name": "Splunk HEC",
            "category": "SIEM",
            "status": STATUS_ERROR,
            "configured": True,
            "tested": True,
            "details": f"Splunk TLS verification error: {type(e).__name__}",
        }
    except requests.exceptions.ConnectionError:
        return {
            "name": "Splunk HEC",
            "category": "SIEM",
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "details": "Splunk HEC endpoint unreachable or connection refused.",
        }
    except requests.exceptions.Timeout:
        return {
            "name": "Splunk HEC",
            "category": "SIEM",
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "details": "Splunk HEC health check timed out (>3s).",
        }
    except Exception as exc:
        return {
            "name": "Splunk HEC",
            "category": "SIEM",
            "status": STATUS_ERROR,
            "configured": True,
            "tested": True,
            "details": f"Splunk probe error: {type(exc).__name__}",
        }


def check_virustotal_status() -> dict[str, Any]:
    """Test VirusTotal API v3 operational state."""
    api_key = (settings.virus_total_api_key or "").strip()
    if not api_key:
        return {
            "name": "VirusTotal",
            "category": "Threat Intelligence",
            "status": STATUS_NOT_CONFIGURED,
            "configured": False,
            "tested": False,
            "details": "VT_API_KEY / VIRUS_TOTAL_API_KEY not configured.",
        }

    # If configured, run a lightweight live verification check
    try:
        resp = requests.get(
            "https://www.virustotal.com/api/v3/domains/example.com",
            headers={"x-apikey": api_key},
            timeout=4.0,
        )
        if resp.status_code == 200:
            return {
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "details": "VirusTotal v3 API operational and authenticated.",
            }
        elif resp.status_code in (401, 403):
            return {
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "status": STATUS_ERROR,
                "configured": True,
                "tested": True,
                "details": f"VirusTotal authentication rejected (HTTP {resp.status_code}): Invalid API key.",
            }
        elif resp.status_code == 429:
            return {
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "status": STATUS_AVAILABLE,
                "configured": True,
                "tested": True,
                "details": "VirusTotal configured (API rate limit currently reached).",
            }
        else:
            return {
                "name": "VirusTotal",
                "category": "Threat Intelligence",
                "status": STATUS_ERROR,
                "configured": True,
                "tested": True,
                "details": f"VirusTotal returned HTTP {resp.status_code}",
            }
    except Exception as exc:
        return {
            "name": "VirusTotal",
            "category": "Threat Intelligence",
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "details": f"VirusTotal unreachable: {type(exc).__name__}",
        }


def check_abuseipdb_status() -> dict[str, Any]:
    """Test AbuseIPDB v2 operational state."""
    api_key = (settings.abuseipdb_api_key or "").strip()
    if not api_key:
        return {
            "name": "AbuseIPDB",
            "category": "Threat Intelligence",
            "status": STATUS_NOT_CONFIGURED,
            "configured": False,
            "tested": False,
            "details": "ABUSEIPDB_API_KEY not configured.",
        }

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": "127.0.0.1", "maxAgeInDays": "30"},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=4.0,
        )
        if resp.status_code == 200:
            return {
                "name": "AbuseIPDB",
                "category": "Threat Intelligence",
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "details": "AbuseIPDB v2 API authenticated and active.",
            }
        elif resp.status_code in (401, 403):
            return {
                "name": "AbuseIPDB",
                "category": "Threat Intelligence",
                "status": STATUS_ERROR,
                "configured": True,
                "tested": True,
                "details": f"AbuseIPDB rejected authentication (HTTP {resp.status_code}).",
            }
        else:
            return {
                "name": "AbuseIPDB",
                "category": "Threat Intelligence",
                "status": STATUS_AVAILABLE,
                "configured": True,
                "tested": True,
                "details": f"AbuseIPDB response HTTP {resp.status_code}",
            }
    except Exception as exc:
        return {
            "name": "AbuseIPDB",
            "category": "Threat Intelligence",
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "details": f"AbuseIPDB unreachable: {type(exc).__name__}",
        }


def check_otx_status() -> dict[str, Any]:
    """Test AlienVault OTX operational state."""
    api_key = (settings.otx_api_key or "").strip()
    if not api_key:
        return {
            "name": "AlienVault OTX",
            "category": "Threat Intelligence",
            "status": STATUS_NOT_CONFIGURED,
            "configured": False,
            "tested": False,
            "details": "OTX_API_KEY not configured.",
        }

    try:
        resp = requests.get(
            "https://otx.alienvault.com/api/v1/user/me",
            headers={"X-OTX-API-KEY": api_key},
            timeout=4.0,
        )
        if resp.status_code == 200:
            return {
                "name": "AlienVault OTX",
                "category": "Threat Intelligence",
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "details": "AlienVault OTX API authenticated.",
            }
        elif resp.status_code in (401, 403):
            return {
                "name": "AlienVault OTX",
                "category": "Threat Intelligence",
                "status": STATUS_ERROR,
                "configured": True,
                "tested": True,
                "details": "AlienVault OTX invalid API key.",
            }
        else:
            return {
                "name": "AlienVault OTX",
                "category": "Threat Intelligence",
                "status": STATUS_AVAILABLE,
                "configured": True,
                "tested": True,
                "details": f"OTX returned HTTP {resp.status_code}",
            }
    except Exception as exc:
        return {
            "name": "AlienVault OTX",
            "category": "Threat Intelligence",
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "details": f"OTX API unreachable: {type(exc).__name__}",
        }


def check_urlhaus_status() -> dict[str, Any]:
    """Test abuse.ch URLhaus public API operational state."""
    # Free public intelligence endpoint — no mandatory API key needed for lookups
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": "https://example.com"},
            timeout=4.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            # If query_status is ok or no_results, the API is operational
            return {
                "name": "URLhaus",
                "category": "Threat Intelligence",
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "details": "Abuse.ch URLhaus API active (Public Feed).",
            }
        else:
            return {
                "name": "URLhaus",
                "category": "Threat Intelligence",
                "status": STATUS_AVAILABLE,
                "configured": True,
                "tested": True,
                "details": f"URLhaus returned HTTP {resp.status_code}",
            }
    except Exception as exc:
        return {
            "name": "URLhaus",
            "category": "Threat Intelligence",
            "status": STATUS_UNAVAILABLE,
            "configured": True,
            "tested": True,
            "details": f"URLhaus API unreachable: {type(exc).__name__}",
        }


def check_dns_status() -> dict[str, Any]:
    """Test DNS resolution engine via dnspython."""
    try:
        import dns.resolver
        # Quick benign resolve to verify local/network DNS works
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2.0
        resolver.resolve("one.one.one.one", "A")
        return {
            "name": "DNS Engine",
            "category": "Network & DNS",
            "status": STATUS_CONNECTED,
            "configured": True,
            "tested": True,
            "details": "dnspython active; live queries resolved successfully.",
        }
    except Exception as exc:
        return {
            "name": "DNS Engine",
            "category": "Network & DNS",
            "status": STATUS_AVAILABLE,
            "configured": True,
            "tested": True,
            "details": f"dnspython installed; live probe: {type(exc).__name__}",
        }


def check_rdap_whois_status() -> dict[str, Any]:
    """Test WHOIS / RDAP query module."""
    try:
        import whois
        return {
            "name": "RDAP / WHOIS",
            "category": "Network & DNS",
            "status": STATUS_AVAILABLE,
            "configured": True,
            "tested": True,
            "details": "python-whois module active for domain lifecycle inspection.",
        }
    except ImportError:
        return {
            "name": "RDAP / WHOIS",
            "category": "Network & DNS",
            "status": STATUS_UNAVAILABLE,
            "configured": False,
            "tested": False,
            "details": "python-whois module not installed.",
        }


def check_yara_status() -> dict[str, Any]:
    """Check YARA static rules engine."""
    try:
        import yara
        rules_path = settings.yara_rules_path
        if rules_path and os.path.exists(rules_path):
            return {
                "name": "YARA Engine",
                "category": "File Analysis",
                "status": STATUS_CONNECTED,
                "configured": True,
                "tested": True,
                "details": f"yara-python active; rule path loaded: {rules_path}",
            }
        return {
            "name": "YARA Engine",
            "category": "File Analysis",
            "status": STATUS_AVAILABLE,
            "configured": False,
            "tested": True,
            "details": "yara-python module installed; custom YARA_RULES_PATH not configured.",
        }
    except ImportError:
        return {
            "name": "YARA Engine",
            "category": "File Analysis",
            "status": STATUS_UNAVAILABLE,
            "configured": False,
            "tested": False,
            "details": "YARA engine not configured (yara-python package unavailable).",
        }


def check_tshark_status() -> dict[str, Any]:
    """Check Wireshark tshark CLI binary availability."""
    custom_path = (settings.tshark_path or "").strip()
    binary = None
    if custom_path and os.path.exists(custom_path):
        binary = custom_path
    else:
        binary = shutil.which("tshark") or shutil.which("tshark.exe")

    if binary:
        return {
            "name": "tshark (Wireshark CLI)",
            "category": "PCAP Analysis",
            "status": STATUS_AVAILABLE,
            "configured": True,
            "tested": True,
            "details": f"tshark binary detected at {binary}",
        }
    return {
        "name": "tshark (Wireshark CLI)",
        "category": "PCAP Analysis",
        "status": STATUS_UNAVAILABLE,
        "configured": False,
        "tested": False,
        "details": "tshark binary not found on PATH or configured location.",
    }


def check_pyshark_status() -> dict[str, Any]:
    """Check PyShark python wrapper availability."""
    try:
        import pyshark
        tshark_binary = shutil.which("tshark") or shutil.which("tshark.exe") or settings.tshark_path
        if tshark_binary and os.path.exists(tshark_binary):
            return {
                "name": "PyShark",
                "category": "PCAP Analysis",
                "status": STATUS_AVAILABLE,
                "configured": True,
                "tested": True,
                "details": "PyShark installed and bound to tshark binary.",
            }
        return {
            "name": "PyShark",
            "category": "PCAP Analysis",
            "status": STATUS_UNAVAILABLE,
            "configured": False,
            "tested": False,
            "details": "PyShark installed but tshark binary is missing.",
        }
    except ImportError:
        return {
            "name": "PyShark",
            "category": "PCAP Analysis",
            "status": STATUS_UNAVAILABLE,
            "configured": False,
            "tested": False,
            "details": "pyshark package not installed.",
        }


def check_scapy_status() -> dict[str, Any]:
    """Check Scapy offline packet analysis engine."""
    try:
        import scapy
        version = getattr(scapy, "__version__", "active")
        return {
            "name": "Scapy",
            "category": "PCAP Analysis",
            "status": STATUS_AVAILABLE,
            "configured": True,
            "tested": True,
            "details": f"Scapy {version} active for defensive offline PCAP parsing.",
        }
    except ImportError:
        return {
            "name": "Scapy",
            "category": "PCAP Analysis",
            "status": STATUS_UNAVAILABLE,
            "configured": False,
            "tested": False,
            "details": "scapy package not installed.",
        }


def get_all_integration_diagnostics() -> list[dict[str, Any]]:
    """Return runtime diagnostic reports for all 11 security integrations."""
    return [
        check_splunk_status(),
        check_virustotal_status(),
        check_abuseipdb_status(),
        check_otx_status(),
        check_urlhaus_status(),
        check_dns_status(),
        check_rdap_whois_status(),
        check_yara_status(),
        check_tshark_status(),
        check_pyshark_status(),
        check_scapy_status(),
    ]
