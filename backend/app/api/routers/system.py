"""
PhishGuard AI — System Integrations & Health Router
Exposes runtime diagnostics for security integrations without secret leakage.
"""
from fastapi import APIRouter
from ...services.integrations_service import get_all_integration_diagnostics

router = APIRouter()


@router.get("/integrations")
def list_system_integrations():
    """
    Return genuine runtime operational report for all 11 security integrations:
    Splunk HEC, VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, DNS,
    RDAP/WHOIS, YARA, tshark, PyShark, Scapy.
    """
    integrations = get_all_integration_diagnostics()
    return {
        "status": "ok",
        "count": len(integrations),
        "integrations": integrations,
    }
