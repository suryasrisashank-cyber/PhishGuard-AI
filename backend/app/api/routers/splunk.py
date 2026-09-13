"""
PhishGuard AI — Splunk Router
Exposes Splunk status, connection testing, event forwarding, and sample SPL searches.
Never exposes Splunk HEC tokens or internal credentials.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any, Optional
from ...services.splunk_service import splunk_service
from ...core.config import settings

router = APIRouter()


class SplunkSendRequest(BaseModel):
    event_type: str = "manual_event"
    sourcetype: Optional[str] = None
    data: dict[str, Any]


@router.get("/status")
def get_splunk_status():
    """Return runtime status of Splunk integration without exposing secrets."""
    is_conf = splunk_service.is_configured
    return {
        "configured": is_conf,
        "host_configured": bool(settings.splunk_host or settings.splunk_hec_url),
        "index": settings.splunk_index,
        "default_sourcetype": settings.splunk_sourcetype,
        "verify_tls": settings.splunk_verify_tls,
        "status": "CONFIGURED" if is_conf else "NOT CONFIGURED",
    }


@router.post("/test")
def test_splunk_connection():
    """Execute live non-destructive health probe against Splunk HEC."""
    return splunk_service.test_connection()


@router.post("/send")
def send_splunk_event(payload: SplunkSendRequest):
    """Forward a custom or normalized security event to Splunk HEC."""
    result = splunk_service.send_event(
        event_data=payload.data,
        sourcetype=payload.sourcetype,
        event_type=payload.event_type,
    )
    return result


@router.get("/spl-examples")
def get_spl_examples():
    """Return verified Splunk SPL search queries tailored to PhishGuard schemas."""
    index = settings.splunk_index or "phishguard"
    return {
        "index": index,
        "searches": [
            {
                "title": "Critical Phishing Detections",
                "description": "Find all high/critical detections flagged by PhishGuard",
                "spl": f'index={index} sourcetype="phishguard:scan" severity="CRITICAL"',
            },
            {
                "title": "High-Risk Indicator Aggregation",
                "description": "Filter scans with risk score >= 75 and count by target domain",
                "spl": f'index={index} sourcetype="phishguard:scan" risk_score>=75 | stats count by target, severity | sort - count',
            },
            {
                "title": "MITRE ATT&CK Technique Distribution",
                "description": "Visualize attack techniques observed across incoming scans",
                "spl": f'index={index} sourcetype="phishguard:scan" | stats count by mitre_techniques{{}}',
            },
            {
                "title": "Threat Trend Over Time",
                "description": "Hourly count of phishing detections",
                "spl": f'index={index} sourcetype="phishguard:scan" | timechart span=1h count by verdict',
            },
            {
                "title": "Malicious PCAP Network Indicators",
                "description": "Correlate packet capture analysis indicators with external IPs",
                "spl": f'index={index} sourcetype="phishguard:pcap" | stats count by destination_ip, protocol',
            },
            {
                "title": "File Hash Reputation Alerts",
                "description": "Investigate files flagged with high confidence",
                "spl": f'index={index} sourcetype="phishguard:file" verdict="Malicious" | table time, file_name, sha256, risk_score',
            },
        ],
    }
