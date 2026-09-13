"""
PhishGuard AI — Real Splunk SIEM Integration (HTTP Event Collector)
Provides real structured JSON event transmission to Splunk Enterprise or Splunk Cloud.
Degrades gracefully when Splunk is not configured or offline.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional
import requests

from ..core.config import settings

logger = logging.getLogger(__name__)

# Standardized Splunk sourcetypes as per SOC specifications
SOURCETYPE_SCAN = "phishguard:scan"
SOURCETYPE_ALERT = "phishguard:alert"
SOURCETYPE_IOC = "phishguard:ioc"
SOURCETYPE_INVESTIGATION = "phishguard:investigation"
SOURCETYPE_THREATINTEL = "phishguard:threatintel"
SOURCETYPE_PCAP = "phishguard:pcap"
SOURCETYPE_FILE = "phishguard:file"


class SplunkService:
    """Manages secure communication with Splunk HTTP Event Collector (HEC)."""

    def __init__(self):
        raw_url = (settings.splunk_hec_url or "").strip().rstrip("/")
        for suffix in ["/services/collector/event", "/services/collector/raw", "/services/collector"]:
            if raw_url.endswith(suffix):
                raw_url = raw_url[:-len(suffix)].rstrip("/")
        self.hec_url = raw_url
        self.token = (settings.splunk_hec_token or "").strip()
        self.index = (settings.splunk_index or "phishguard").strip()
        self.default_sourcetype = (settings.splunk_sourcetype or SOURCETYPE_SCAN).strip()
        self.verify_tls = settings.splunk_verify_tls

    @property
    def is_configured(self) -> bool:
        return bool(self.hec_url and self.token)

    def test_connection(self) -> dict[str, Any]:
        """Test active connectivity with Splunk HEC health or raw endpoint."""
        if not self.is_configured:
            return {
                "status": "NOT CONFIGURED",
                "configured": False,
                "connected": False,
                "message": "Splunk HEC URL and Token must be provided in environment variables.",
            }

        health_endpoint = f"{self.hec_url}/services/collector/health"
        headers = {"Authorization": f"Splunk {self.token}"}
        try:
            resp = requests.get(health_endpoint, headers=headers, timeout=4.0, verify=self.verify_tls)
            if resp.status_code == 200:
                return {
                    "status": "CONNECTED",
                    "configured": True,
                    "connected": True,
                    "message": f"Successfully connected to Splunk HEC. Target index: '{self.index}'.",
                }
            elif resp.status_code in (401, 403):
                return {
                    "status": "ERROR",
                    "configured": True,
                    "connected": False,
                    "message": f"Splunk rejected token (HTTP {resp.status_code}). Please verify SPLUNK_HEC_TOKEN.",
                }
            else:
                return {
                    "status": "ERROR",
                    "configured": True,
                    "connected": False,
                    "message": f"Splunk returned HTTP {resp.status_code}: {resp.text[:100]}",
                }
        except requests.exceptions.ConnectionError:
            return {
                "status": "UNAVAILABLE",
                "configured": True,
                "connected": False,
                "message": "Could not establish connection to Splunk host (Connection refused).",
            }
        except requests.exceptions.Timeout:
            return {
                "status": "UNAVAILABLE",
                "configured": True,
                "connected": False,
                "message": "Splunk HEC request timed out after 4 seconds.",
            }
        except Exception as exc:
            return {
                "status": "ERROR",
                "configured": True,
                "connected": False,
                "message": f"Splunk error: {type(exc).__name__} - {str(exc)[:150]}",
            }

    def send_event(
        self,
        event_data: dict[str, Any],
        sourcetype: Optional[str] = None,
        event_type: str = "security_event",
    ) -> dict[str, Any]:
        """Transmit a normalized structured event to Splunk HEC."""
        if not self.is_configured:
            logger.info("Splunk HEC not configured. Event not forwarded.")
            return {
                "status": "NOT CONFIGURED",
                "sent": False,
                "message": "Splunk HEC is not configured.",
            }

        endpoint = f"{self.hec_url}/services/collector/event"
        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json",
        }

        st = sourcetype or self.default_sourcetype

        # Standard Splunk event wrapper
        payload = {
            "time": time.time(),
            "host": "phishguard-soc",
            "source": "phishguard",
            "sourcetype": st,
            "index": self.index,
            "event": {
                "event_type": event_type,
                **event_data,
            },
        }

        try:
            resp = requests.post(endpoint, headers=headers, json=payload, timeout=4.0, verify=self.verify_tls)
            if resp.status_code == 200:
                logger.info(f"Successfully sent {st} event to Splunk HEC")
                return {
                    "status": "CONNECTED",
                    "sent": True,
                    "sourcetype": st,
                    "index": self.index,
                    "message": "Event indexed by Splunk HEC successfully.",
                }
            elif resp.status_code in (401, 403):
                logger.warning(f"Splunk HEC auth failure: HTTP {resp.status_code}")
                return {
                    "status": "ERROR",
                    "sent": False,
                    "message": f"Splunk authorization failed (HTTP {resp.status_code}).",
                }
            else:
                logger.warning(f"Splunk HEC error HTTP {resp.status_code}: {resp.text[:100]}")
                return {
                    "status": "ERROR",
                    "sent": False,
                    "message": f"Splunk HEC returned HTTP {resp.status_code}.",
                }
        except requests.exceptions.ConnectionError:
            return {
                "status": "UNAVAILABLE",
                "sent": False,
                "message": "Splunk HEC server unreachable (Connection refused).",
            }
        except requests.exceptions.Timeout:
            return {
                "status": "UNAVAILABLE",
                "sent": False,
                "message": "Splunk event dispatch timed out.",
            }
        except Exception as exc:
            return {
                "status": "ERROR",
                "sent": False,
                "message": f"Splunk transmission error: {type(exc).__name__}",
            }

    def send_scan_event(self, scan: dict[str, Any]) -> dict[str, Any]:
        """Normalize and forward a completed detection scan to Splunk."""
        normalized = {
            "scan_id": f"PG-SCAN-{scan.get('id', 'N/A')}",
            "scan_type": scan.get("scan_type", "url"),
            "target": scan.get("target", ""),
            "verdict": scan.get("verdict", "Unknown"),
            "risk_score": scan.get("risk_score", 0.0),
            "confidence_score": scan.get("confidence_score", 0.0),
            "severity": scan.get("severity", "INFORMATIONAL"),
            "mitre_techniques": scan.get("mitre_techniques") or [],
            "indicators_count": len(scan.get("indicators") or []),
            "engine_version": scan.get("detection_engine_version", "3.0.0"),
        }
        return self.send_event(normalized, sourcetype=SOURCETYPE_SCAN, event_type="phishing_detection")

    def send_alert_event(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Forward a high or critical security alert to Splunk."""
        return self.send_event(alert, sourcetype=SOURCETYPE_ALERT, event_type="soc_alert")

    def send_investigation_event(self, case: dict[str, Any]) -> dict[str, Any]:
        """Forward an investigation case state update to Splunk."""
        return self.send_event(case, sourcetype=SOURCETYPE_INVESTIGATION, event_type="soc_case_update")


# Global singleton instance
splunk_service = SplunkService()
