"""
PhishGuard AI — AbuseIPDB Provider Adapter (API v2)
Queries IP reputation, abuse confidence scores, and historical reports.
"""
from __future__ import annotations

import logging
from typing import Any
import requests

from .base import ThreatIntelProvider
from ...core.config import settings

logger = logging.getLogger(__name__)


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "AbuseIPDB"
    category = "Threat Intelligence"

    def __init__(self):
        self.api_key = (settings.abuseipdb_api_key or "").strip()
        self.base_url = "https://api.abuseipdb.com/api/v2"

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def check_status(self) -> dict[str, Any]:
        if not self.is_configured:
            return {
                "name": self.name,
                "status": "NOT CONFIGURED",
                "configured": False,
                "tested": False,
                "details": "AbuseIPDB API key not configured.",
            }
        try:
            resp = requests.get(
                f"{self.base_url}/check",
                params={"ipAddress": "127.0.0.1"},
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=4.0,
            )
            if resp.status_code == 200:
                return {"name": self.name, "status": "CONNECTED", "configured": True, "tested": True, "details": "AbuseIPDB v2 API active."}
            elif resp.status_code in (401, 403):
                return {"name": self.name, "status": "ERROR", "configured": True, "tested": True, "details": "AbuseIPDB key unauthorized."}
            return {"name": self.name, "status": "AVAILABLE", "configured": True, "tested": True, "details": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"name": self.name, "status": "UNAVAILABLE", "configured": True, "tested": True, "details": str(e)[:100]}

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        if not self.is_configured:
            return self._format_result(ip, "IPv4", "NOT CONFIGURED", "AbuseIPDB API key not configured in environment.")

        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
        try:
            resp = requests.get(f"{self.base_url}/check", headers=headers, params=params, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports_count = data.get("totalReports", 0)
                country = data.get("countryCode", "N/A")
                isp = data.get("isp", "N/A")
                domain = data.get("domain", "N/A")
                is_tor = data.get("isTor", False)

                verdict = "MALICIOUS" if score >= 50 else ("SUSPICIOUS" if score >= 20 else "BENIGN")
                interp = f"AbuseIPDB reports abuse confidence score of {score}% based on {reports_count} community report(s)."
                return self._format_result(
                    indicator=ip,
                    indicator_type="IPv4",
                    verdict=verdict,
                    interpretation=interp,
                    raw_reputation={"abuse_confidence_score": score, "total_reports": reports_count, "is_tor": is_tor},
                    confidence=float(score),
                    details={"country": country, "isp": isp, "domain": domain, "usage_type": data.get("usageType")},
                )
            elif resp.status_code in (401, 403):
                return self._format_result(ip, "IPv4", "ERROR", "AbuseIPDB authentication error: API key invalid.")
            else:
                return self._format_result(ip, "IPv4", "ERROR", f"AbuseIPDB returned HTTP {resp.status_code}")
        except Exception as exc:
            return self._format_result(ip, "IPv4", "ERROR", f"AbuseIPDB request error: {type(exc).__name__}")
