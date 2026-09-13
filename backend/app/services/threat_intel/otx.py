"""
PhishGuard AI — AlienVault OTX Provider Adapter
Queries OTX pulse count, targeted threat groups, and adversary intelligence.
"""
from __future__ import annotations

import logging
from typing import Any
import requests

from .base import ThreatIntelProvider
from ...core.config import settings

logger = logging.getLogger(__name__)


class OTXProvider(ThreatIntelProvider):
    name = "AlienVault OTX"
    category = "Threat Intelligence"

    def __init__(self):
        self.api_key = (settings.otx_api_key or "").strip()
        self.base_url = "https://otx.alienvault.com/api/v1"

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
                "details": "OTX_API_KEY is not configured.",
            }
        try:
            resp = requests.get(f"{self.base_url}/user/me", headers={"X-OTX-API-KEY": self.api_key}, timeout=4.0)
            if resp.status_code == 200:
                return {"name": self.name, "status": "CONNECTED", "configured": True, "tested": True, "details": "AlienVault OTX connected."}
            elif resp.status_code in (401, 403):
                return {"name": self.name, "status": "ERROR", "configured": True, "tested": True, "details": "OTX API key rejected."}
            return {"name": self.name, "status": "AVAILABLE", "configured": True, "tested": True, "details": f"OTX HTTP {resp.status_code}"}
        except Exception as e:
            return {"name": self.name, "status": "UNAVAILABLE", "configured": True, "tested": True, "details": str(e)[:100]}

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        if not self.is_configured:
            return self._format_result(domain, "DOMAIN", "NOT CONFIGURED", "OTX API key not configured in environment.")

        url = f"{self.base_url}/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                pulses_count = pulse_info.get("count", 0)
                references = pulse_info.get("pulses", [])[:3]
                pulse_names = [p.get("name") for p in references if p.get("name")]

                verdict = "MALICIOUS" if pulses_count >= 2 else ("SUSPICIOUS" if pulses_count == 1 else "BENIGN")
                interp = f"AlienVault OTX identified {pulses_count} threat pulse(s) linked to this domain."
                return self._format_result(
                    indicator=domain,
                    indicator_type="DOMAIN",
                    verdict=verdict,
                    interpretation=interp,
                    raw_reputation={"pulse_count": pulses_count, "related_pulses": pulse_names},
                    confidence=min(95.0, 50.0 + (pulses_count * 15)),
                    details={"alexa": data.get("alexa"), "whois": data.get("whois")},
                )
            return self._format_result(domain, "DOMAIN", "UNKNOWN" if resp.status_code == 404 else "ERROR", f"OTX HTTP {resp.status_code}")
        except Exception as exc:
            return self._format_result(domain, "DOMAIN", "ERROR", f"OTX error: {type(exc).__name__}")

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        if not self.is_configured:
            return self._format_result(ip, "IPv4", "NOT CONFIGURED", "OTX API key not configured.")

        url = f"{self.base_url}/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                verdict = "MALICIOUS" if pulse_count >= 2 else ("SUSPICIOUS" if pulse_count == 1 else "BENIGN")
                return self._format_result(
                    indicator=ip,
                    indicator_type="IPv4",
                    verdict=verdict,
                    interpretation=f"AlienVault OTX identified {pulse_count} pulse(s) for IP {ip}.",
                    raw_reputation={"pulse_count": pulse_count},
                    details={"country_code": data.get("country_code"), "asn": data.get("asn")},
                )
            return self._format_result(ip, "IPv4", "UNKNOWN" if resp.status_code == 404 else "ERROR", f"OTX HTTP {resp.status_code}")
        except Exception as exc:
            return self._format_result(ip, "IPv4", "ERROR", f"OTX error: {type(exc).__name__}")
