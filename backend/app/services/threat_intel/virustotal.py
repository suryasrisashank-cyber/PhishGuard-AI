"""
PhishGuard AI — VirusTotal Provider Adapter (API v3)
Queries domain, IP, URL, and file hash reputation safely.
"""
from __future__ import annotations

import base64
import logging
from typing import Any
import requests

from .base import ThreatIntelProvider
from ...core.config import settings

logger = logging.getLogger(__name__)


class VirusTotalProvider(ThreatIntelProvider):
    name = "VirusTotal"
    category = "Threat Intelligence"

    def __init__(self):
        self.api_key = (settings.virus_total_api_key or "").strip()
        self.base_url = "https://www.virustotal.com/api/v3"

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
                "details": "VirusTotal API key is not configured.",
            }
        try:
            resp = requests.get(f"{self.base_url}/domains/example.com", headers={"x-apikey": self.api_key}, timeout=4.0)
            if resp.status_code == 200:
                return {"name": self.name, "status": "CONNECTED", "configured": True, "tested": True, "details": "VirusTotal API v3 connected."}
            elif resp.status_code in (401, 403):
                return {"name": self.name, "status": "ERROR", "configured": True, "tested": True, "details": "VirusTotal API key invalid."}
            else:
                return {"name": self.name, "status": "AVAILABLE", "configured": True, "tested": True, "details": f"VT HTTP {resp.status_code}"}
        except Exception as e:
            return {"name": self.name, "status": "UNAVAILABLE", "configured": True, "tested": True, "details": str(e)[:100]}

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        if not self.is_configured:
            return self._format_result(domain, "DOMAIN", "NOT CONFIGURED", "VirusTotal API key not configured in environment.")

        url = f"{self.base_url}/domains/{domain}"
        headers = {"x-apikey": self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=6.0)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                reputation = data.get("reputation", 0)

                verdict = "MALICIOUS" if malicious >= 3 else ("SUSPICIOUS" if (malicious > 0 or suspicious > 2) else "BENIGN")
                interp = f"VirusTotal flagged {malicious} malicious and {suspicious} suspicious security vendor detections."
                return self._format_result(
                    indicator=domain,
                    indicator_type="DOMAIN",
                    verdict=verdict,
                    interpretation=interp,
                    raw_reputation={"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "reputation_score": reputation},
                    confidence=min(100.0, 50.0 + (malicious * 10)),
                    details={"categories": data.get("categories", {}), "creation_date": data.get("creation_date")},
                )
            elif resp.status_code == 404:
                return self._format_result(domain, "DOMAIN", "UNKNOWN", "Domain has no prior telemetry on VirusTotal.")
            elif resp.status_code in (401, 403):
                return self._format_result(domain, "DOMAIN", "ERROR", "VirusTotal authentication error: API key rejected.")
            elif resp.status_code == 429:
                return self._format_result(domain, "DOMAIN", "UNAVAILABLE", "VirusTotal API rate limit reached.")
            else:
                return self._format_result(domain, "DOMAIN", "ERROR", f"VirusTotal returned HTTP {resp.status_code}.")
        except Exception as exc:
            return self._format_result(domain, "DOMAIN", "ERROR", f"VirusTotal network error: {type(exc).__name__}")

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        if not self.is_configured:
            return self._format_result(ip, "IPv4", "NOT CONFIGURED", "VirusTotal API key not configured.")

        url = f"{self.base_url}/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=6.0)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                verdict = "MALICIOUS" if malicious >= 2 else ("SUSPICIOUS" if malicious == 1 else "BENIGN")
                return self._format_result(
                    indicator=ip,
                    indicator_type="IPv4",
                    verdict=verdict,
                    interpretation=f"VirusTotal reports {malicious} engine detections for IP {ip}.",
                    raw_reputation=stats,
                    details={"as_owner": data.get("as_owner"), "country": data.get("country")},
                )
            return self._format_result(ip, "IPv4", "UNKNOWN" if resp.status_code == 404 else "ERROR", f"VirusTotal response: {resp.status_code}")
        except Exception as exc:
            return self._format_result(ip, "IPv4", "ERROR", f"VirusTotal error: {type(exc).__name__}")

    def lookup_url(self, target_url: str) -> dict[str, Any]:
        if not self.is_configured:
            return self._format_result(target_url, "URL", "NOT CONFIGURED", "VirusTotal API key not configured.")

        # VT requires base64url encoding without padding
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        url = f"{self.base_url}/urls/{url_id}"
        headers = {"x-apikey": self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=6.0)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                verdict = "MALICIOUS" if malicious >= 2 else ("SUSPICIOUS" if malicious == 1 else "BENIGN")
                return self._format_result(
                    indicator=target_url,
                    indicator_type="URL",
                    verdict=verdict,
                    interpretation=f"VirusTotal detected {malicious} security vendor hits for this URL.",
                    raw_reputation=stats,
                )
            return self._format_result(target_url, "URL", "UNKNOWN" if resp.status_code == 404 else "ERROR", f"VT HTTP {resp.status_code}")
        except Exception as exc:
            return self._format_result(target_url, "URL", "ERROR", f"VT request error: {type(exc).__name__}")

    def lookup_hash(self, file_hash: str) -> dict[str, Any]:
        if not self.is_configured:
            return self._format_result(file_hash, "HASH", "NOT CONFIGURED", "VirusTotal API key not configured.")

        url = f"{self.base_url}/files/{file_hash}"
        headers = {"x-apikey": self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=6.0)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                verdict = "MALICIOUS" if malicious >= 3 else ("SUSPICIOUS" if malicious > 0 else "BENIGN")
                return self._format_result(
                    indicator=file_hash,
                    indicator_type="HASH",
                    verdict=verdict,
                    interpretation=f"VirusTotal detected {malicious} AV/EDR detections for file hash.",
                    raw_reputation=stats,
                    details={
                        "meaningful_name": data.get("meaningful_name"),
                        "type_description": data.get("type_description"),
                        "size": data.get("size"),
                    },
                )
            elif resp.status_code == 404:
                return self._format_result(file_hash, "HASH", "UNKNOWN", "Hash not previously observed in VirusTotal database.")
            return self._format_result(file_hash, "HASH", "ERROR", f"VirusTotal returned HTTP {resp.status_code}")
        except Exception as exc:
            return self._format_result(file_hash, "HASH", "ERROR", f"VT hash error: {type(exc).__name__}")
