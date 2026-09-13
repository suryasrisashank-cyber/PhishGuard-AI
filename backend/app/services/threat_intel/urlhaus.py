"""
PhishGuard AI — abuse.ch URLhaus Provider Adapter
Queries public malware/phishing URL and host threat intelligence.
Operates using the official free URLhaus API (no mandatory key required).
"""
from __future__ import annotations

import logging
from typing import Any
import requests

from .base import ThreatIntelProvider

logger = logging.getLogger(__name__)


class URLhausProvider(ThreatIntelProvider):
    name = "URLhaus (abuse.ch)"
    category = "Threat Intelligence"

    def __init__(self):
        self.base_url = "https://urlhaus-api.abuse.ch/v1"

    @property
    def is_configured(self) -> bool:
        # Public feed freely accessible over HTTPS
        return True

    def check_status(self) -> dict[str, Any]:
        try:
            resp = requests.post(f"{self.base_url}/url/", data={"url": "https://example.com"}, timeout=4.0)
            if resp.status_code == 200:
                return {
                    "name": self.name,
                    "status": "CONNECTED",
                    "configured": True,
                    "tested": True,
                    "details": "abuse.ch URLhaus public feed active and reachable.",
                }
            return {"name": self.name, "status": "AVAILABLE", "configured": True, "tested": True, "details": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"name": self.name, "status": "UNAVAILABLE", "configured": True, "tested": True, "details": str(e)[:100]}

    def lookup_url(self, target_url: str) -> dict[str, Any]:
        try:
            resp = requests.post(f"{self.base_url}/url/", data={"url": target_url}, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                q_status = data.get("query_status")
                if q_status == "ok":
                    url_status = data.get("url_status", "unknown")
                    threat = data.get("threat", "malware_download")
                    tags = data.get("tags") or []
                    payloads = data.get("payloads") or []

                    verdict = "MALICIOUS"
                    interp = f"URLhaus confirms active malicious URL distributing '{threat}' (Status: {url_status})."
                    return self._format_result(
                        indicator=target_url,
                        indicator_type="URL",
                        verdict=verdict,
                        interpretation=interp,
                        raw_reputation={"url_status": url_status, "threat": threat, "tags": tags, "payload_count": len(payloads)},
                        confidence=95.0,
                        details={"reporter": data.get("reporter"), "date_added": data.get("date_added"), "larted": data.get("larted")},
                    )
                elif q_status == "no_results":
                    return self._format_result(
                        indicator=target_url,
                        indicator_type="URL",
                        verdict="BENIGN",
                        interpretation="No malicious campaigns matching this URL in the URLhaus database.",
                        raw_reputation={"query_status": "no_results"},
                        confidence=70.0,
                    )
            return self._format_result(target_url, "URL", "UNKNOWN", f"URLhaus query returned: {resp.status_code}")
        except Exception as exc:
            return self._format_result(target_url, "URL", "ERROR", f"URLhaus query failed: {type(exc).__name__}")

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        try:
            resp = requests.post(f"{self.base_url}/host/", data={"host": domain}, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                q_status = data.get("query_status")
                if q_status == "ok":
                    urls = data.get("urls") or []
                    active_count = sum(1 for u in urls if u.get("url_status") == "online")
                    verdict = "MALICIOUS" if active_count > 0 else "SUSPICIOUS"
                    interp = f"URLhaus records {len(urls)} malicious URL(s) hosted on {domain} ({active_count} online)."
                    return self._format_result(
                        indicator=domain,
                        indicator_type="DOMAIN",
                        verdict=verdict,
                        interpretation=interp,
                        raw_reputation={"total_recorded_urls": len(urls), "active_online_urls": active_count},
                        confidence=90.0,
                    )
                elif q_status == "no_results":
                    return self._format_result(
                        indicator=domain,
                        indicator_type="DOMAIN",
                        verdict="BENIGN",
                        interpretation="Domain has no malicious host records listed in URLhaus.",
                        raw_reputation={"query_status": "no_results"},
                        confidence=70.0,
                    )
            return self._format_result(domain, "DOMAIN", "UNKNOWN", f"URLhaus host status: {resp.status_code}")
        except Exception as exc:
            return self._format_result(domain, "DOMAIN", "ERROR", f"URLhaus query error: {type(exc).__name__}")
