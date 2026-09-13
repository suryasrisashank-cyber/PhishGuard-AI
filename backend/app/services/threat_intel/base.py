"""
PhishGuard AI — Threat Intelligence Provider Abstract Base Class
Defines the standard contract for all external intelligence adapters.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
import datetime
from typing import Any, Optional


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    name: str = "BaseProvider"
    category: str = "Threat Intelligence"

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if required credentials or network resources are present."""
        pass

    @abstractmethod
    def check_status(self) -> dict[str, Any]:
        """Returns provider runtime status: CONNECTED, AVAILABLE, NOT CONFIGURED, UNAVAILABLE, or ERROR."""
        pass

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Perform reputation and intelligence query on domain."""
        return self._format_result(domain, "DOMAIN", "NOT CONFIGURED", "Provider lookup not configured.")

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Perform reputation and intelligence query on IP."""
        return self._format_result(ip, "IPv4", "NOT CONFIGURED", "Provider lookup not configured.")

    def lookup_url(self, url: str) -> dict[str, Any]:
        """Perform reputation and intelligence query on URL."""
        return self._format_result(url, "URL", "NOT CONFIGURED", "Provider lookup not configured.")

    def lookup_hash(self, hash_val: str) -> dict[str, Any]:
        """Perform reputation and intelligence query on file hash."""
        return self._format_result(hash_val, "HASH", "NOT CONFIGURED", "Provider lookup not configured.")

    def _format_result(
        self,
        indicator: str,
        indicator_type: str,
        verdict: str,
        interpretation: str,
        raw_reputation: Optional[Any] = None,
        confidence: Optional[float] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Standardized, defensible output preserving provider identity, timestamps, and raw details."""
        return {
            "provider": self.name,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "retrieval_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "provider_verdict": verdict,  # SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN, NOT CONFIGURED, ERROR
            "raw_reputation": raw_reputation,
            "confidence": confidence,
            "normalized_interpretation": interpretation,
            "details": details or {},
        }
