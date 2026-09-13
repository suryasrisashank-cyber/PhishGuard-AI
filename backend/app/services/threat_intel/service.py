"""
PhishGuard AI — Threat Intelligence Aggregation Service
Coordinates multi-provider lookups, merges reputation scores, and provides runtime status.
"""
from __future__ import annotations

import logging
from typing import Any

from .base import ThreatIntelProvider
from .virustotal import VirusTotalProvider
from .abuseipdb import AbuseIPDBProvider
from .otx import OTXProvider
from .urlhaus import URLhausProvider
from .dns_provider import DNSProvider
from .rdap_provider import RDAPProvider

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """Aggregates all threat intelligence providers with unified query and health check interfaces."""

    def __init__(self):
        self.vt = VirusTotalProvider()
        self.abuseipdb = AbuseIPDBProvider()
        self.otx = OTXProvider()
        self.urlhaus = URLhausProvider()
        self.dns = DNSProvider()
        self.rdap = RDAPProvider()

        self.providers: list[ThreatIntelProvider] = [
            self.vt,
            self.abuseipdb,
            self.otx,
            self.urlhaus,
            self.dns,
            self.rdap,
        ]

    def get_providers_status(self) -> list[dict[str, Any]]:
        """Return runtime health and configuration state for each provider."""
        return [p.check_status() for p in self.providers]

    def enrich_indicator(self, indicator_type: str, value: str) -> dict[str, Any]:
        """
        Enrich a normalized indicator (DOMAIN, IPv4, URL, HASH) across all applicable providers.
        Preserves individual provider verdicts, raw reputation telemetry, and overall consensus.
        """
        itype = indicator_type.upper()
        results: list[dict[str, Any]] = []

        if itype == "DOMAIN":
            results.append(self.urlhaus.lookup_domain(value))
            results.append(self.dns.lookup_domain(value))
            results.append(self.rdap.lookup_domain(value))
            results.append(self.vt.lookup_domain(value))
            results.append(self.otx.lookup_domain(value))
        elif itype in ("IPV4", "IP"):
            results.append(self.abuseipdb.lookup_ip(value))
            results.append(self.vt.lookup_ip(value))
            results.append(self.otx.lookup_ip(value))
        elif itype == "URL":
            results.append(self.urlhaus.lookup_url(value))
            results.append(self.vt.lookup_url(value))
        elif itype in ("HASH", "SHA256", "MD5", "SHA1"):
            results.append(self.vt.lookup_hash(value))

        # Calculate consensus verdict
        malicious_hits = sum(1 for r in results if r.get("provider_verdict") == "MALICIOUS")
        suspicious_hits = sum(1 for r in results if r.get("provider_verdict") == "SUSPICIOUS")

        if malicious_hits > 0:
            consensus_verdict = "MALICIOUS"
        elif suspicious_hits > 0:
            consensus_verdict = "SUSPICIOUS"
        elif any(r.get("provider_verdict") == "BENIGN" for r in results):
            consensus_verdict = "BENIGN"
        else:
            consensus_verdict = "UNKNOWN"

        return {
            "indicator": value,
            "indicator_type": itype,
            "consensus_verdict": consensus_verdict,
            "malicious_hits": malicious_hits,
            "suspicious_hits": suspicious_hits,
            "total_queries": len(results),
            "providers_queried": len(results),
            "sources": results,
        }


# Global singleton instance
threat_intel_service = ThreatIntelService()
