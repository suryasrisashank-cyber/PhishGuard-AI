"""
PhishGuard AI — RDAP / WHOIS Domain Registration Intelligence Provider
Extracts registrar, registration age, expiration, nameservers, and organization info.
"""
from __future__ import annotations

import datetime
import logging
from typing import Any

from .base import ThreatIntelProvider

logger = logging.getLogger(__name__)


class RDAPProvider(ThreatIntelProvider):
    name = "RDAP / WHOIS"
    category = "Network & DNS"

    @property
    def is_configured(self) -> bool:
        return True

    def check_status(self) -> dict[str, Any]:
        try:
            import whois
            return {
                "name": self.name,
                "status": "AVAILABLE",
                "configured": True,
                "tested": True,
                "details": "python-whois active for registrar and domain lifecycle queries.",
            }
        except ImportError:
            return {"name": self.name, "status": "UNAVAILABLE", "configured": False, "tested": False, "details": "python-whois module missing."}

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        try:
            import whois
            w = whois.whois(domain)

            registrar = str(w.registrar) if w.registrar else "Not Available"
            country = str(w.country) if w.country else "Not Available"
            org = str(w.org) if w.org else "Not Available"

            created = w.creation_date
            if isinstance(created, list) and created:
                created = created[0]
            expires = w.expiration_date
            if isinstance(expires, list) and expires:
                expires = expires[0]

            created_str = created.isoformat() if isinstance(created, (datetime.datetime, datetime.date)) else str(created or "Unknown")
            expires_str = expires.isoformat() if isinstance(expires, (datetime.datetime, datetime.date)) else str(expires or "Unknown")

            # Check for young domain (< 30 days old)
            is_young = False
            domain_age_days = None
            if isinstance(created, (datetime.datetime, datetime.date)):
                now = datetime.datetime.now(datetime.timezone.utc if getattr(created, "tzinfo", None) else None)
                if isinstance(created, datetime.date) and not isinstance(created, datetime.datetime):
                    now = now.date()
                age = (now - created).days
                domain_age_days = age
                if age < 30:
                    is_young = True

            verdict = "SUSPICIOUS" if is_young else "BENIGN"
            interp = f"Domain registered via {registrar}. " + (f"Warning: newly registered domain ({domain_age_days} days old)." if is_young else f"Established domain ({domain_age_days} days old).")

            return self._format_result(
                indicator=domain,
                indicator_type="DOMAIN",
                verdict=verdict,
                interpretation=interp,
                raw_reputation={"is_young_domain": is_young, "domain_age_days": domain_age_days, "registrar": registrar},
                confidence=80.0 if domain_age_days is not None else 50.0,
                details={
                    "registrar": registrar,
                    "creation_date": created_str,
                    "expiration_date": expires_str,
                    "country": country,
                    "organization": org,
                    "name_servers": w.name_servers if w.name_servers else [],
                },
            )
        except Exception as exc:
            return self._format_result(domain, "DOMAIN", "UNKNOWN", f"WHOIS query: {type(exc).__name__}")
