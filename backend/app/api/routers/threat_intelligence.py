"""
PhishGuard AI — Threat Intelligence Router
Exposes multi-provider status, domain/IP/URL lookups, and normalized enrichment.
"""
from fastapi import APIRouter
from ...services.threat_intel.service import threat_intel_service

router = APIRouter()


@router.get("/providers/status")
def get_providers_status():
    """Return runtime operational status for each external threat intel provider."""
    return {
        "status": "ok",
        "providers": threat_intel_service.get_providers_status(),
    }


@router.get("/lookup")
def lookup_domain(domain: str):
    """Perform comprehensive multi-provider lookup on a domain."""
    return threat_intel_service.enrich_indicator("DOMAIN", domain)


@router.get("/enrich/{indicator_type}/{value}")
def enrich_indicator(indicator_type: str, value: str):
    """Enrich any supported indicator (DOMAIN, IPv4, URL, HASH)."""
    return threat_intel_service.enrich_indicator(indicator_type, value)
