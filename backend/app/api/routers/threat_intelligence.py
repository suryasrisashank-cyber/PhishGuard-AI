"""
PhishGuard AI — Threat Intelligence Router
Exposes multi-provider status, domain/IP/URL lookups, and normalized enrichment.
Persists threat lookups to the database for SOC audit trail & history.
"""
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ...db.database import get_db
from ...models.scan import Scan
from ...services.threat_intel.service import threat_intel_service
from .scans import _scan_to_dict, _post_process_scan

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/providers/status")
def get_providers_status():
    """Return runtime operational status for each external threat intel provider."""
    return {
        "status": "ok",
        "providers": threat_intel_service.get_providers_status(),
    }


@router.get("/lookup")
def lookup_domain(domain: str, db: Session = Depends(get_db)):
    """Perform comprehensive multi-provider lookup on a domain and persist scan record."""
    data = threat_intel_service.enrich_indicator("DOMAIN", domain)
    try:
        verdict = "Safe"
        if data.get("consensus_verdict") == "MALICIOUS":
            verdict = "Malicious"
        elif data.get("consensus_verdict") == "SUSPICIOUS":
            verdict = "Suspicious"

        risk_score = 85.0 if verdict == "Malicious" else 45.0 if verdict == "Suspicious" else 5.0
        indicators = []
        for src in data.get("sources", []):
            indicators.append({
                "name": src.get("provider", "Threat Intel Provider"),
                "ioc_type": "DOMAIN",
                "ioc_value": domain,
                "severity": "HIGH" if src.get("provider_verdict") == "MALICIOUS" else "INFORMATIONAL",
                "passed": src.get("provider_verdict") != "MALICIOUS",
                "explanation": f"Provider verdict: {src.get('provider_verdict', 'UNKNOWN')}",
                "score_impact": 15.0 if src.get("provider_verdict") == "MALICIOUS" else 0.0,
            })

        scan_dict = {
            "risk_score": risk_score,
            "verdict": verdict,
            "summary": f"Multi-provider threat intelligence consensus: {verdict} for {domain}",
            "confidence_score": 85.0,
            "severity": "HIGH" if verdict == "Malicious" else "MEDIUM" if verdict == "Suspicious" else "INFORMATIONAL",
            "indicators": indicators,
            "mitre_techniques": [],
            "analyst_actions": ["Review external threat reputation", "Check DNS/RDAP registration age"],
            "timeline": [{"timestamp": "00:00:00", "event": "Threat Intel Lookup", "detail": f"Queried multi-provider intelligence for {domain}"}],
            "processing_time_ms": 120.0,
            "detection_engine_version": "3.0.0",
        }
        scan = Scan(**_scan_to_dict(scan_dict, "threat_intel", domain))
        db.add(scan)
        db.commit()
        db.refresh(scan)
        _post_process_scan(scan, scan_dict, "threat_intel", db)
        data["scan_id"] = scan.id
    except Exception as e:
        logger.warning(f"Could not persist threat intel scan: {e}")

    return data


@router.get("/enrich/{indicator_type}/{value}")
def enrich_indicator(indicator_type: str, value: str):
    """Enrich any supported indicator (DOMAIN, IPv4, URL, HASH)."""
    return threat_intel_service.enrich_indicator(indicator_type, value)

