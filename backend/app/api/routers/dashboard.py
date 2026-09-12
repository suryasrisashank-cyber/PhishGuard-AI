"""
PhishGuard AI 2.0 — Dashboard Statistics API
"""
import json
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ...db.database import get_db
from ...models.scan import Scan
from ...schemas.scan import ScanListItem

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)) -> dict:
    """
    Returns KPI statistics for the SOC dashboard.
    All values come from the real database — never fabricated.
    """
    scans = db.query(Scan).all()

    if not scans:
        return {
            "total_scans": 0,
            "safe": 0,
            "suspicious": 0,
            "malicious": 0,
            "critical": 0,
            "threat_rate": 0.0,
            "severity_distribution": {
                "INFORMATIONAL": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0
            },
            "threat_trend": [],
            "empty": True,
        }

    total = len(scans)
    safe = sum(1 for s in scans if s.verdict == "Safe")
    suspicious = sum(1 for s in scans if s.verdict == "Suspicious")
    malicious = sum(1 for s in scans if s.verdict == "Malicious")
    critical = sum(1 for s in scans if (s.risk_score or 0) >= 80)

    # Severity distribution
    sev_dist = {"INFORMATIONAL": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for s in scans:
        sev = s.severity or "INFORMATIONAL"
        if sev in sev_dist:
            sev_dist[sev] += 1

    # Threat trend: last 7 days (date → scan count + threat count)
    today = datetime.utcnow().date()
    trend = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_scans = [s for s in scans if s.created_at and s.created_at.date() == day]
        day_threats = [s for s in day_scans if s.verdict in ("Suspicious", "Malicious")]
        trend.append({
            "date": day.strftime("%b %d"),
            "scans": len(day_scans),
            "threats": len(day_threats),
        })

    threat_rate = round((suspicious + malicious) / total * 100, 1) if total > 0 else 0.0

    return {
        "total_scans": total,
        "safe": safe,
        "suspicious": suspicious,
        "malicious": malicious,
        "critical": critical,
        "threat_rate": threat_rate,
        "severity_distribution": sev_dist,
        "threat_trend": trend,
        "empty": False,
    }


@router.get("/recent", response_model=list[ScanListItem])
def get_recent_scans(limit: int = 10, db: Session = Depends(get_db)) -> list[dict]:
    """Returns the most recent scans for the dashboard investigation table."""
    scans = db.query(Scan).order_by(Scan.id.desc()).limit(limit).all()
    return [ScanListItem.model_validate(s).model_dump() for s in scans]

