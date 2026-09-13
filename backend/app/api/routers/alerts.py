"""
PhishGuard AI — SOC Alerts Router
Aggregates high-priority indicators, unresolved cases, and critical telemetry into an active SOC triage queue.
"""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from ...db.database import get_db
from ...models.scan import Scan
from ...models.investigation import InvestigationCase

router = APIRouter()


@router.get("")
def list_alerts(
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Retrieve active SOC alert queue prioritized by risk and severity."""
    # Query scans with suspicious or malicious verdicts
    scans_query = db.query(Scan).filter(Scan.verdict.in_(["Suspicious", "Malicious"]))
    if severity:
        scans_query = scans_query.filter(Scan.severity == severity.upper())

    recent_scans = scans_query.order_by(Scan.created_at.desc()).limit(limit).all()

    alerts = []
    for s in recent_scans:
        alerts.append({
            "alert_id": f"PG-ALERT-{s.id:05d}",
            "source_type": s.scan_type.upper(),
            "target": s.target,
            "verdict": s.verdict,
            "severity": s.severity or "HIGH",
            "risk_score": s.risk_score or 0.0,
            "confidence_score": s.confidence_score or 50.0,
            "investigation_status": s.investigation_status or "NEW",
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "scan_id": s.id,
            "summary": s.summary or f"High-risk {s.scan_type} activity detected on {s.target}",
        })

    # Summary counts
    counts = {
        "critical": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
        "high": sum(1 for a in alerts if a["severity"] == "HIGH"),
        "medium": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
        "low": sum(1 for a in alerts if a["severity"] == "LOW"),
    }

    return {
        "total_alerts": len(alerts),
        "counts": counts,
        "alerts": alerts,
    }
