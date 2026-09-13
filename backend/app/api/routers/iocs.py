"""
PhishGuard AI — IOC Management & Explorer Router
Provides querying, filtering, correlation, and CSV export for indicators of compromise.
"""
from __future__ import annotations

import csv
import io
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ...db.database import get_db
from ...models.ioc import IOCRecord
from ...services.ioc_service import upsert_ioc, correlate_ioc_value

router = APIRouter()


class IOCCreateRequest(BaseModel):
    value: str
    ioc_type: str
    severity: str = "INFORMATIONAL"
    confidence: float = 50.0
    reputation: str = "UNKNOWN"
    source: str = "Manual Entry"
    notes: Optional[str] = None


@router.get("")
def list_iocs(
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    reputation: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Retrieve cataloged IOCs with filters and pagination."""
    query = db.query(IOCRecord)

    if ioc_type:
        query = query.filter(IOCRecord.ioc_type == ioc_type.upper())
    if severity:
        query = query.filter(IOCRecord.severity == severity.upper())
    if reputation:
        query = query.filter(IOCRecord.reputation == reputation.upper())
    if search:
        query = query.filter(IOCRecord.value.contains(search))

    total = query.count()
    iocs = query.order_by(IOCRecord.last_seen.desc()).offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "iocs": [
            {
                "id": i.id,
                "value": i.value,
                "ioc_type": i.ioc_type,
                "severity": i.severity,
                "confidence": i.confidence,
                "reputation": i.reputation,
                "source": i.source,
                "scan_count": i.scan_count,
                "first_seen": i.first_seen.isoformat() if i.first_seen else None,
                "last_seen": i.last_seen.isoformat() if i.last_seen else None,
                "notes": i.notes,
            }
            for i in iocs
        ],
    }


@router.get("/export/csv")
def export_iocs_csv(db: Session = Depends(get_db)):
    """Export all cataloged IOCs as CSV for SIEM/firewall consumption."""
    iocs = db.query(IOCRecord).order_by(IOCRecord.last_seen.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Type", "Value", "Severity", "Confidence", "Reputation", "Source", "ScanCount", "FirstSeen", "LastSeen"])

    for i in iocs:
        writer.writerow([
            i.id,
            i.ioc_type,
            i.value,
            i.severity,
            i.confidence,
            i.reputation,
            i.source,
            i.scan_count,
            i.first_seen.isoformat() if i.first_seen else "",
            i.last_seen.isoformat() if i.last_seen else "",
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard_iocs.csv"},
    )


@router.get("/correlate/{value:path}")
def correlate_ioc(value: str, db: Session = Depends(get_db)):
    """Deep correlation: find all scans, cases, and intelligence referencing this indicator."""
    return correlate_ioc_value(db, value)


@router.get("/{ioc_id}")
def get_ioc_detail(ioc_id: int, db: Session = Depends(get_db)):
    """Fetch single IOC record by ID."""
    ioc = db.query(IOCRecord).filter(IOCRecord.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return {
        "id": ioc.id,
        "value": ioc.value,
        "ioc_type": ioc.ioc_type,
        "severity": ioc.severity,
        "confidence": ioc.confidence,
        "reputation": ioc.reputation,
        "source": ioc.source,
        "scan_count": ioc.scan_count,
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
        "notes": ioc.notes,
    }


@router.post("")
def create_manual_ioc(payload: IOCCreateRequest, db: Session = Depends(get_db)):
    """Allow SOC analysts to record verified external indicators manually."""
    rec = upsert_ioc(
        db=db,
        value=payload.value,
        ioc_type=payload.ioc_type,
        severity=payload.severity,
        confidence=payload.confidence,
        reputation=payload.reputation,
        source=payload.source,
        notes=payload.notes,
    )
    return {"status": "created", "ioc": rec.value, "id": rec.id}
