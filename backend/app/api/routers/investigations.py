"""
PhishGuard AI — Investigations & SOC Case Management Router
Implements the full investigation lifecycle: NEW → TRIAGED → INVESTIGATING → CONFIRMED_THREAT → CONTAINMENT → RESOLVED.
Allows analysts to attach external authorized Burp Suite observations and sync cases with Splunk SIEM.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ...db.database import get_db
from ...models.investigation import InvestigationCase
from ...models.scan import Scan
from ...services.splunk_service import splunk_service

logger = logging.getLogger(__name__)
router = APIRouter()


class CaseCreateFromScan(BaseModel):
    scan_id: int
    title: Optional[str] = None
    analyst: str = "SOC Analyst Tier 1"


class CaseCreateManual(BaseModel):
    title: str
    severity: str = "MEDIUM"
    risk_score: float = 50.0
    confidence_score: float = 60.0
    analyst: str = "SOC Analyst Tier 1"
    summary: str = ""
    iocs: list[str] = []


class CaseUpdateRequest(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    analyst_notes: Optional[str] = None
    recommended_actions: Optional[list[str]] = None


class BurpFindingAttachRequest(BaseModel):
    issue_name: str
    severity: str = "High"  # High, Medium, Low, Information
    confidence: str = "Certain"  # Certain, Firm, Tentative
    host: str
    path: str
    detail: str
    remediation: Optional[str] = None


def _serialize_case(case: InvestigationCase) -> dict[str, Any]:
    """Safely convert ORM case to dictionary, deserializing JSON fields."""
    d = {
        "id": case.id,
        "case_id": case.case_id,
        "title": case.title,
        "severity": case.severity,
        "risk_score": case.risk_score,
        "confidence_score": case.confidence_score,
        "status": case.status,
        "analyst": case.analyst,
        "summary": case.summary,
        "analyst_notes": case.analyst_notes or "",
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
    }

    for f in ("evidence", "iocs", "threat_intel", "mitre_techniques", "timeline", "recommended_actions", "splunk_events", "burp_findings"):
        raw = getattr(case, f, None)
        if raw:
            try:
                d[f] = json.loads(raw)
            except Exception:
                d[f] = [] if f != "threat_intel" else {}
        else:
            d[f] = [] if f != "threat_intel" else {}

    return d


@router.get("")
def list_investigations(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """List investigation cases with status and severity filters."""
    query = db.query(InvestigationCase)

    if status:
        query = query.filter(InvestigationCase.status == status.upper())
    if severity:
        query = query.filter(InvestigationCase.severity == severity.upper())
    if search:
        query = query.filter(InvestigationCase.title.contains(search) | InvestigationCase.case_id.contains(search))

    total = query.count()
    cases = query.order_by(InvestigationCase.updated_at.desc()).offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "cases": [_serialize_case(c) for c in cases],
    }


@router.post("/from-scan")
def create_investigation_from_scan(payload: CaseCreateFromScan, db: Session = Depends(get_db)):
    """Instantiate a new SOC investigation case directly from an existing scan record."""
    scan = db.query(Scan).filter(Scan.id == payload.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    count = db.query(InvestigationCase).count() + 1
    case_id = f"PG-CASE-{time.strftime('%Y')}-{count:04d}"
    title = payload.title or f"Investigation: {scan.verdict} {scan.scan_type.upper()} on {scan.target[:40]}"

    # Extract scan indicators
    raw_indicators = []
    if scan.indicators:
        try: raw_indicators = json.loads(scan.indicators)
        except Exception: pass

    extracted_ioc_values = [i.get("ioc_value") for i in raw_indicators if i.get("ioc_value")]

    timeline = [
        {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "author": payload.analyst,
            "action": "Case Created",
            "detail": f"Case escalated from scan ID {scan.id} ({scan.verdict}).",
        }
    ]

    new_case = InvestigationCase(
        case_id=case_id,
        title=title,
        severity=scan.severity or "MEDIUM",
        risk_score=scan.risk_score or 0.0,
        confidence_score=scan.confidence_score or 50.0,
        status="NEW",
        analyst=payload.analyst,
        summary=scan.summary or f"Initial detection for {scan.target}",
        evidence=scan.indicators,
        iocs=json.dumps(extracted_ioc_values),
        mitre_techniques=scan.mitre_techniques,
        timeline=json.dumps(timeline),
        analyst_notes=scan.analyst_notes or "",
        recommended_actions=scan.analyst_actions,
    )

    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    # Forward to Splunk if configured
    if splunk_service.is_configured:
        splunk_service.send_investigation_event(_serialize_case(new_case))

    return _serialize_case(new_case)


@router.get("/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)):
    """Retrieve full details of an investigation case by case_id or numeric ID."""
    if case_id.isdigit():
        case = db.query(InvestigationCase).filter(InvestigationCase.id == int(case_id)).first()
    else:
        case = db.query(InvestigationCase).filter(InvestigationCase.case_id == case_id).first()

    if not case:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return _serialize_case(case)


@router.patch("/{case_id}")
def update_case(case_id: str, payload: CaseUpdateRequest, db: Session = Depends(get_db)):
    """Update case status, severity, analyst notes, or response actions."""
    if case_id.isdigit():
        case = db.query(InvestigationCase).filter(InvestigationCase.id == int(case_id)).first()
    else:
        case = db.query(InvestigationCase).filter(InvestigationCase.case_id == case_id).first()

    if not case:
        raise HTTPException(status_code=404, detail="Investigation case not found")

    timeline_items = []
    if case.timeline:
        try: timeline_items = json.loads(case.timeline)
        except Exception: pass

    if payload.status and payload.status != case.status:
        old_status = case.status
        case.status = payload.status.upper()
        timeline_items.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "author": case.analyst,
            "action": f"Status Changed: {old_status} → {case.status}",
            "detail": f"Investigation moved to {case.status} state.",
        })

    if payload.severity:
        case.severity = payload.severity.upper()

    if payload.analyst_notes is not None:
        case.analyst_notes = payload.analyst_notes

    if payload.recommended_actions is not None:
        case.recommended_actions = json.dumps(payload.recommended_actions)

    case.timeline = json.dumps(timeline_items)
    db.commit()
    db.refresh(case)

    # Sync state to Splunk
    if splunk_service.is_configured:
        splunk_service.send_investigation_event(_serialize_case(case))

    return _serialize_case(case)


@router.post("/{case_id}/burp-finding")
def attach_burp_finding(case_id: str, payload: BurpFindingAttachRequest, db: Session = Depends(get_db)):
    """
    Associate external authorized Burp Suite observations directly with this case.
    PhishGuard documents Burp Suite as external manual verification without faking scanner results.
    """
    if case_id.isdigit():
        case = db.query(InvestigationCase).filter(InvestigationCase.id == int(case_id)).first()
    else:
        case = db.query(InvestigationCase).filter(InvestigationCase.case_id == case_id).first()

    if not case:
        raise HTTPException(status_code=404, detail="Investigation case not found")

    findings = []
    if case.burp_findings:
        try: findings = json.loads(case.burp_findings)
        except Exception: pass

    finding_record = {
        "attached_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "Burp Suite Professional (External Manual Verification)",
        "issue_name": payload.issue_name,
        "severity": payload.severity,
        "confidence": payload.confidence,
        "host": payload.host,
        "path": payload.path,
        "detail": payload.detail,
        "remediation": payload.remediation or "Refer to Burp Suite vulnerability knowledge base.",
    }
    findings.append(finding_record)
    case.burp_findings = json.dumps(findings)

    # Add to timeline
    timeline_items = []
    if case.timeline:
        try: timeline_items = json.loads(case.timeline)
        except Exception: pass
    timeline_items.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "author": case.analyst,
        "action": "Burp Suite Evidence Attached",
        "detail": f"Imported external finding '{payload.issue_name}' for target {payload.host}{payload.path}.",
    })
    case.timeline = json.dumps(timeline_items)

    db.commit()
    db.refresh(case)
    return {"status": "attached", "burp_finding": finding_record, "case": _serialize_case(case)}


@router.post("/{case_id}/splunk")
def forward_case_to_splunk(case_id: str, db: Session = Depends(get_db)):
    """Manually dispatch full investigation state to Splunk HEC."""
    if case_id.isdigit():
        case = db.query(InvestigationCase).filter(InvestigationCase.id == int(case_id)).first()
    else:
        case = db.query(InvestigationCase).filter(InvestigationCase.case_id == case_id).first()

    if not case:
        raise HTTPException(status_code=404, detail="Investigation case not found")

    result = splunk_service.send_investigation_event(_serialize_case(case))
    return result
