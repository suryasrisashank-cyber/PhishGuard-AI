"""
PhishGuard AI — IOC Management & Correlation Service
Handles normalization, deduplication, threat intelligence linkage, and correlation.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_

from ..models.ioc import IOCRecord
from ..models.scan import Scan
from ..models.investigation import InvestigationCase

logger = logging.getLogger(__name__)


def upsert_ioc(
    db: Session,
    value: str,
    ioc_type: str,
    severity: str = "INFORMATIONAL",
    confidence: float = 50.0,
    reputation: str = "UNKNOWN",
    source: str = "Automated Scanner",
    notes: Optional[str] = None,
    raw_intelligence: Optional[dict[str, Any]] = None,
) -> IOCRecord:
    """Insert or update an IOC record in the database."""
    val = value.strip()
    if not val:
        return None

    existing = db.query(IOCRecord).filter(IOCRecord.value == val).first()
    raw_json = json.dumps(raw_intelligence) if raw_intelligence else None

    if existing:
        existing.scan_count += 1
        if confidence > (existing.confidence or 0.0):
            existing.confidence = confidence
        if reputation in ("MALICIOUS", "SUSPICIOUS"):
            existing.reputation = reputation
        if severity in ("CRITICAL", "HIGH") and existing.severity not in ("CRITICAL", "HIGH"):
            existing.severity = severity
        if raw_json and not existing.raw_intelligence:
            existing.raw_intelligence = raw_json
        db.commit()
        db.refresh(existing)
        return existing
    else:
        new_ioc = IOCRecord(
            value=val,
            ioc_type=ioc_type.upper(),
            severity=severity,
            confidence=confidence,
            reputation=reputation,
            source=source,
            notes=notes,
            raw_intelligence=raw_json,
        )
        db.add(new_ioc)
        db.commit()
        db.refresh(new_ioc)
        return new_ioc


def extract_and_record_scan_iocs(db: Session, scan_dict: dict[str, Any], scan_type: str) -> list[IOCRecord]:
    """Extract all relevant indicators from scan results and catalog them as IOCs."""
    saved_iocs: list[IOCRecord] = []
    target = scan_dict.get("target") or ""
    verdict = scan_dict.get("verdict", "Unknown")
    severity = scan_dict.get("severity", "INFORMATIONAL")
    confidence = scan_dict.get("confidence_score") or 50.0

    rep = "MALICIOUS" if verdict == "Malicious" else ("SUSPICIOUS" if verdict == "Suspicious" else "BENIGN")

    # Record target as IOC if URL or file
    if target and scan_type in ("url", "website"):
        ioc = upsert_ioc(db, target, "URL", severity=severity, confidence=confidence, reputation=rep, source=f"{scan_type.upper()} Scan")
        if ioc: saved_iocs.append(ioc)

    # Process structured indicators
    indicators = scan_dict.get("indicators") or []
    for ind in indicators:
        val = ind.get("ioc_value")
        itype = ind.get("ioc_type", "UNKNOWN").upper()
        if val and itype in ("DOMAIN", "IPV4", "IP", "URL", "HASH", "SHA256", "MD5", "EMAIL"):
            ind_sev = ind.get("severity", "INFORMATIONAL")
            ind_passed = ind.get("passed", True)
            ind_rep = "SUSPICIOUS" if not ind_passed else "BENIGN"
            ioc = upsert_ioc(db, val, itype, severity=ind_sev, confidence=confidence, reputation=ind_rep, source=f"{scan_type.upper()} Scanner")
            if ioc: saved_iocs.append(ioc)

    # If file scan, record hashes
    if scan_type == "file":
        for h_type in ("sha256", "md5", "sha1"):
            h_val = scan_dict.get(h_type)
            if h_val:
                ioc = upsert_ioc(db, h_val, h_type.upper(), severity=severity, confidence=confidence, reputation=rep, source="File Analyzer")
                if ioc: saved_iocs.append(ioc)

    return saved_iocs


def correlate_ioc_value(db: Session, value: str) -> dict[str, Any]:
    """
    Perform deep cross-entity correlation across scans, cases, and threat intelligence.
    Example: Finds that 'example-login.com' appeared in 3 scans, 2 cases, and 1 PCAP capture.
    """
    val = value.strip()
    ioc_rec = db.query(IOCRecord).filter(IOCRecord.value == val).first()

    # Search in scans (either target equals value or indicators text contains value)
    related_scans = db.query(Scan).filter(
        or_(
            Scan.target == val,
            Scan.indicators.contains(val),
        )
    ).order_by(Scan.created_at.desc()).limit(20).all()

    # Search in investigation cases
    related_cases = db.query(InvestigationCase).filter(
        or_(
            InvestigationCase.title.contains(val),
            InvestigationCase.iocs.contains(val),
            InvestigationCase.evidence.contains(val),
        )
    ).order_by(InvestigationCase.created_at.desc()).limit(10).all()

    scan_types_found = {s.scan_type for s in related_scans}

    return {
        "ioc": {
            "id": ioc_rec.id if ioc_rec else None,
            "value": val,
            "ioc_type": ioc_rec.ioc_type if ioc_rec else "UNKNOWN",
            "severity": ioc_rec.severity if ioc_rec else "INFORMATIONAL",
            "confidence": ioc_rec.confidence if ioc_rec else 50.0,
            "reputation": ioc_rec.reputation if ioc_rec else "UNKNOWN",
            "first_seen": ioc_rec.first_seen.isoformat() if (ioc_rec and ioc_rec.first_seen) else None,
            "last_seen": ioc_rec.last_seen.isoformat() if (ioc_rec and ioc_rec.last_seen) else None,
            "scan_count": len(related_scans),
            "raw_intelligence": json.loads(ioc_rec.raw_intelligence) if (ioc_rec and ioc_rec.raw_intelligence) else None,
        },
        "correlation": {
            "total_correlated_scans": len(related_scans),
            "total_correlated_cases": len(related_cases),
            "modalities": list(scan_types_found),
            "scans": [
                {
                    "id": s.id,
                    "scan_type": s.scan_type,
                    "target": s.target,
                    "verdict": s.verdict,
                    "severity": s.severity,
                    "risk_score": s.risk_score,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                }
                for s in related_scans
            ],
            "cases": [
                {
                    "id": c.id,
                    "case_id": c.case_id,
                    "title": c.title,
                    "status": c.status,
                    "severity": c.severity,
                }
                for c in related_cases
            ],
        },
    }
