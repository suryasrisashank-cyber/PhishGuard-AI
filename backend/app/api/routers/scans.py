"""
PhishGuard AI — Scans API Router
Comprehensive defensive analysis endpoints:
  POST /api/scans/url         — Analyze a URL
  POST /api/scans/website     — Analyze a website (with strict SSRF protection)
  POST /api/scans/email       — Analyze email text (JSON body)
  POST /api/scans/email/file  — Analyze email from uploaded .eml file
  POST /api/scans/file        — Safe static defensive file analysis (hashes, strings, YARA, VT)
  POST /api/scans/pcap        — Defensive offline PCAP network analysis (Scapy/tshark)
  GET  /api/scans             — List scans (paginated, filterable)
  GET  /api/scans/{id}        — Full scan detail
  PATCH /api/scans/{id}/status — Update investigation status
  PATCH /api/scans/{id}/notes  — Update analyst notes
"""
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from ...db.database import get_db
from ...models.scan import Scan
from ...schemas.scan import ScanCreate, ScanOut, ScanListItem, EmailAnalyzeRequest, StatusUpdateRequest, NotesUpdateRequest
from ...services.scanner_service import analyze_email, analyze_url, analyze_website
from ...services.file_service import analyze_file_bytes
from ...services.pcap_service import analyze_pcap_bytes
from ...services.ioc_service import extract_and_record_scan_iocs
from ...services.splunk_service import splunk_service

logger = logging.getLogger(__name__)
router = APIRouter()


def _scan_to_dict(result: dict, scan_type: str, target: str) -> dict:
    """Convert a scanner service result dict to Scan ORM kwargs, serializing JSON fields."""
    return {
        "scan_type": scan_type,
        "target": target,
        "risk_score": result.get("risk_score", 0.0),
        "verdict": result.get("verdict", "Unknown"),
        "summary": result.get("summary", ""),
        "confidence_score": result.get("confidence_score"),
        "severity": result.get("severity", "INFORMATIONAL"),
        "investigation_status": "NEW",
        "indicators": json.dumps(result.get("indicators") or []),
        "mitre_techniques": json.dumps(result.get("mitre_techniques") or []),
        "analyst_actions": json.dumps(result.get("analyst_actions") or []),
        "timeline": json.dumps(result.get("timeline") or []),
        "processing_time_ms": result.get("processing_time_ms"),
        "detection_engine_version": result.get("detection_engine_version", "3.0.0"),
    }


def _serialize_scan(scan: Scan) -> dict:
    """Convert Scan ORM object to dict, parsing JSON text fields back into Python objects."""
    d = {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "target": scan.target,
        "risk_score": scan.risk_score or 0.0,
        "verdict": scan.verdict or "Unknown",
        "summary": scan.summary or "",
        "created_at": scan.created_at,
        "confidence_score": scan.confidence_score,
        "severity": scan.severity or "INFORMATIONAL",
        "investigation_status": scan.investigation_status or "NEW",
        "analyst_notes": scan.analyst_notes,
        "processing_time_ms": scan.processing_time_ms,
        "detection_engine_version": scan.detection_engine_version or "3.0.0",
    }

    for field in ("indicators", "mitre_techniques", "analyst_actions", "timeline"):
        raw = getattr(scan, field, None)
        if raw:
            try:
                d[field] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                d[field] = []
        else:
            d[field] = []

    return d


def _post_process_scan(scan: Scan, result: dict, scan_type: str, db: Session):
    """Catalog extracted IOCs and forward to Splunk if configured."""
    try:
        extract_and_record_scan_iocs(db, result, scan_type)
    except Exception as e:
        logger.warning(f"Error cataloging IOCs for scan {scan.id}: {e}")

    try:
        if splunk_service.is_configured:
            splunk_service.send_scan_event(_serialize_scan(scan))
    except Exception as e:
        logger.warning(f"Error forwarding scan {scan.id} to Splunk: {e}")


@router.post("/url", response_model=ScanOut)
def scan_url(payload: ScanCreate, db: Session = Depends(get_db)) -> dict:
    """Analyze a URL for phishing indicators."""
    result = analyze_url(payload.target)
    scan = Scan(**_scan_to_dict(result, payload.scan_type, payload.target))
    db.add(scan)
    db.commit()
    db.refresh(scan)
    _post_process_scan(scan, result, payload.scan_type, db)
    logger.info(f"URL scan completed: {payload.target} → {scan.verdict} (risk={scan.risk_score})")
    return _serialize_scan(scan)


@router.post("/website", response_model=ScanOut)
def scan_website(payload: ScanCreate, db: Session = Depends(get_db)) -> dict:
    """Fetch and statically analyze website HTML for phishing indicators with SSRF protection."""
    result = analyze_website(payload.target)
    scan = Scan(**_scan_to_dict(result, payload.scan_type, payload.target))
    db.add(scan)
    db.commit()
    db.refresh(scan)
    _post_process_scan(scan, result, payload.scan_type, db)
    logger.info(f"Website scan completed: {payload.target} → {scan.verdict}")
    return _serialize_scan(scan)


@router.post("/email", response_model=ScanOut)
def scan_email_text(payload: EmailAnalyzeRequest, db: Session = Depends(get_db)) -> dict:
    """Analyze email content from pasted text or headers."""
    result = analyze_email(payload.content)
    target = "Pasted Email Content"
    scan = Scan(**_scan_to_dict(result, "email", target))
    db.add(scan)
    db.commit()
    db.refresh(scan)
    _post_process_scan(scan, result, "email", db)
    logger.info(f"Email scan completed → {scan.verdict} (risk={scan.risk_score})")
    return _serialize_scan(scan)


@router.post("/email/file", response_model=ScanOut)
def scan_email_file(file: UploadFile = File(...), db: Session = Depends(get_db)) -> dict:
    """Analyze email from uploaded .eml or raw message file."""
    content = file.file.read().decode("utf-8", errors="ignore")
    result = analyze_email(content)
    target = file.filename or "Email File"
    scan = Scan(**_scan_to_dict(result, "email", target))
    db.add(scan)
    db.commit()
    db.refresh(scan)
    _post_process_scan(scan, result, "email", db)
    return _serialize_scan(scan)


@router.post("/file", response_model=ScanOut)
def scan_file_upload(file: UploadFile = File(...), db: Session = Depends(get_db)) -> dict:
    """Safe defensive static file analysis: calculates hashes, extracts strings/IOCs, optional YARA/VT."""
    content = file.file.read()
    # Check max file size (15MB defensive limit)
    if len(content) > 15 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds maximum permitted limit (15MB)")

    filename = file.filename or "uploaded_sample.bin"
    result = analyze_file_bytes(content, filename)
    scan = Scan(**_scan_to_dict(result, "file", filename))
    db.add(scan)
    db.commit()
    db.refresh(scan)
    _post_process_scan(scan, result, "file", db)
    logger.info(f"File scan completed: {filename} → {scan.verdict} (risk={scan.risk_score})")
    return _serialize_scan(scan)


@router.post("/pcap", response_model=ScanOut)
def scan_pcap_upload(file: UploadFile = File(...), db: Session = Depends(get_db)) -> dict:
    """Defensive offline PCAP network analysis: parses protocols, DNS queries, HTTP hosts, TLS SNI."""
    content = file.file.read()
    if len(content) > 25 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="PCAP file size exceeds maximum permitted limit (25MB)")

    filename = file.filename or "capture.pcap"
    result = analyze_pcap_bytes(content, filename)
    scan = Scan(**_scan_to_dict(result, "pcap", filename))
    db.add(scan)
    db.commit()
    db.refresh(scan)
    _post_process_scan(scan, result, "pcap", db)
    logger.info(f"PCAP scan completed: {filename} → {scan.verdict}")
    return _serialize_scan(scan)


@router.get("", response_model=list[ScanListItem])
def list_scans(
    page: int = 1,
    limit: int = 50,
    verdict: str = "",
    search: str = "",
    db: Session = Depends(get_db),
) -> list[dict]:
    """List scans with optional filtering and pagination."""
    query = db.query(Scan)
    if verdict:
        query = query.filter(Scan.verdict == verdict)
    if search:
        query = query.filter(Scan.target.contains(search))
    scans = query.order_by(Scan.id.desc()).offset((page - 1) * limit).limit(limit).all()
    return [ScanListItem.model_validate(s).model_dump() for s in scans]


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> dict:
    """Get full investigation detail for a single scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return _serialize_scan(scan)


@router.patch("/{scan_id}/status")
def update_scan_status(
    scan_id: int,
    payload: StatusUpdateRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Update the investigation status of a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    scan.investigation_status = payload.investigation_status
    db.commit()
    db.refresh(scan)
    logger.info(f"Scan {scan_id} status updated to {payload.investigation_status}")
    return {"id": scan_id, "investigation_status": scan.investigation_status}


@router.patch("/{scan_id}/notes")
def update_scan_notes(
    scan_id: int,
    payload: NotesUpdateRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Add or update analyst notes for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    scan.analyst_notes = payload.analyst_notes[:5000]
    db.commit()
    db.refresh(scan)
    return {"id": scan_id, "analyst_notes": scan.analyst_notes}
