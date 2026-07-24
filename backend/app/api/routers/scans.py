from fastapi import APIRouter, Depends, UploadFile, File
from sqlalchemy.orm import Session
from ...db.database import get_db
from ...models.scan import Scan
from ...schemas.scan import ScanCreate, ScanOut
from ...services.scanner_service import analyze_email, analyze_url, analyze_website

router = APIRouter()


@router.post("/url", response_model=ScanOut)
def scan_url(payload: ScanCreate, db: Session = Depends(get_db)) -> Scan:
    result = analyze_url(payload.target)
    scan = Scan(scan_type=payload.scan_type, target=payload.target, risk_score=result["risk_score"], verdict=result["verdict"], summary=result["summary"])
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/email", response_model=ScanOut)
def scan_email(file: UploadFile = File(...), db: Session = Depends(get_db)) -> Scan:
    content = file.file.read().decode("utf-8", errors="ignore")
    result = analyze_email(content)
    scan = Scan(scan_type="email", target=file.filename, risk_score=result["risk_score"], verdict=result["verdict"], summary=result["summary"])
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/website", response_model=ScanOut)
def scan_website(payload: ScanCreate, db: Session = Depends(get_db)) -> Scan:
    result = analyze_website(payload.target)
    scan = Scan(scan_type=payload.scan_type, target=payload.target, risk_score=result["risk_score"], verdict=result["verdict"], summary=result["summary"])
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db)) -> list[Scan]:
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    return [ScanOut.model_validate(s).model_dump() for s in scans]
