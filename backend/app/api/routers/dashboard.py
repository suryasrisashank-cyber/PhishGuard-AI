from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ...db.database import get_db
from ...models.scan import Scan
from ...schemas.scan import ScanOut

router = APIRouter()


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)) -> dict:
    scans = db.query(Scan).all()
    return {
        "total_scans": len(scans),
        "safe": sum(1 for scan in scans if scan.verdict == "Safe"),
        "suspicious": sum(1 for scan in scans if scan.verdict == "Suspicious"),
        "malicious": sum(1 for scan in scans if scan.verdict == "Malicious"),
    }


@router.get("/recent", response_model=list[ScanOut])
def get_recent_scans(db: Session = Depends(get_db)) -> list[ScanOut]:
    scans = db.query(Scan).order_by(Scan.id.desc()).limit(10).all()
    # Use Pydantic v2 model_validate(from_attributes) to convert ORM models
    return [ScanOut.model_validate(s).model_dump() for s in scans]
