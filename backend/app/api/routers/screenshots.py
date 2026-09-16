import logging
from fastapi import APIRouter, UploadFile, File, Depends
from sqlalchemy.orm import Session
from ...db.database import get_db
from ...models.scan import Scan
from ...services.screenshot_service import analyze_screenshot
from .scans import _scan_to_dict, _post_process_scan, _serialize_scan

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/upload")
def upload_screenshot(file: UploadFile = File(...), db: Session = Depends(get_db)) -> dict:
    content = file.file.read()
    result = analyze_screenshot(content)
    filename = file.filename or "screenshot.png"

    # Persist screenshot scan to server database
    scan_kwargs = _scan_to_dict(result, "screenshot", filename)
    scan = Scan(**scan_kwargs)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    _post_process_scan(scan, result, "screenshot", db)
    logger.info(f"Screenshot scan persisted: ID #{scan.id} ({filename})")

    serialized = _serialize_scan(scan)
    return {
        "id": scan.id,
        "filename": filename,
        **result,
        **serialized,
    }

