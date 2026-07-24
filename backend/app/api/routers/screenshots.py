from fastapi import APIRouter, UploadFile, File
from ...services.screenshot_service import analyze_screenshot

router = APIRouter()


@router.post("/upload")
def upload_screenshot(file: UploadFile = File(...)) -> dict:
    content = file.file.read()
    result = analyze_screenshot(content)
    return {"filename": file.filename, **result}
