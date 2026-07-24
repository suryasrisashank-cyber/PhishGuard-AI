from fastapi import APIRouter
from ...services.scanner_service import threat_intelligence_lookup

router = APIRouter()


@router.get("/lookup")
def lookup(domain: str) -> dict:
    return threat_intelligence_lookup(domain)
