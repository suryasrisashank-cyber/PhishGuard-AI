from pydantic import BaseModel


class ScanCreate(BaseModel):
    scan_type: str
    target: str


class ScanOut(BaseModel):
    id: int
    scan_type: str
    target: str
    risk_score: float
    verdict: str
    summary: str

    model_config = {"from_attributes": True}
