from sqlalchemy import Column, Integer, String, DateTime, Float
from sqlalchemy.sql import func
from ..db.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String, nullable=False)
    target = Column(String, nullable=False)
    risk_score = Column(Float, default=0.0)
    verdict = Column(String, default="Unknown")
    summary = Column(String, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
