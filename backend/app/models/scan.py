from sqlalchemy import Column, Integer, String, DateTime, Float, Text
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

    # PhishGuard AI 2.0 — enhanced fields
    confidence_score = Column(Float, nullable=True)           # 0-100, separate from risk_score
    severity = Column(String, default="INFORMATIONAL")        # INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL
    investigation_status = Column(String, default="NEW")      # NEW/INVESTIGATING/CONFIRMED_THREAT/FALSE_POSITIVE/RESOLVED
    indicators = Column(Text, nullable=True)                  # JSON array of structured indicator objects
    mitre_techniques = Column(Text, nullable=True)            # JSON array of MITRE ATT&CK technique mappings
    analyst_notes = Column(Text, nullable=True)               # Freeform analyst notes text
    analyst_actions = Column(Text, nullable=True)             # JSON array of recommended analyst actions
    timeline = Column(Text, nullable=True)                    # JSON array of investigation timeline events
    processing_time_ms = Column(Float, nullable=True)         # Actual scan duration in milliseconds
    detection_engine_version = Column(String, default="2.0.0")
