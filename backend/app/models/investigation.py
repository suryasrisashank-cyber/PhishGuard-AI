from sqlalchemy import Column, Integer, String, DateTime, Float, Text
from sqlalchemy.sql import func
from ..db.database import Base


class InvestigationCase(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, unique=True, index=True, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, default="MEDIUM")               # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, default=0.0)
    confidence_score = Column(Float, default=50.0)
    status = Column(String, default="NEW")                   # NEW, TRIAGED, INVESTIGATING, CONFIRMED_THREAT, CONTAINMENT, RESOLVED, FALSE_POSITIVE
    analyst = Column(String, default="SOC Analyst Tier 1")
    summary = Column(Text, default="")
    evidence = Column(Text, nullable=True)                   # JSON list of evidence items
    iocs = Column(Text, nullable=True)                       # JSON list of associated IOCs
    threat_intel = Column(Text, nullable=True)               # JSON dict of enriched threat intel
    mitre_techniques = Column(Text, nullable=True)           # JSON list of MITRE techniques
    timeline = Column(Text, nullable=True)                   # JSON list of timeline events
    analyst_notes = Column(Text, default="")
    recommended_actions = Column(Text, nullable=True)        # JSON list of response actions
    splunk_events = Column(Text, nullable=True)              # JSON list of events forwarded to Splunk
    burp_findings = Column(Text, nullable=True)              # JSON list of external manual Burp Suite observations
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
