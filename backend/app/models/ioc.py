from sqlalchemy import Column, Integer, String, DateTime, Float, Text
from sqlalchemy.sql import func
from ..db.database import Base


class IOCRecord(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, unique=True, index=True, nullable=False)
    ioc_type = Column(String, index=True, nullable=False)  # URL, DOMAIN, IPv4, IPv6, EMAIL, SHA256, SHA1, MD5, CERTIFICATE
    severity = Column(String, default="INFORMATIONAL")     # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=50.0)              # 0.0 - 100.0
    reputation = Column(String, default="UNKNOWN")         # BENIGN, SUSPICIOUS, MALICIOUS, UNKNOWN
    source = Column(String, default="Automated Scanner")
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    scan_count = Column(Integer, default=1)
    notes = Column(Text, nullable=True)
    raw_intelligence = Column(Text, nullable=True)         # JSON string of raw external provider results
