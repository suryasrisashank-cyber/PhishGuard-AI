"""
PhishGuard AI 2.0 — Pydantic schemas for scan request/response.

Key design decisions:
- risk_score and confidence_score are SEPARATE values with distinct meanings
- indicators contains structured IOC evidence (not fabricated)
- mitre_techniques only present when evidence supports the mapping
- All new fields are Optional to maintain backwards API compatibility
"""
from __future__ import annotations
from typing import Optional, List, Any
from datetime import datetime
from pydantic import BaseModel, field_validator


# ---------------------------------------------------------------------------
# Sub-schemas used within ScanOut
# ---------------------------------------------------------------------------

class IndicatorItem(BaseModel):
    """A single detected indicator of compromise or security check result."""
    name: str                       # Human-readable check name
    ioc_type: str                   # IOC category: URL, DOMAIN, IP, EMAIL, HOSTNAME, HASH
    ioc_value: str                  # The actual value (domain, IP, URL fragment, etc.)
    severity: str                   # INFORMATIONAL / LOW / MEDIUM / HIGH / CRITICAL
    passed: bool                    # True = check passed (no issue); False = issue detected
    explanation: str                # Plain-English explanation for SOC analyst
    score_impact: float = 0.0       # Risk score points contributed by this indicator
    category: str = "URL"           # DOMAIN, NETWORK, URL, CONTENT, EMAIL, AUTHENTICATION, THREAT INTELLIGENCE
    technical_evidence: str = ""    # Specific technical artifact/evidence observed
    weight: float = 0.0             # Heuristic rule weight


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique mapping — only populated when evidence supports it."""
    technique_id: str               # e.g. T1566.002
    technique_name: str             # e.g. Phishing: Spearphishing Link
    tactic: str                     # e.g. Initial Access
    reason: str                     # Why this technique was mapped
    evidence: str                   # What specific evidence triggered the mapping


class TimelineEvent(BaseModel):
    """A timestamped event in the investigation timeline."""
    timestamp: str                  # HH:MM:SS format
    event: str                      # Short event name
    detail: str                     # Detailed description


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class ScanCreate(BaseModel):
    scan_type: str
    target: str


class EmailAnalyzeRequest(BaseModel):
    """For text-based email analysis (paste email content)."""
    content: str

    @field_validator("content")
    @classmethod
    def content_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Email content cannot be empty")
        return v


class StatusUpdateRequest(BaseModel):
    """PATCH /api/scans/{id}/status"""
    investigation_status: str

    @field_validator("investigation_status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        allowed = {"NEW", "INVESTIGATING", "CONFIRMED_THREAT", "RESPONDING", "FALSE_POSITIVE", "RESOLVED"}
        if v not in allowed:
            raise ValueError(f"investigation_status must be one of {allowed}")
        return v


class NotesUpdateRequest(BaseModel):
    """PATCH /api/scans/{id}/notes"""
    analyst_notes: str


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class ScanOut(BaseModel):
    """
    Full scan result — returned by POST /api/scans/* and GET /api/scans/{id}.

    Risk Score vs Confidence Score:
      risk_score    — how dangerous the observed indicators appear (0-100)
      confidence_score — how strongly the available evidence supports the verdict (0-100)
    These are calculated independently and must never be combined or conflated.
    """
    id: int
    scan_type: str
    target: str
    risk_score: float
    verdict: str
    summary: str
    created_at: Optional[datetime] = None

    # PhishGuard AI 2.0 fields
    confidence_score: Optional[float] = None
    severity: str = "INFORMATIONAL"
    investigation_status: str = "NEW"
    indicators: Optional[List[Any]] = None          # Parsed from JSON on read
    mitre_techniques: Optional[List[Any]] = None    # Parsed from JSON on read
    analyst_notes: Optional[str] = None
    analyst_actions: Optional[List[Any]] = None     # Parsed from JSON on read
    timeline: Optional[List[Any]] = None            # Parsed from JSON on read
    processing_time_ms: Optional[float] = None
    detection_engine_version: str = "2.0.0"

    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    """Lightweight version for scan history list (avoids large JSON payloads in lists)."""
    id: int
    scan_type: str
    target: str
    risk_score: float
    verdict: str
    severity: str = "INFORMATIONAL"
    investigation_status: str = "NEW"
    created_at: Optional[datetime] = None
    confidence_score: Optional[float] = None

    model_config = {"from_attributes": True}

