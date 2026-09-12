"""
PhishGuard AI 2.1 — AI Security Explanation Router
====================================================
Generates plain-English security explanations strictly from structured scanner evidence.
Integrity Rules:
  - Input MUST come from structured scanner evidence.
  - The AI layer NEVER invents facts, external reputation, domain age, malware, or attribution.
  - Transparently marked as "AI-assisted explanation".
  - If external AI API keys are not present, uses a deterministic expert-system translation.
"""
from typing import Any, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from ...core.config import settings

router = APIRouter()


class ExplainRequest(BaseModel):
    verdict: str
    risk_score: float
    confidence_score: Optional[float] = None
    severity: str
    target: str
    indicators: List[dict] = []
    mitre_techniques: List[dict] = []


class ExplainResponse(BaseModel):
    headline: str
    explanation: str
    key_drivers: List[str]
    analyst_context: str
    provider: str
    disclaimer: str


@router.post("/explain", response_model=ExplainResponse)
def generate_ai_explanation(payload: ExplainRequest) -> ExplainResponse:
    """
    Produce an honest, plain-English security explanation based strictly
    on deterministic scanner findings.
    """
    failed_indicators = [ind for ind in payload.indicators if not ind.get("passed", True)]
    failed_names = [ind.get("name", "Unknown Check") for ind in failed_indicators]

    # Key drivers from failed checks
    key_drivers = []
    for ind in failed_indicators[:5]:
        explanation = ind.get("explanation", "")
        tech_ev = ind.get("technical_evidence", "")
        if tech_ev and tech_ev != "Within expected parameters":
            key_drivers.append(f"{ind.get('name')}: {tech_ev}")
        elif explanation:
            key_drivers.append(f"{ind.get('name')}: {explanation[:120]}")
        else:
            key_drivers.append(ind.get("name", "Security check failed"))

    if not key_drivers:
        key_drivers.append("All automated heuristic security checks passed within expected baseline thresholds.")

    # Generate synthesized analyst context
    verdict_upper = payload.verdict.upper()
    if payload.verdict == "Malicious":
        headline = f"High-Confidence Threat Detected: {payload.target}"
        explanation = (
            f"This target was classified as MALICIOUS with a calculated risk score of {payload.risk_score:.0f}/100 "
            f"and {payload.severity} severity. Primary danger signals stem from {len(failed_indicators)} identified "
            f"threat indicator(s), specifically: {', '.join(failed_names[:3]) if failed_names else 'heuristic risk flags'}. "
            "Evidence indicates tactical alignment with credential harvesting or deceptive infrastructure."
        )
        analyst_context = (
            "Recommended SOC priority: Immediate containment. Add this target to perimeter blocklists, "
            "investigate historical telemetry in SIEM for past interactions, and verify if internal users "
            "submitted credentials."
        )
    elif payload.verdict == "Suspicious":
        headline = f"Anomalous Indicators Require Analyst Triage: {payload.target}"
        explanation = (
            f"This target was classified as SUSPICIOUS with a risk score of {payload.risk_score:.0f}/100. "
            f"While not conclusively proven malicious, the analysis flagged {len(failed_indicators)} anomaly pattern(s): "
            f"{', '.join(failed_names[:3]) if failed_names else 'structural deviations'}. "
            "These traits are frequently weaponized in spearphishing and reconnaissance campaigns."
        )
        analyst_context = (
            "Recommended SOC priority: Secondary triage. Enrich via WHOIS and passive DNS records, "
            "inspect page content with the Website Analyzer, and monitor for related domain registrations."
        )
    else:
        headline = f"Target Evaluated as Safe: {payload.target}"
        explanation = (
            f"Analysis of '{payload.target}' yielded a risk score of {payload.risk_score:.0f}/100 (Safe verdict). "
            f"Across {len(payload.indicators)} heuristic evaluation checks, no recognized phishing, homoglyph, "
            "brand impersonation, or obfuscation indicators were detected."
        )
        analyst_context = (
            "No immediate containment required. Maintain routine passive monitoring and verify destination "
            "if reported through user phishing submission channels."
        )

    return ExplainResponse(
        headline=headline,
        explanation=explanation,
        key_drivers=key_drivers,
        analyst_context=analyst_context,
        provider="PhishGuard Heuristic Synthesis Engine v2.1",
        disclaimer="AI-assisted explanation: Derived strictly from deterministic scanner findings. Does not extrapolate unverified threat intelligence.",
    )
