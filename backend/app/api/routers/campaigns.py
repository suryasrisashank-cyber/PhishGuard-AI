"""
PhishGuard AI — Threat Campaigns Router
Correlates disparate scans, indicators, and cases into unified threat campaign clusters.
"""
from __future__ import annotations

import collections
import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ...db.database import get_db
from ...models.scan import Scan
from ...models.ioc import IOCRecord
from ...models.investigation import InvestigationCase

router = APIRouter()


@router.get("")
def list_campaigns(db: Session = Depends(get_db)):
    """Group identified indicators into coherent threat infrastructure campaigns."""
    scans = db.query(Scan).filter(Scan.verdict.in_(["Suspicious", "Malicious"])).all()

    # Cluster by brand or shared infrastructure
    clusters: dict[str, dict] = collections.defaultdict(lambda: {
        "targets": set(),
        "scan_ids": set(),
        "scan_types": set(),
        "severities": collections.defaultdict(int),
        "total_risk": 0.0,
        "sample_verdict": "Suspicious",
    })

    for s in scans:
        # Determine theme or brand
        theme = "Unassigned Campaign Infrastructure"
        if s.indicators:
            try:
                inds = json.loads(s.indicators)
                for ind in inds:
                    name = ind.get("name", "").lower()
                    if "brand impersonation" in name or "credential" in name:
                        tech_ev = ind.get("technical_evidence", "")
                        for brand in ["paypal", "microsoft", "google", "apple", "amazon", "chase", "netflix", "docusign", "fedex", "dhl"]:
                            if brand in s.target.lower() or brand in tech_ev.lower():
                                theme = f"{brand.capitalize()} Spoofing Campaign"
                                break
            except Exception:
                pass

        cluster = clusters[theme]
        cluster["targets"].add(s.target)
        cluster["scan_ids"].add(s.id)
        cluster["scan_types"].add(s.scan_type)
        cluster["severities"][s.severity or "MEDIUM"] += 1
        cluster["total_risk"] += (s.risk_score or 0.0)
        if s.verdict == "Malicious":
            cluster["sample_verdict"] = "Malicious"

    campaign_list = []
    idx = 1
    for name, data in clusters.items():
        count = len(data["scan_ids"])
        avg_risk = round(data["total_risk"] / count, 1) if count else 0.0
        campaign_list.append({
            "campaign_id": f"PG-CAMP-{idx:03d}",
            "name": name,
            "target_count": len(data["targets"]),
            "targets": list(data["targets"])[:10],
            "related_scan_ids": list(data["scan_ids"])[:10],
            "modalities": list(data["scan_types"]),
            "average_risk": avg_risk,
            "severity_breakdown": dict(data["severities"]),
            "verdict": data["sample_verdict"],
            "first_observed": "Recent Telemetry",
        })
        idx += 1

    return {
        "total_campaigns": len(campaign_list),
        "campaigns": sorted(campaign_list, key=lambda x: x["average_risk"], reverse=True),
    }
