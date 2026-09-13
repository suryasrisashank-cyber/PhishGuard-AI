"""
PhishGuard AI — Safe Defensive Static File Analysis Service
Computes cryptographic hashes, extracts embedded strings and IOCs, performs optional YARA matching,
and queries VirusTotal without executing uploaded binaries.
"""
from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import time
from typing import Any

from ..core.config import settings
from .threat_intel.virustotal import VirusTotalProvider
from .splunk_service import splunk_service, SOURCETYPE_FILE

# Regular expressions for defensive static string & IOC extraction
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_REGEX = re.compile(r"https?://[a-zA-Z0-9_\-\.\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\%]+")
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
SUSPICIOUS_STRINGS = [
    b"cmd.exe", b"powershell", b"wscript", b"cscript", b"certutil", b"bitsadmin",
    b"rundll32", b"regsvr32", b"vssadmin", b"mimikatz", b"downloadstring", b"invoke-expression",
    b"net user", b"whoami", b"schtasks", b"payload", b"beacon", b"reverse_tcp",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse", ".ps1", ".hta", ".wsf",
    ".iso", ".img", ".vhd", ".dll", ".pif", ".cpl", ".msi", ".jar", ".lnk",
}


def analyze_file_bytes(content: bytes, filename: str) -> dict[str, Any]:
    """
    Perform pure static, defensive inspection of uploaded file bytes.
    Does NOT execute the file under any circumstances.
    """
    start_time = time.time()

    # 1. Cryptographic Hashes
    md5_hash = hashlib.md5(content).hexdigest()
    sha1_hash = hashlib.sha1(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()
    file_size = len(content)

    # 2. File Extension and MIME Type
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    mime_type, _ = mimetypes.guess_type(filename)
    mime_type = mime_type or "application/octet-stream"

    indicators: list[dict[str, Any]] = []

    # Check suspicious extension
    is_suspicious_ext = ext in SUSPICIOUS_EXTENSIONS
    indicators.append({
        "name": "Executable/Script Extension Check",
        "ioc_type": "FILE",
        "ioc_value": filename,
        "severity": "HIGH" if is_suspicious_ext else "INFORMATIONAL",
        "passed": not is_suspicious_ext,
        "score_impact": 35.0 if is_suspicious_ext else 0.0,
        "category": "FILE",
        "technical_evidence": f"Extension: '{ext}', MIME: '{mime_type}'",
        "explanation": f"File uses {ext} extension which is frequently weaponized in phishing payloads." if is_suspicious_ext else "Standard non-executable file extension.",
    })

    # 3. Static String & Embedded IOC Extraction
    extracted_urls = set(URL_REGEX.findall(content.decode("latin-1", errors="ignore")))
    extracted_ips = set(IPV4_REGEX.findall(content.decode("latin-1", errors="ignore")))
    extracted_emails = set(EMAIL_REGEX.findall(content.decode("latin-1", errors="ignore")))

    # Filter out benign loopback/broadcast IPs
    extracted_ips = {ip for ip in extracted_ips if not ip.startswith(("0.", "127.", "255."))}

    found_suspicious_strings: list[str] = []
    content_lower = content.lower()
    for s in SUSPICIOUS_STRINGS:
        if s in content_lower:
            found_suspicious_strings.append(s.decode("latin-1"))

    if found_suspicious_strings:
        indicators.append({
            "name": "Suspicious Static Strings Detected",
            "ioc_type": "STRING",
            "ioc_value": ", ".join(found_suspicious_strings[:5]),
            "severity": "HIGH",
            "passed": False,
            "score_impact": 30.0,
            "category": "STATIC_STRINGS",
            "technical_evidence": f"Found strings: {found_suspicious_strings[:5]}",
            "explanation": "File contains command execution, evasion, or scripting keywords commonly observed in droppers.",
        })

    if extracted_urls:
        indicators.append({
            "name": "Embedded Network Callout URLs",
            "ioc_type": "URL",
            "ioc_value": list(extracted_urls)[0],
            "severity": "MEDIUM",
            "passed": False,
            "score_impact": 15.0,
            "category": "NETWORK",
            "technical_evidence": f"Extracted {len(extracted_urls)} embedded URLs: {list(extracted_urls)[:3]}",
            "explanation": "Static extraction identified external URLs embedded inside the file.",
        })

    # 4. Optional YARA Engine Matching
    yara_result = {"status": "not_configured", "matched_rules": [], "message": "YARA engine not configured."}
    try:
        import yara
        rules_path = settings.yara_rules_path
        if rules_path and os.path.exists(rules_path):
            rules = yara.compile(filepath=rules_path)
            matches = rules.match(data=content)
            matched_names = [m.rule for m in matches]
            if matched_names:
                yara_result = {"status": "matched", "matched_rules": matched_names, "message": f"Matched {len(matched_names)} YARA rule(s)."}
                indicators.append({
                    "name": "YARA Rule Matches",
                    "ioc_type": "YARA",
                    "ioc_value": ", ".join(matched_names),
                    "severity": "CRITICAL",
                    "passed": False,
                    "score_impact": 40.0,
                    "category": "SIGNATURE",
                    "technical_evidence": f"YARA rules: {matched_names}",
                    "explanation": "Static binary signatures matched configured YARA detection rules.",
                })
            else:
                yara_result = {"status": "clean", "matched_rules": [], "message": "No configured YARA rules matched."}
        else:
            yara_result = {"status": "not_configured", "matched_rules": [], "message": "YARA rules path not configured in environment."}
    except ImportError:
        yara_result = {"status": "unavailable", "matched_rules": [], "message": "yara-python package unavailable on host."}
    except Exception as e:
        yara_result = {"status": "error", "matched_rules": [], "message": f"YARA evaluation error: {type(e).__name__}"}

    # 5. VirusTotal Hash Check (if configured)
    vt_provider = VirusTotalProvider()
    vt_result = vt_provider.lookup_hash(sha256_hash)
    if vt_result.get("provider_verdict") == "MALICIOUS":
        indicators.append({
            "name": "VirusTotal Hash Match",
            "ioc_type": "HASH",
            "ioc_value": sha256_hash,
            "severity": "CRITICAL",
            "passed": False,
            "score_impact": 40.0,
            "category": "THREAT_INTEL",
            "technical_evidence": str(vt_result.get("raw_reputation", {})),
            "explanation": vt_result.get("normalized_interpretation", "Identified as malicious by AV vendors on VirusTotal."),
        })

    # 6. Scoring & MITRE Mapping
    risk_score = round(min(100.0, sum(i["score_impact"] for i in indicators if not i["passed"])), 2)
    confidence_score = 85.0 if vt_provider.is_configured else 70.0

    if risk_score >= 60.0:
        verdict = "Malicious"
        severity = "CRITICAL" if risk_score >= 80 else "HIGH"
    elif risk_score >= 30.0:
        verdict = "Suspicious"
        severity = "MEDIUM"
    else:
        verdict = "Safe"
        severity = "INFORMATIONAL"

    mitre_techniques: list[dict[str, Any]] = []
    if is_suspicious_ext:
        mitre_techniques.append({
            "technique_id": "T1204.002",
            "technique_name": "User Execution: Malicious File",
            "tactic": "Execution",
            "evidence": f"File extension '{ext}' invites direct execution by victim.",
        })
    if found_suspicious_strings:
        mitre_techniques.append({
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "evidence": f"Discovered commands: {found_suspicious_strings[:3]}",
        })

    processing_time_ms = round((time.time() - start_time) * 1000, 2)

    # 7. Normalize Result
    result = {
        "scan_type": "file",
        "target": filename,
        "file_name": filename,
        "file_size_bytes": file_size,
        "mime_type": mime_type,
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash,
        "risk_score": risk_score,
        "confidence_score": confidence_score,
        "severity": severity,
        "verdict": verdict,
        "summary": f"Static analysis of '{filename}' completed in {processing_time_ms}ms. Hashes computed. Verdict: {verdict}.",
        "indicators": indicators,
        "mitre_techniques": mitre_techniques,
        "extracted_iocs": {
            "urls": list(extracted_urls)[:20],
            "ips": list(extracted_ips)[:20],
            "emails": list(extracted_emails)[:20],
            "suspicious_strings": found_suspicious_strings,
        },
        "yara": yara_result,
        "threat_intelligence": {"virustotal": vt_result},
        "processing_time_ms": processing_time_ms,
        "detection_engine_version": "3.0.0",
    }

    # 8. Optional Splunk Forwarding
    if splunk_service.is_configured:
        splunk_service.send_event(result, sourcetype=SOURCETYPE_FILE, event_type="file_analysis")

    return result
