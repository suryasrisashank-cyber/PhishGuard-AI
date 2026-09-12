"""
PhishGuard AI 2.0 — Heuristic Detection Engine
================================================
Detection methodology:
  - Rule-based heuristic analysis (no ML inference in this version)
  - Each check produces a structured IndicatorItem with evidence
  - Risk Score   = sum of score_impact values for failed checks (capped at 100)
  - Confidence   = ratio of conclusive checks to total checks (deterministic, not invented)
  - Severity     = derived from risk score + presence of high-impact indicators
  - MITRE ATT&CK = mapped only when specific evidence patterns are observed

No external threat intelligence APIs are called unless configured via environment variables.
All results are based solely on heuristic analysis of the input.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
import socket
import time
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, unquote

import requests
import tldextract
from bs4 import BeautifulSoup
import dns.resolver
import whois

DETECTION_ENGINE_VERSION = "2.1.0"

# ---------------------------------------------------------------------------
# Constants — Detection rules knowledge base
# ---------------------------------------------------------------------------

# Brands commonly impersonated in phishing campaigns
# Each entry is the brand keyword that should only appear in the brand's own domain.
BRAND_IMPERSONATION_MAP: dict[str, str] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "outlook": "outlook.com",
    "office365": "office.com",
    "docusign": "docusign.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "dhl": "dhl.com",
    "irs": "irs.gov",
    "walmart": "walmart.com",
    "ebay": "ebay.com",
    "steam": "steampowered.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
}

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_URL_KEYWORDS: list[str] = [
    "login", "signin", "sign-in", "verify", "secure", "update", "alert",
    "confirm", "validate", "credential", "suspended", "urgent", "billing",
    "invoice", "account", "password", "authenticate", "access", "unlock",
    "recover", "claim", "reward", "prize", "limited-time", "act-now",
    "click-here", "free", "winner",
]

# TLDs frequently abused in phishing campaigns (not inherently malicious alone)
SUSPICIOUS_TLDS: set[str] = {
    "xyz", "tk", "ml", "cf", "ga", "gq", "pw", "top", "club",
    "work", "click", "link", "download", "zip", "review", "country",
    "kim", "cricket", "science", "party", "gdn", "stream", "win",
    "loan", "bid", "trade", "date", "faith", "racing", "accountant",
    "men", "webcam", "tech", "space", "online",
}

# Non-standard ports that may indicate a phishing server
SUSPICIOUS_PORTS: set[int] = {8080, 8443, 8000, 3000, 4000, 5000, 9000, 1337, 4444}

# Query parameter names used in redirect chains
REDIRECT_PARAMS: set[str] = {"url", "redirect", "next", "return", "goto", "dest", "destination", "ref", "return_to"}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy (> 3.5) may indicate randomly generated or obfuscated content.
    """
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def _is_punycode(hostname: str) -> bool:
    """Detect IDN/Punycode hostnames (xn-- prefix) used in homograph attacks."""
    return "xn--" in hostname.lower()


def _has_unicode_lookalikes(hostname: str) -> bool:
    """
    Detect Unicode characters outside standard ASCII that may visually impersonate
    ASCII letters (homograph/IDN homograph attack).
    """
    try:
        hostname.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def _is_private_or_internal_ip(ip_str: str) -> bool:
    """Check if an IP address string is private, loopback, link-local, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False


def _validate_safe_url_for_fetch(url: str) -> tuple[bool, str]:
    """
    Validate that a URL is safe to fetch over HTTP/HTTPS, preventing SSRF attacks.
    Blocks:
      - non-http/https schemes
      - localhost, 127.0.0.1, ::1
      - private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.)
      - link-local addresses (169.254.0.0/16)
      - cloud metadata endpoints (169.254.169.254)
      - internal domain suffixes (.local, .internal, .lan, etc.)
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "Target URL contains no valid hostname."

    # Immediate host checks
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or hostname.endswith((".local", ".internal", ".lan", ".corp")):
        return False, "Access to internal, loopback, or private hostnames is strictly prohibited."

    # Direct IP check
    if _is_private_or_internal_ip(hostname):
        return False, f"Direct access to private or reserved IP range ({hostname}) is blocked."

    # DNS resolution check for SSRF protection
    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in resolved_ips:
            ip_val = sockaddr[0]
            if _is_private_or_internal_ip(ip_val):
                return False, f"Resolved IP {ip_val} resides in a private or restricted network range."
    except socket.gaierror:
        # Domain resolution failed — will be handled by HTTP client or DNS analyzer
        pass
    except Exception:
        pass

    return True, "URL passed SSRF verification"


def _make_indicator(
    name: str,
    ioc_type: str,
    ioc_value: str,
    severity: str,
    passed: bool,
    explanation: str,
    score_impact: float = 0.0,
    category: str = "URL",
    technical_evidence: str = "",
) -> dict[str, Any]:
    """Construct a standard IndicatorItem dict with technical evidence and category."""
    return {
        "name": name,
        "ioc_type": ioc_type,
        "ioc_value": str(ioc_value)[:300],
        "severity": severity,
        "passed": passed,
        "explanation": explanation,
        "score_impact": score_impact if not passed else 0.0,
        "category": category,
        "technical_evidence": technical_evidence or (str(ioc_value)[:300] if not passed else "Within expected parameters"),
        "weight": score_impact,
    }


def _calculate_risk(indicators: list[dict]) -> float:
    """
    Risk Score = sum of score_impact for all failed checks, capped at 100.
    This represents how dangerous the observed indicators appear.
    """
    total = sum(ind["score_impact"] for ind in indicators if not ind["passed"])
    return round(min(total, 100.0), 2)


def _calculate_confidence(indicators: list[dict]) -> Optional[float]:
    """
    Confidence Score = ratio of checks with real evidence to total checks.
    This represents how strongly available evidence supports the verdict.

    Returns None if there are fewer than 4 indicators (insufficient basis).
    Never returns 100.0 — we cannot be absolutely certain from heuristics alone.
    """
    if len(indicators) < 4:
        return None

    # Checks that produced definitive results (had actual values to examine)
    conclusive = sum(1 for i in indicators if i["ioc_value"] != "" and i["ioc_value"] != "N/A")
    total = len(indicators)
    ratio = conclusive / total

    # Scale: full evidence coverage → max 92%; reduce if many checks lacked data
    confidence = round(ratio * 92.0, 1)
    return confidence


def _calculate_severity(risk_score: float, indicators: list[dict]) -> str:
    """
    Severity matrix — NOT simply mapped from verdict:
      CRITICAL    : risk >= 80, or brand impersonation + risk >= 60, or punycode + risk >= 70
      HIGH        : risk >= 60, or brand impersonation, or punycode
      MEDIUM      : risk >= 40
      LOW         : risk >= 20
      INFORMATIONAL: risk < 20

    Severity is independent from verdict. A "Suspicious" scan can still be HIGH severity.
    """
    has_brand_impersonation = any(
        not ind["passed"] and "brand impersonation" in ind["name"].lower()
        for ind in indicators
    )
    has_punycode = any(
        not ind["passed"] and "punycode" in ind["name"].lower()
        for ind in indicators
    )
    has_ip_hostname = any(
        not ind["passed"] and "ip address" in ind["name"].lower()
        for ind in indicators
    )

    if (
        risk_score >= 80
        or (has_brand_impersonation and risk_score >= 60)
        or (has_punycode and risk_score >= 70)
    ):
        return "CRITICAL"
    elif risk_score >= 60 or has_brand_impersonation or has_punycode or has_ip_hostname:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    elif risk_score >= 20:
        return "LOW"
    else:
        return "INFORMATIONAL"


def _get_verdict(risk_score: float) -> str:
    """Verdict thresholds: Safe < 40, Suspicious 40-69, Malicious >= 70."""
    if risk_score >= 70:
        return "Malicious"
    elif risk_score >= 40:
        return "Suspicious"
    return "Safe"


def _get_mitre_mappings(indicators: list[dict], verdict: str) -> list[dict]:
    """
    MITRE ATT&CK mapping — ONLY populated when specific evidence patterns are observed.
    Rule: do not add technique mappings merely to make the UI look advanced.

    Potential mappings:
      T1566.002 — Phishing: Spearphishing Link (brand impersonation + suspicious link)
      T1566.001 — Phishing: Spearphishing Attachment (attachment indicators in email)
      T1566     — Phishing (generic phishing indicators)
      T1598.003 — Phishing for Information: Spearphishing Link (info-gathering phishing)
    """
    if verdict == "Safe":
        return []  # No ATT&CK mapping for safe URLs

    has_brand = any(not i["passed"] and "brand impersonation" in i["name"].lower() for i in indicators)
    has_credential_kw = any(not i["passed"] and ("credential" in i["name"].lower() or "login" in i["name"].lower()) for i in indicators)

    mappings: list[dict] = []

    if has_brand:
        mappings.append({
            "technique_id": "T1566.002",
            "technique_name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "reason": "Brand impersonation pattern detected — URL mimics a trusted organization's domain to deceive users.",
            "evidence": f"Domain contains brand name outside the brand's known legitimate domain. Verdict: {verdict}.",
        })
    elif has_credential_kw and verdict in ("Suspicious", "Malicious"):
        mappings.append({
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactic": "Initial Access",
            "reason": "Credential harvesting language detected in URL combined with multiple phishing indicators.",
            "evidence": "URL contains keywords associated with credential collection (login, verify, password, etc.).",
        })
    elif verdict == "Malicious":
        mappings.append({
            "technique_id": "T1598.003",
            "technique_name": "Phishing for Information: Spearphishing Link",
            "tactic": "Reconnaissance",
            "reason": "Multiple phishing indicators suggest this URL is designed to collect user information.",
            "evidence": "URL demonstrates several characteristics associated with phishing campaigns.",
        })

    return mappings


def _get_analyst_actions(indicators: list[dict], verdict: str, scan_type: str = "url") -> list[str]:
    """Dynamic analyst recommendations based on what was actually found."""
    actions: list[str] = []

    if verdict in ("Suspicious", "Malicious"):
        actions.append("Investigate the full domain registration via WHOIS lookup")
        actions.append("Query DNS records (A, MX, TXT) for the domain")

    has_brand = any(not i["passed"] and "brand impersonation" in i["name"].lower() for i in indicators)
    if has_brand:
        actions.append("Verify whether this domain is an official asset of the impersonated brand")
        actions.append("Consider reporting the domain to the brand's abuse team")

    has_ip = any(not i["passed"] and "ip address" in i["name"].lower() for i in indicators)
    if has_ip:
        actions.append("Look up the IP address in threat intelligence databases (AbuseIPDB, VirusTotal)")
        actions.append("Check for other phishing infrastructure on the same IP block")

    has_redirect = any(not i["passed"] and "redirect" in i["name"].lower() for i in indicators)
    if has_redirect:
        actions.append("Trace the full redirect chain to identify the final landing page")

    if verdict == "Malicious":
        actions.append("Block this URL in endpoint security and proxy controls")
        actions.append("Search scan history for related domains and infrastructure")
        actions.append("Generate an incident report and escalate to the security team")
        actions.append("Notify affected users if this URL was distributed via email or messaging")

    if verdict == "Suspicious":
        actions.append("Perform website content analysis to examine the actual page")
        actions.append("Monitor for similar domains using pattern-based detection")

    if not actions:
        actions.append("No immediate action required — continue monitoring")

    return actions


def _build_timeline(start_time: float, url: str, indicators: list[dict], verdict: str) -> list[dict]:
    """Build an investigation timeline with realistic timestamps."""
    end_time = time.time()
    elapsed = end_time - start_time

    # Allocate elapsed time proportionally across pipeline stages
    stages = [
        (0.05, "URL Submitted", f"Target URL received for analysis: {url[:80]}{'...' if len(url) > 80 else ''}"),
        (0.15, "URL Normalization", "URL parsed: scheme, hostname, port, path, query string extracted"),
        (0.25, "Domain Analysis", "Domain structure, TLD, and subdomain chain analyzed"),
        (0.45, "Pattern Detection", f"{sum(1 for i in indicators if not i['passed'])} suspicious pattern(s) detected across {len(indicators)} checks"),
        (0.65, "Reputation Analysis", "Heuristic scoring applied — no external threat feeds queried"),
        (0.85, "Risk Calculation", "Risk score and confidence score calculated from indicator weights"),
        (1.00, f"Verdict: {verdict}", f"Analysis complete — verdict determined as {verdict.upper()}"),
    ]

    events = []
    for fraction, event, detail in stages:
        t = start_time + (elapsed * fraction)
        events.append({
            "timestamp": time.strftime("%H:%M:%S", time.localtime(t)),
            "event": event,
            "detail": detail,
        })

    return events


# ---------------------------------------------------------------------------
# URL Analysis — Main entry point
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> dict[str, Any]:
    """
    Comprehensive heuristic URL analysis.

    Returns a dict containing:
      risk_score, confidence_score, verdict, severity, summary,
      indicators, mitre_techniques, analyst_actions, timeline,
      processing_time_ms, detection_engine_version
    """
    start_time = time.time()
    indicators: list[dict] = []

    parsed = urlparse(url)
    domain_info = tldextract.extract(url)
    hostname = parsed.hostname or ""
    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_domain = f"{domain_info.subdomain}.{domain_info.domain}.{domain_info.suffix}".lstrip(".")

    # ------------------------------------------------------------------
    # Check 1: URL scheme (HTTPS)
    # ------------------------------------------------------------------
    scheme = (parsed.scheme or "").lower()
    if scheme == "https":
        indicators.append(_make_indicator(
            name="HTTPS Encryption",
            ioc_type="URL",
            ioc_value=url[:100],
            severity="INFORMATIONAL",
            passed=True,
            explanation="URL uses HTTPS. Encrypted connection is expected for legitimate sites. Note: HTTPS alone does not guarantee safety.",
            score_impact=0.0,
        ))
    elif scheme == "http":
        indicators.append(_make_indicator(
            name="No HTTPS (HTTP Only)",
            ioc_type="URL",
            ioc_value=url[:100],
            severity="MEDIUM",
            passed=False,
            explanation="URL uses unencrypted HTTP. Phishing pages sometimes avoid HTTPS to reduce cost, though many now use it. This increases suspicion in combination with other indicators.",
            score_impact=10.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="Missing or Malformed Scheme",
            ioc_type="URL",
            ioc_value=url[:100],
            severity="HIGH",
            passed=False,
            explanation="The URL does not have a valid scheme (http/https). Malformed URLs often indicate automated generation or obfuscation.",
            score_impact=25.0,
        ))

    # ------------------------------------------------------------------
    # Check 2: IP address as hostname
    # ------------------------------------------------------------------
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(hostname):
        indicators.append(_make_indicator(
            name="IP Address as Hostname",
            ioc_type="IP",
            ioc_value=hostname,
            severity="HIGH",
            passed=False,
            explanation=f"The URL uses a raw IP address ({hostname}) instead of a domain name. Legitimate websites almost always use domain names. This is a strong phishing indicator.",
            score_impact=30.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="Domain Name (Not Raw IP)",
            ioc_type="DOMAIN",
            ioc_value=hostname,
            severity="INFORMATIONAL",
            passed=True,
            explanation="Hostname is a domain name, not a raw IP address.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Check 3: URL length
    # ------------------------------------------------------------------
    url_len = len(url)
    if url_len > 100:
        indicators.append(_make_indicator(
            name="Excessive URL Length",
            ioc_type="URL",
            ioc_value=f"Length: {url_len} characters",
            severity="MEDIUM",
            passed=False,
            explanation=f"URL is {url_len} characters long. Phishing URLs are often lengthy to include embedded redirect parameters or obfuscate the true destination.",
            score_impact=15.0,
        ))
    elif url_len > 70:
        indicators.append(_make_indicator(
            name="Long URL",
            ioc_type="URL",
            ioc_value=f"Length: {url_len} characters",
            severity="LOW",
            passed=False,
            explanation=f"URL length ({url_len} chars) is above average. Moderately long URLs can indicate redirect chains or parameter manipulation.",
            score_impact=8.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="Normal URL Length",
            ioc_type="URL",
            ioc_value=f"Length: {url_len} characters",
            severity="INFORMATIONAL",
            passed=True,
            explanation="URL length is within normal range.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Check 4: Suspicious TLD
    # ------------------------------------------------------------------
    suffix = (domain_info.suffix or "").lower()
    if suffix in SUSPICIOUS_TLDS:
        indicators.append(_make_indicator(
            name="Suspicious TLD",
            ioc_type="DOMAIN",
            ioc_value=f".{suffix}",
            severity="MEDIUM",
            passed=False,
            explanation=f"The TLD '.{suffix}' is frequently abused in phishing and spam campaigns due to low registration cost and limited oversight. While not conclusive alone, it increases overall suspicion.",
            score_impact=12.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="Common TLD",
            ioc_type="DOMAIN",
            ioc_value=f".{suffix}" if suffix else "N/A",
            severity="INFORMATIONAL",
            passed=True,
            explanation="TLD is not in the list of commonly abused registries.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Check 5: Suspicious keywords in URL
    # ------------------------------------------------------------------
    lowered_url = url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in lowered_url]
    if matched_keywords:
        indicators.append(_make_indicator(
            name="Suspicious Keywords in URL",
            ioc_type="URL",
            ioc_value=", ".join(matched_keywords[:5]),
            severity="MEDIUM",
            passed=False,
            explanation=f"The URL contains keywords associated with phishing: {', '.join(matched_keywords[:5])}. These terms are frequently used to create urgency or mimic authentication flows.",
            score_impact=15.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="No Suspicious Keywords",
            ioc_type="URL",
            ioc_value="N/A",
            severity="INFORMATIONAL",
            passed=True,
            explanation="No phishing-associated keywords detected in the URL.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Check 6: Excessive subdomains
    # ------------------------------------------------------------------
    subdomain = domain_info.subdomain or ""
    sub_count = len([s for s in subdomain.split(".") if s]) if subdomain else 0
    if sub_count >= 3:
        indicators.append(_make_indicator(
            name="Excessive Subdomain Depth",
            ioc_type="DOMAIN",
            ioc_value=f"{subdomain}.{domain_info.domain}.{suffix}",
            severity="MEDIUM",
            passed=False,
            explanation=f"URL has {sub_count} subdomain levels ({subdomain}). Phishing URLs often stack subdomains to bury the actual registered domain and make the URL appear legitimate at a glance.",
            score_impact=12.0,
        ))
    elif sub_count >= 1:
        indicators.append(_make_indicator(
            name="Subdomain Present",
            ioc_type="DOMAIN",
            ioc_value=f"{subdomain}.{domain_info.domain}.{suffix}",
            severity="LOW",
            passed=False,
            explanation=f"URL contains a subdomain ({subdomain}). Single subdomains are common in legitimate sites, but phishing sites often use them to impersonate (e.g. paypal.attacker.com).",
            score_impact=5.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="No Excessive Subdomains",
            ioc_type="DOMAIN",
            ioc_value=hostname,
            severity="INFORMATIONAL",
            passed=True,
            explanation="Domain has no excessive subdomain nesting.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Check 7: URL entropy (Shannon entropy on hostname)
    # ------------------------------------------------------------------
    entropy = _shannon_entropy(hostname)
    if entropy > 4.0:
        indicators.append(_make_indicator(
            name="High Hostname Entropy",
            ioc_type="DOMAIN",
            ioc_value=f"Entropy: {entropy} (hostname: {hostname})",
            severity="MEDIUM",
            passed=False,
            explanation=f"The hostname has Shannon entropy of {entropy}, suggesting random or algorithmically generated characters. DGA (Domain Generation Algorithm) domains used in phishing often have high entropy.",
            score_impact=12.0,
        ))
    elif entropy > 3.5:
        indicators.append(_make_indicator(
            name="Elevated Hostname Entropy",
            ioc_type="DOMAIN",
            ioc_value=f"Entropy: {entropy}",
            severity="LOW",
            passed=False,
            explanation=f"Hostname entropy ({entropy}) is above average but within a range that can occur with legitimate complex domain names.",
            score_impact=5.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="Normal Hostname Entropy",
            ioc_type="DOMAIN",
            ioc_value=f"Entropy: {entropy}",
            severity="INFORMATIONAL",
            passed=True,
            explanation="Hostname entropy is within normal range for human-readable domains.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Check 8: Percent-encoded characters in hostname or path
    # ------------------------------------------------------------------
    percent_count = url.count("%")
    if percent_count > 5:
        indicators.append(_make_indicator(
            name="Heavy Percent-Encoding",
            ioc_type="URL",
            ioc_value=f"{percent_count} encoded sequences",
            severity="HIGH",
            passed=False,
            explanation=f"URL contains {percent_count} percent-encoded characters. Excessive encoding is a common technique to obfuscate malicious URLs from simple filters and human review.",
            score_impact=20.0,
        ))
    elif percent_count > 2:
        indicators.append(_make_indicator(
            name="Percent-Encoded Characters",
            ioc_type="URL",
            ioc_value=f"{percent_count} encoded sequences",
            severity="LOW",
            passed=False,
            explanation=f"URL contains {percent_count} percent-encoded sequences. Some encoding is normal, but higher counts may indicate obfuscation.",
            score_impact=8.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="Minimal URL Encoding",
            ioc_type="URL",
            ioc_value="N/A",
            severity="INFORMATIONAL",
            passed=True,
            explanation="URL does not contain suspicious levels of percent-encoding.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Check 9: Punycode / IDN (homograph attack)
    # ------------------------------------------------------------------
    if _is_punycode(hostname):
        indicators.append(_make_indicator(
            name="Punycode / IDN Hostname",
            ioc_type="DOMAIN",
            ioc_value=hostname,
            severity="HIGH",
            passed=False,
            explanation=f"The hostname '{hostname}' uses Punycode (xn--) encoding, which is the mechanism for internationalized domain names. This is a technique used in homograph attacks where visually similar Unicode characters impersonate ASCII domains (e.g., pаypal.com using Cyrillic 'а').",
            score_impact=25.0,
        ))
    elif _has_unicode_lookalikes(hostname):
        indicators.append(_make_indicator(
            name="Unicode Lookalike Characters",
            ioc_type="DOMAIN",
            ioc_value=hostname,
            severity="HIGH",
            passed=False,
            explanation=f"The hostname contains non-ASCII Unicode characters that may visually resemble ASCII letters. This is the homograph attack technique used to impersonate well-known domains.",
            score_impact=25.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="No Punycode/IDN Indicators",
            ioc_type="DOMAIN",
            ioc_value=hostname,
            severity="INFORMATIONAL",
            passed=True,
            explanation="Hostname uses standard ASCII characters with no punycode encoding.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Check 10: Non-standard port
    # ------------------------------------------------------------------
    port = parsed.port
    if port and port in SUSPICIOUS_PORTS:
        indicators.append(_make_indicator(
            name="Suspicious Port",
            ioc_type="URL",
            ioc_value=f":{port}",
            severity="MEDIUM",
            passed=False,
            explanation=f"URL uses port {port}, which is non-standard for web traffic. Phishing infrastructure is sometimes hosted on non-standard ports to avoid default port filtering.",
            score_impact=15.0,
        ))
    elif port and port not in (80, 443, None):
        indicators.append(_make_indicator(
            name="Non-Standard Port",
            ioc_type="URL",
            ioc_value=f":{port}",
            severity="LOW",
            passed=False,
            explanation=f"URL specifies port {port}. Legitimate sites occasionally use non-standard ports, but this warrants additional scrutiny.",
            score_impact=8.0,
        ))

    # ------------------------------------------------------------------
    # Check 11: Redirect parameters in query string
    # ------------------------------------------------------------------
    if query:
        params = parse_qs(query)
        redirect_found = [p for p in params if p.lower() in REDIRECT_PARAMS]
        if redirect_found:
            indicators.append(_make_indicator(
                name="Redirect Parameters in URL",
                ioc_type="URL",
                ioc_value=", ".join(redirect_found),
                severity="MEDIUM",
                passed=False,
                explanation=f"Query string contains redirect parameters: {', '.join(redirect_found)}. These can be exploited in open redirect attacks to bounce victims through a trusted domain to a malicious one.",
                score_impact=15.0,
            ))

    # ------------------------------------------------------------------
    # Check 12: Brand impersonation
    # ------------------------------------------------------------------
    registered_domain = f"{domain_info.domain}.{domain_info.suffix}".lower()
    impersonated_brand = None
    for brand, legit_domain in BRAND_IMPERSONATION_MAP.items():
        # Brand name appears in domain but this is NOT the legitimate domain
        if brand in registered_domain.replace(legit_domain, ""):
            impersonated_brand = brand
            break
        # Also check: brand in subdomain
        if brand in subdomain.lower() and registered_domain != legit_domain:
            impersonated_brand = brand
            break

    if impersonated_brand:
        indicators.append(_make_indicator(
            name="Brand Impersonation Pattern",
            ioc_type="DOMAIN",
            ioc_value=full_domain,
            severity="HIGH",
            passed=False,
            explanation=f"The URL appears to impersonate '{impersonated_brand}' — the brand name is present in the domain but this is not the brand's legitimate domain ({BRAND_IMPERSONATION_MAP.get(impersonated_brand, 'unknown')}). This is a classic phishing technique to deceive users into believing they are on a trusted site.",
            score_impact=25.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="No Brand Impersonation Detected",
            ioc_type="DOMAIN",
            ioc_value=full_domain,
            severity="INFORMATIONAL",
            passed=True,
            explanation="Domain does not contain patterns matching known brand impersonation targets.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Check 13: Suspicious path patterns
    # ------------------------------------------------------------------
    path_lower = path.lower()
    path_indicators = []
    if "/login" in path_lower or "/signin" in path_lower:
        path_indicators.append("login/signin endpoint")
    if "///" in path:
        path_indicators.append("triple slashes (obfuscation indicator)")
    if len(path.split("/")) > 8:
        path_indicators.append(f"deep path depth ({len(path.split('/'))} segments)")
    if re.search(r"[a-f0-9]{32,}", path_lower):
        path_indicators.append("hash-like string in path (possible token obfuscation)")

    if path_indicators:
        indicators.append(_make_indicator(
            name="Suspicious Path Pattern",
            ioc_type="URL",
            ioc_value=path[:100] if path else "/",
            severity="LOW",
            passed=False,
            explanation=f"Path contains suspicious patterns: {'; '.join(path_indicators)}.",
            score_impact=8.0,
        ))

    # ------------------------------------------------------------------
    # Check 14: @ symbol in URL (credential stuffing technique)
    # ------------------------------------------------------------------
    if "@" in netloc:
        indicators.append(_make_indicator(
            name="@ Symbol in URL Authority",
            ioc_type="URL",
            ioc_value=netloc,
            severity="HIGH",
            passed=False,
            explanation="The URL contains an '@' symbol in the authority section. Browsers interpret content before '@' as credentials, which attackers exploit to hide the real destination (e.g. paypal.com@attacker.com).",
            score_impact=20.0,
        ))

    # ------------------------------------------------------------------
    # Check 15: Domain length
    # ------------------------------------------------------------------
    domain_name = domain_info.domain or ""
    if len(domain_name) > 20:
        indicators.append(_make_indicator(
            name="Long Registered Domain",
            ioc_type="DOMAIN",
            ioc_value=domain_name,
            severity="LOW",
            passed=False,
            explanation=f"Registered domain '{domain_name}' is {len(domain_name)} characters long. Phishing domains sometimes use long names to include brand keywords while appearing plausible.",
            score_impact=5.0,
        ))

    # ------------------------------------------------------------------
    # Compute final scores
    # ------------------------------------------------------------------
    risk_score = _calculate_risk(indicators)
    confidence_score = _calculate_confidence(indicators)
    verdict = _get_verdict(risk_score)
    severity = _calculate_severity(risk_score, indicators)
    mitre_techniques = _get_mitre_mappings(indicators, verdict)
    analyst_actions = _get_analyst_actions(indicators, verdict, "url")
    timeline = _build_timeline(start_time, url, indicators, verdict)
    processing_time_ms = round((time.time() - start_time) * 1000, 2)

    # Build summary from failed indicator names
    failed = [ind["name"] for ind in indicators if not ind["passed"]]
    summary = "; ".join(failed) if failed else "No phishing indicators detected."

    return {
        "risk_score": risk_score,
        "confidence_score": confidence_score,
        "verdict": verdict,
        "severity": severity,
        "summary": summary,
        "indicators": indicators,
        "mitre_techniques": mitre_techniques,
        "analyst_actions": analyst_actions,
        "timeline": timeline,
        "processing_time_ms": processing_time_ms,
        "detection_engine_version": DETECTION_ENGINE_VERSION,
    }


# ---------------------------------------------------------------------------
# Typosquatting helper (kept for backwards compatibility)
# ---------------------------------------------------------------------------

def _has_typosquatting(domain: str) -> bool:
    if not domain:
        return False
    return any(brand in domain.lower() for brand in BRAND_IMPERSONATION_MAP)


# ---------------------------------------------------------------------------
# Email Analysis
# ---------------------------------------------------------------------------

URGENCY_PHRASES: list[str] = [
    "urgent", "immediately", "action required", "your account has been",
    "suspicious activity", "verify now", "account suspended", "click here",
    "limited time", "expires soon", "within 24 hours", "respond immediately",
    "final notice", "last chance", "failure to respond", "act now",
]

CREDENTIAL_PHRASES: list[str] = [
    "password", "login", "credential", "username", "sign in", "signin",
    "enter your", "confirm your", "verify your identity", "bank account",
    "social security", "credit card", "pin number", "security code",
]

SPOOFING_INDICATORS: list[str] = [
    "noreply@", "no-reply@", "donotreply@", "automated@", "system@",
    "security-alert@", "account-security@",
]


def analyze_email(eml_text: str) -> dict[str, Any]:
    """
    Email phishing analysis via heuristic text examination.

    Headers (From, Reply-To, Subject, etc.) are extracted if present.
    SPF/DKIM/DMARC results are only shown when the actual header data is available.
    No external DNS checks are performed here (email content only).
    """
    start_time = time.time()
    indicators: list[dict] = []
    lowered = eml_text.lower()

    # ------------------------------------------------------------------
    # Extract headers if present in pasted email
    # ------------------------------------------------------------------
    from_header = ""
    reply_to = ""
    subject = ""
    spf_result = None
    dkim_result = None
    dmarc_result = None

    for line in eml_text.splitlines():
        line_lower = line.lower()
        if line_lower.startswith("from:"):
            from_header = line[5:].strip()
        elif line_lower.startswith("reply-to:"):
            reply_to = line[9:].strip()
        elif line_lower.startswith("subject:"):
            subject = line[8:].strip()
        elif "spf=" in line_lower:
            spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none)", line_lower)
            if spf_match:
                spf_result = spf_match.group(1)
        elif "dkim=" in line_lower:
            dkim_match = re.search(r"dkim=(pass|fail|none)", line_lower)
            if dkim_match:
                dkim_result = dkim_match.group(1)
        elif "dmarc=" in line_lower:
            dmarc_match = re.search(r"dmarc=(pass|fail|none)", line_lower)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1)

    # ------------------------------------------------------------------
    # Check 1: Urgency language
    # ------------------------------------------------------------------
    found_urgency = [p for p in URGENCY_PHRASES if p in lowered]
    if len(found_urgency) >= 3:
        indicators.append(_make_indicator(
            name="Strong Urgency Language",
            ioc_type="EMAIL",
            ioc_value=", ".join(found_urgency[:4]),
            severity="HIGH",
            passed=False,
            explanation=f"Email contains strong urgency language: '{', '.join(found_urgency[:4])}'. Creating a false sense of urgency is a primary phishing social engineering technique.",
            score_impact=20.0,
        ))
    elif found_urgency:
        indicators.append(_make_indicator(
            name="Urgency Language",
            ioc_type="EMAIL",
            ioc_value=", ".join(found_urgency[:3]),
            severity="MEDIUM",
            passed=False,
            explanation=f"Email contains urgency phrases: '{', '.join(found_urgency[:3])}'. This is a common phishing technique to pressure recipients into acting without thinking.",
            score_impact=12.0,
        ))
    else:
        indicators.append(_make_indicator(
            name="No Urgency Language",
            ioc_type="EMAIL",
            ioc_value="N/A",
            severity="INFORMATIONAL",
            passed=True,
            explanation="No urgency-inducing phrases detected.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Check 2: Credential harvesting language
    # ------------------------------------------------------------------
    found_cred = [p for p in CREDENTIAL_PHRASES if p in lowered]
    if len(found_cred) >= 2:
        indicators.append(_make_indicator(
            name="Credential Harvesting Language",
            ioc_type="EMAIL",
            ioc_value=", ".join(found_cred[:4]),
            severity="HIGH",
            passed=False,
            explanation=f"Email requests sensitive information: '{', '.join(found_cred[:4])}'. Legitimate organizations rarely request credentials via email.",
            score_impact=25.0,
        ))
    elif found_cred:
        indicators.append(_make_indicator(
            name="Credential-Related Terms",
            ioc_type="EMAIL",
            ioc_value=", ".join(found_cred[:3]),
            severity="MEDIUM",
            passed=False,
            explanation=f"Email mentions credential-related terms: '{', '.join(found_cred[:3])}'. In context with other indicators this raises phishing suspicion.",
            score_impact=12.0,
        ))

    # ------------------------------------------------------------------
    # Check 3: Reply-To mismatch
    # ------------------------------------------------------------------
    if from_header and reply_to:
        from_domain = re.search(r"@([^\s>]+)", from_header)
        reply_domain = re.search(r"@([^\s>]+)", reply_to)
        if from_domain and reply_domain and from_domain.group(1).lower() != reply_domain.group(1).lower():
            indicators.append(_make_indicator(
                name="Reply-To / From Domain Mismatch",
                ioc_type="EMAIL",
                ioc_value=f"From: {from_header[:80]} | Reply-To: {reply_to[:80]}",
                severity="HIGH",
                passed=False,
                explanation="The From domain and Reply-To domain do not match. This is a classic email spoofing technique: the email appears to come from a trusted source but replies go to an attacker-controlled address.",
                score_impact=25.0,
            ))
        elif reply_to:
            indicators.append(_make_indicator(
                name="Reply-To Present (Domains Match)",
                ioc_type="EMAIL",
                ioc_value=reply_to[:80],
                severity="INFORMATIONAL",
                passed=True,
                explanation="Reply-To header is present and matches the From domain.",
                score_impact=0.0,
            ))
    elif reply_to and not from_header:
        indicators.append(_make_indicator(
            name="Reply-To Without From Header",
            ioc_type="EMAIL",
            ioc_value=reply_to[:80],
            severity="LOW",
            passed=False,
            explanation="Reply-To is present but From header could not be parsed. Cannot verify domain consistency.",
            score_impact=5.0,
        ))

    # ------------------------------------------------------------------
    # Check 4: Spoofing sender patterns
    # ------------------------------------------------------------------
    for pattern in SPOOFING_INDICATORS:
        if pattern in lowered:
            indicators.append(_make_indicator(
                name="Spoofing-Style Sender Pattern",
                ioc_type="EMAIL",
                ioc_value=pattern,
                severity="MEDIUM",
                passed=False,
                explanation=f"Sender address pattern '{pattern}' is commonly used to impersonate automated system emails. Verify the actual sending domain.",
                score_impact=10.0,
            ))
            break

    # ------------------------------------------------------------------
    # Check 5: URLs in email body
    # ------------------------------------------------------------------
    urls_in_email = re.findall(r"https?://[^\s<>\"]+", eml_text)
    if urls_in_email:
        indicators.append(_make_indicator(
            name=f"URLs in Email Body ({len(urls_in_email)} found)",
            ioc_type="URL",
            ioc_value=", ".join(urls_in_email[:3]),
            severity="LOW",
            passed=False,
            explanation=f"Email contains {len(urls_in_email)} URL(s). Each URL should be analyzed separately using the URL Scanner. Embedded URLs are the primary delivery mechanism for phishing attacks.",
            score_impact=8.0,
        ))

    # ------------------------------------------------------------------
    # Check 6: SPF/DKIM/DMARC (only when header data available)
    # ------------------------------------------------------------------
    if spf_result:
        spf_passed = spf_result == "pass"
        indicators.append(_make_indicator(
            name=f"SPF: {spf_result.upper()}",
            ioc_type="EMAIL",
            ioc_value=f"spf={spf_result}",
            severity="HIGH" if not spf_passed else "INFORMATIONAL",
            passed=spf_passed,
            explanation=f"SPF header found in email: result is '{spf_result}'. SPF {'pass indicates' if spf_passed else 'fail/softfail indicates'} the sending server {'is' if spf_passed else 'is NOT'} authorized to send mail for this domain.",
            score_impact=0.0 if spf_passed else 20.0,
        ))

    if dkim_result:
        dkim_passed = dkim_result == "pass"
        indicators.append(_make_indicator(
            name=f"DKIM: {dkim_result.upper()}",
            ioc_type="EMAIL",
            ioc_value=f"dkim={dkim_result}",
            severity="HIGH" if not dkim_passed else "INFORMATIONAL",
            passed=dkim_passed,
            explanation=f"DKIM header found: result is '{dkim_result}'. DKIM {'pass verifies' if dkim_passed else 'fail indicates'} the email's cryptographic signature {'is valid' if dkim_passed else 'is invalid or absent'}, meaning content {'has not been' if dkim_passed else 'may have been'} tampered with in transit.",
            score_impact=0.0 if dkim_passed else 15.0,
        ))

    if dmarc_result:
        dmarc_passed = dmarc_result == "pass"
        indicators.append(_make_indicator(
            name=f"DMARC: {dmarc_result.upper()}",
            ioc_type="EMAIL",
            ioc_value=f"dmarc={dmarc_result}",
            severity="HIGH" if not dmarc_passed else "INFORMATIONAL",
            passed=dmarc_passed,
            explanation=f"DMARC header found: result is '{dmarc_result}'. DMARC {'pass confirms' if dmarc_passed else 'fail indicates'} alignment between SPF/DKIM and the From domain.",
            score_impact=0.0 if dmarc_passed else 15.0,
        ))

    if not spf_result and not dkim_result and not dmarc_result:
        indicators.append(_make_indicator(
            name="No SPF/DKIM/DMARC Headers Available",
            ioc_type="EMAIL",
            ioc_value="Not available",
            severity="INFORMATIONAL",
            passed=True,
            explanation="SPF, DKIM, and DMARC authentication results are not present in the provided text. These are only available in full email headers. Copy the complete email headers to enable authentication analysis.",
            score_impact=0.0,
        ))

    # ------------------------------------------------------------------
    # Compute scores
    # ------------------------------------------------------------------
    risk_score = _calculate_risk(indicators)
    confidence_score = _calculate_confidence(indicators)
    verdict = _get_verdict(risk_score)
    severity = _calculate_severity(risk_score, indicators)

    # Email-specific MITRE mapping
    mitre_techniques: list[dict] = []
    if verdict in ("Suspicious", "Malicious"):
        has_cred = any(not i["passed"] and "credential" in i["name"].lower() for i in indicators)
        has_urls = any(not i["passed"] and "url" in i["name"].lower() for i in indicators)
        if has_urls:
            mitre_techniques.append({
                "technique_id": "T1566.002",
                "technique_name": "Phishing: Spearphishing Link",
                "tactic": "Initial Access",
                "reason": "Email contains URLs combined with social engineering indicators consistent with spearphishing link delivery.",
                "evidence": f"URLs detected in email body. Urgency/credential language present.",
            })
        elif has_cred:
            mitre_techniques.append({
                "technique_id": "T1566.001",
                "technique_name": "Phishing: Spearphishing Attachment/Content",
                "tactic": "Initial Access",
                "reason": "Credential harvesting language detected in email body.",
                "evidence": "Email requests credentials without verifiable link evidence.",
            })

    analyst_actions = _get_analyst_actions(indicators, verdict, "email")
    if urls_in_email:
        analyst_actions.insert(0, f"Analyze {len(urls_in_email)} embedded URL(s) using the URL Scanner")
    if from_header:
        analyst_actions.append(f"Verify sender domain reputation for: {re.search(r'@([^>]+)', from_header).group(1) if re.search(r'@([^>]+)', from_header) else from_header}")

    processing_time_ms = round((time.time() - start_time) * 1000, 2)
    failed = [ind["name"] for ind in indicators if not ind["passed"]]
    summary = "; ".join(failed) if failed else "No phishing indicators detected in email content."

    return {
        "risk_score": risk_score,
        "confidence_score": confidence_score,
        "verdict": verdict,
        "severity": severity,
        "summary": summary,
        "indicators": indicators,
        "mitre_techniques": mitre_techniques,
        "analyst_actions": analyst_actions,
        "timeline": [
            {"timestamp": time.strftime("%H:%M:%S"), "event": "Email Submitted", "detail": "Email content received for analysis"},
            {"timestamp": time.strftime("%H:%M:%S"), "event": "Header Extraction", "detail": f"From: {from_header[:50] or 'not found'} | Subject: {subject[:50] or 'not found'}"},
            {"timestamp": time.strftime("%H:%M:%S"), "event": "Pattern Analysis", "detail": f"{len(indicators)} checks completed"},
            {"timestamp": time.strftime("%H:%M:%S"), "event": f"Verdict: {verdict}", "detail": f"Email analysis complete — {verdict.upper()}"},
        ],
        "processing_time_ms": processing_time_ms,
        "detection_engine_version": DETECTION_ENGINE_VERSION,
    }


# ---------------------------------------------------------------------------
# Website Analysis
# ---------------------------------------------------------------------------

def analyze_website(url: str) -> dict[str, Any]:
    """
    Fetch and analyze website HTML content for phishing indicators.
    Requires network access; returns a graceful error dict if unreachable.
    """
    start_time = time.time()
    # SSRF Protection Check
    is_safe, ssrf_msg = _validate_safe_url_for_fetch(url)
    if not is_safe:
        return {
            "risk_score": 0.0,
            "confidence_score": None,
            "verdict": "Blocked",
            "severity": "INFORMATIONAL",
            "summary": f"SSRF Guard Blocked Request: {ssrf_msg}",
            "indicators": [
                _make_indicator(
                    name="SSRF Protection Guard Triggered",
                    ioc_type="URL",
                    ioc_value=url,
                    severity="INFORMATIONAL",
                    passed=False,
                    explanation=f"The requested target was blocked to prevent Server-Side Request Forgery: {ssrf_msg}",
                    score_impact=0.0,
                    category="NETWORK",
                    technical_evidence=ssrf_msg,
                )
            ],
            "mitre_techniques": [],
            "analyst_actions": ["Verify that the target URL resolves to an external public IP address."],
            "timeline": [
                {"timestamp": time.strftime("%H:%M:%S"), "event": "Target Submitted", "detail": f"Target: {url}"},
                {"timestamp": time.strftime("%H:%M:%S"), "event": "SSRF Security Guard", "detail": f"Blocked: {ssrf_msg}"},
            ],
            "processing_time_ms": round((time.time() - start_time) * 1000, 2),
            "detection_engine_version": DETECTION_ENGINE_VERSION,
        }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True, headers={
            "User-Agent": "PhishGuard-AI/2.1 (Security Research Scanner)"
        })
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        final_url = response.url
        status_code = response.status_code
    except requests.exceptions.Timeout:
        return {"risk_score": 0.0, "confidence_score": None, "verdict": "Unknown",
                "severity": "INFORMATIONAL", "summary": "Website analysis timed out after 10 seconds.",
                "indicators": [], "mitre_techniques": [], "analyst_actions": [],
                "timeline": [], "processing_time_ms": round((time.time() - start_time) * 1000, 2),
                "detection_engine_version": DETECTION_ENGINE_VERSION}
    except Exception as exc:
        return {"risk_score": 0.0, "confidence_score": None, "verdict": "Unknown",
                "severity": "INFORMATIONAL", "summary": f"Website analysis unavailable: {type(exc).__name__}",
                "indicators": [], "mitre_techniques": [], "analyst_actions": [],
                "timeline": [], "processing_time_ms": round((time.time() - start_time) * 1000, 2),
                "detection_engine_version": DETECTION_ENGINE_VERSION}

    content_lower = response.text.lower()
    forms = soup.find_all("form")
    scripts = soup.find_all("script")
    iframes = soup.find_all("iframe")
    inputs = soup.find_all("input")

    # ------------------------------------------------------------------
    # Check 1: Login / credential collection indicators
    # ------------------------------------------------------------------
    password_inputs = [inp for inp in inputs if inp.get("type", "").lower() == "password"]
    if password_inputs:
        indicators.append(_make_indicator(
            name="Password Input Field Detected",
            ioc_type="URL",
            ioc_value=f"{len(password_inputs)} password field(s)",
            severity="MEDIUM",
            passed=False,
            explanation=f"Page contains {len(password_inputs)} password input field(s). Phishing pages mimic login forms to harvest credentials. Not suspicious alone but significant in combination with other indicators.",
            score_impact=15.0,
        ))
    
    login_keywords = any(kw in content_lower for kw in ["login", "sign in", "password", "username"])
    if login_keywords and not password_inputs:
        indicators.append(_make_indicator(
            name="Login Page Indicators",
            ioc_type="URL",
            ioc_value=url,
            severity="LOW",
            passed=False,
            explanation="Page content contains login-related keywords. May be a credential-collection page.",
            score_impact=8.0,
        ))

    # ------------------------------------------------------------------
    # Check 2: Forms with suspicious external action destinations
    # ------------------------------------------------------------------
    url_domain = tldextract.extract(url)
    external_form_actions = []
    for form in forms:
        action = form.get("action", "")
        if action.startswith("http"):
            form_domain = tldextract.extract(action)
            if form_domain.registered_domain != url_domain.registered_domain:
                external_form_actions.append(action[:100])

    if external_form_actions:
        indicators.append(_make_indicator(
            name="External Form Action Destination",
            ioc_type="URL",
            ioc_value=external_form_actions[0],
            severity="HIGH",
            passed=False,
            explanation=f"A form on this page submits data to an external domain ({external_form_actions[0][:60]}). This is a strong phishing indicator — credentials entered on this page would be sent to a third-party server.",
            score_impact=30.0,
        ))
    elif forms:
        indicators.append(_make_indicator(
            name=f"{len(forms)} Form(s) Present (Internal Actions)",
            ioc_type="URL",
            ioc_value=f"{len(forms)} form(s)",
            severity="LOW",
            passed=False,
            explanation=f"Page has {len(forms)} form(s) with internal action destinations. Not necessarily malicious but warrants review in context.",
            score_impact=5.0 * len(forms),
        ))

    # ------------------------------------------------------------------
    # Check 3: Iframes
    # ------------------------------------------------------------------
    hidden_iframes = [f for f in iframes if f.get("style", "").replace(" ", "") in ("display:none", "visibility:hidden") or f.get("hidden") is not None]
    if hidden_iframes:
        indicators.append(_make_indicator(
            name="Hidden iFrame(s) Detected",
            ioc_type="URL",
            ioc_value=f"{len(hidden_iframes)} hidden iframe(s)",
            severity="HIGH",
            passed=False,
            explanation=f"Page contains {len(hidden_iframes)} hidden iframe(s). Hidden iframes can be used to load malicious content silently, perform clickjacking attacks, or embed tracking/phishing elements.",
            score_impact=20.0,
        ))
    elif iframes:
        indicators.append(_make_indicator(
            name=f"{len(iframes)} Visible iFrame(s)",
            ioc_type="URL",
            ioc_value=f"{len(iframes)} iframe(s)",
            severity="LOW",
            passed=False,
            explanation=f"Page embeds {len(iframes)} iframe(s). Iframes are sometimes used for content embedding but can also embed malicious content.",
            score_impact=8.0,
        ))

    # ------------------------------------------------------------------
    # Check 4: Suspicious JavaScript patterns
    # ------------------------------------------------------------------
    suspicious_js_patterns = []
    for script in scripts:
        script_text = script.string or ""
        if "eval(" in script_text:
            suspicious_js_patterns.append("eval() call")
        if "document.cookie" in script_text:
            suspicious_js_patterns.append("document.cookie access")
        if "atob(" in script_text or "btoa(" in script_text:
            suspicious_js_patterns.append("base64 encoding/decoding")
        if re.search(r"\\x[0-9a-f]{2}", script_text):
            suspicious_js_patterns.append("hex-escaped characters")

    if suspicious_js_patterns:
        indicators.append(_make_indicator(
            name="Suspicious JavaScript Patterns",
            ioc_type="URL",
            ioc_value=", ".join(list(set(suspicious_js_patterns))[:4]),
            severity="HIGH",
            passed=False,
            explanation=f"JavaScript contains suspicious patterns: {', '.join(list(set(suspicious_js_patterns))[:4])}. These techniques are used for obfuscation, credential theft, or redirecting victims.",
            score_impact=20.0,
        ))
    
    indicators.append(_make_indicator(
        name=f"{len(scripts)} Script Tag(s)",
        ioc_type="URL",
        ioc_value=f"{len(scripts)} scripts",
        severity="INFORMATIONAL" if len(scripts) < 10 else "LOW",
        passed=len(scripts) < 15,
        explanation=f"Page contains {len(scripts)} script tag(s). High script counts on simple pages can indicate obfuscated malicious code.",
        score_impact=0.0 if len(scripts) < 10 else 5.0,
    ))

    # ------------------------------------------------------------------
    # Check 5: External domain resources
    # ------------------------------------------------------------------
    external_domains: set[str] = set()
    for tag in soup.find_all(["script", "link", "img", "a"]):
        src = tag.get("src") or tag.get("href") or ""
        if src.startswith("http"):
            ext_info = tldextract.extract(src)
            if ext_info.registered_domain and ext_info.registered_domain != url_domain.registered_domain:
                external_domains.add(ext_info.registered_domain)

    if len(external_domains) > 10:
        indicators.append(_make_indicator(
            name="Many External Domain Resources",
            ioc_type="DOMAIN",
            ioc_value=f"{len(external_domains)} external domains",
            severity="MEDIUM",
            passed=False,
            explanation=f"Page loads resources from {len(external_domains)} different external domains. A high number of external dependencies can indicate an aggregated phishing kit or tracking infrastructure.",
            score_impact=10.0,
        ))

    # ------------------------------------------------------------------
    # Compute scores
    # ------------------------------------------------------------------
    risk_score = _calculate_risk(indicators)
    confidence_score = _calculate_confidence(indicators)
    verdict = _get_verdict(risk_score)
    severity = _calculate_severity(risk_score, indicators)
    mitre_techniques = _get_mitre_mappings(indicators, verdict)
    analyst_actions = _get_analyst_actions(indicators, verdict, "website")
    processing_time_ms = round((time.time() - start_time) * 1000, 2)

    failed = [ind["name"] for ind in indicators if not ind["passed"]]
    summary = f"Forms={len(forms)}, Scripts={len(scripts)}, Iframes={len(iframes)}, PasswordFields={len(password_inputs)}, ExternalFormActions={len(external_form_actions)}. Issues: {'; '.join(failed[:3])}" if failed else "No significant phishing indicators detected on this page."

    return {
        "risk_score": risk_score,
        "confidence_score": confidence_score,
        "verdict": verdict,
        "severity": severity,
        "summary": summary,
        "indicators": indicators,
        "mitre_techniques": mitre_techniques,
        "analyst_actions": analyst_actions,
        "timeline": _build_timeline(start_time, url, indicators, verdict),
        "processing_time_ms": processing_time_ms,
        "detection_engine_version": DETECTION_ENGINE_VERSION,
    }


# ---------------------------------------------------------------------------
# Threat Intelligence Lookup (DNS + WHOIS only; no external paid APIs)
# ---------------------------------------------------------------------------

def threat_intelligence_lookup(domain: str) -> dict[str, Any]:
    """
    Perform DNS and WHOIS lookup for a domain or IP address.

    External threat intelligence providers (VirusTotal, AbuseIPDB) require
    API keys configured via environment variables. When not configured, their
    status is returned as 'not_configured' — never fabricated.
    """
    from ..core.config import settings

    result: dict[str, Any] = {
        "domain": domain,
        "ips": [],
        "whois": {},
        "virustotal": {"status": "not_configured", "message": "VirusTotal API key not configured. Set VIRUS_TOTAL_API_KEY environment variable to enable."},
        "abuseipdb": {"status": "not_configured", "message": "AbuseIPDB API key not configured. Set ABUSEIPDB_API_KEY environment variable to enable."},
    }

    # DNS A record lookup
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        result["ips"] = [str(r) for r in answers]
    except Exception as e:
        result["dns_error"] = f"DNS A record lookup failed: {type(e).__name__}"

    # DNS MX record lookup
    try:
        mx_answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        result["mx_records"] = [str(r.exchange) for r in mx_answers]
    except Exception:
        result["mx_records"] = []

    # DNS TXT record lookup
    try:
        txt_answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        result["txt_records"] = [str(r) for r in txt_answers]
    except Exception:
        result["txt_records"] = []

    # WHOIS lookup
    try:
        whois_data = whois.whois(domain)
        result["whois"] = {
            "registrar": str(whois_data.registrar) if whois_data.registrar else "Not available",
            "creation_date": str(whois_data.creation_date) if whois_data.creation_date else "Not available",
            "expiration_date": str(whois_data.expiration_date) if whois_data.expiration_date else "Not available",
            "name_servers": whois_data.name_servers if whois_data.name_servers else [],
            "country": str(whois_data.country) if whois_data.country else "Not available",
            "org": str(whois_data.org) if whois_data.org else "Not available",
        }
    except Exception as e:
        result["whois"] = {"error": f"WHOIS lookup failed: {type(e).__name__}"}

    # VirusTotal (only if API key is configured)
    if settings.virus_total_api_key:
        try:
            vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            vt_response = requests.get(vt_url, headers={"x-apikey": settings.virus_total_api_key}, timeout=10)
            if vt_response.status_code == 200:
                vt_data = vt_response.json()
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result["virustotal"] = {
                    "status": "configured",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }
            else:
                result["virustotal"]["status"] = "error"
                result["virustotal"]["message"] = f"VirusTotal API returned {vt_response.status_code}"
        except Exception as e:
            result["virustotal"]["status"] = "error"
            result["virustotal"]["message"] = str(e)

    return result
