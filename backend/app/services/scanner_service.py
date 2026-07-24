import re
from urllib.parse import urlparse
import requests
import tldextract
from bs4 import BeautifulSoup
import dns.resolver
import whois

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "alert", "bank", "paypal", "amazon", "support"]
COMMON_TLDS = {"com", "net", "org", "io", "co", "uk"}


def analyze_url(url: str) -> dict:
    parsed = urlparse(url)
    domain_info = tldextract.extract(url)
    score = 0.0
    reasons = []

    if not parsed.scheme or not parsed.netloc:
        score += 50
        reasons.append("Malformed URL")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.netloc):
        score += 30
        reasons.append("Uses IP address")

    if len(url) > 70:
        score += 15
        reasons.append("URL length is unusually long")

    if parsed.scheme.lower() != "https":
        score += 10
        reasons.append("No HTTPS")

    lowered = url.lower()
    if any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS):
        score += 15
        reasons.append("Contains suspicious keywords")

    if domain_info.subdomain:
        score += 10
        reasons.append("Contains subdomains")

    if domain_info.domain and domain_info.suffix and domain_info.suffix not in COMMON_TLDS:
        score += 5
        reasons.append("Uncommon TLD")

    if _has_typosquatting(domain_info.domain):
        score += 20
        reasons.append("Possible typosquatting")

    if score >= 70:
        verdict = "Malicious"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "risk_score": round(min(score, 100), 2),
        "verdict": verdict,
        "summary": "; ".join(reasons) if reasons else "No obvious phishing indicators detected.",
    }


def _has_typosquatting(domain: str) -> bool:
    if not domain:
        return False
    return any(fake in domain for fake in ["paypal", "microsoft", "google", "apple", "amazon"])


def analyze_email(eml_text: str) -> dict:
    lowered = eml_text.lower()
    indicators = []
    score = 0.0

    if "urgent" in lowered or "immediately" in lowered:
        score += 20
        indicators.append("Urgent language")
    if "password" in lowered or "login" in lowered or "credential" in lowered:
        score += 25
        indicators.append("Credential harvesting language")
    if "from:" in lowered and "@" in lowered:
        score += 10
        indicators.append("Potential spoofing indicators")

    verdict = "Safe"
    if score >= 45:
        verdict = "Suspicious"
    if score >= 70:
        verdict = "Malicious"

    return {
        "risk_score": round(min(score, 100), 2),
        "verdict": verdict,
        "summary": "; ".join(indicators) if indicators else "No obvious email phishing indicators detected.",
    }


def analyze_website(url: str) -> dict:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        scripts = soup.find_all("script")
        iframes = soup.find_all("iframe")
        login_page = any(keyword in response.text.lower() for keyword in ["login", "password", "signin"])
        score = 20 if login_page else 0
        score += 10 * len(forms)
        score += 5 * len(scripts)
        score += 15 * len(iframes)
        verdict = "Malicious" if score >= 60 else "Suspicious" if score >= 30 else "Safe"
        return {
            "risk_score": round(min(score, 100), 2),
            "verdict": verdict,
            "summary": f"Forms={len(forms)}, Scripts={len(scripts)}, Iframes={len(iframes)}, LoginPage={login_page}",
        }
    except Exception as exc:
        return {"risk_score": 0.0, "verdict": "Safe", "summary": f"Website analysis unavailable: {exc}"}


def threat_intelligence_lookup(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [str(item) for item in answers]
    except Exception:
        ips = []

    try:
        whois_data = whois.whois(domain)
    except Exception:
        whois_data = {}

    return {
        "domain": domain,
        "ips": ips,
        "whois": whois_data,
    }
