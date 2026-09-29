"""
=============================================================================
Module: backend.services.url_analyzer
=============================================================================
Defensive Security Service: Static URL & Hyperlink Risk Analysis.

CRITICAL DEFENSIVE SECURITY PRINCIPLES:
1. NEVER automatically visit or fetch suspicious URLs!
   Automated network requests could trigger exploit kits, alert the threat
   actor that the victim IP is active (canary tokens), or download malware.
2. HTTPS DOES NOT EQUAL TRUSTWORTHY!
   Modern threat actors routinely provision free SSL/TLS certificates (e.g.
   Let's Encrypt) to display the padlock icon and generate false trust.
3. This module performs 100% OFFLINE, STATIC, LEXICAL and STRUCTURAL parsing.
=============================================================================
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Any


# Regular expressions for IPv4 addresses
IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?$'
)

# Known URL shorteners and redirector patterns
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorte.st"
}

# Suspicious keywords in URL path or parameters targeting authentication
SUSPICIOUS_URL_KEYWORDS = [
    "verify", "login", "signin", "auth", "password", "credential",
    "checkpoint", "secure", "update", "banking", "billing", "confirm",
    "webscr", "ebayisapi", "security", "token", "settle"
]


def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Performs safe static inspection of a URL string without network requests.

    Args:
        raw_url: String representation of URL

    Returns:
        Structured breakdown with risk score (0-100), components, and findings.
    """
    if not raw_url or not raw_url.strip():
        return {
            "url": "",
            "is_valid": False,
            "url_risk_score": 0,
            "findings": []
        }

    raw_url = raw_url.strip()
    
    # Prepend scheme if missing for accurate urllib parsing
    target_url = raw_url
    if not (target_url.startswith("http://") or target_url.startswith("https://") or target_url.startswith("ftp://")):
        target_url = "http://" + target_url

    parsed = urlparse(target_url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    
    findings: List[Dict[str, str]] = []
    risk_score = 0

    # 1. Scheme Check (HTTP vs HTTPS)
    if scheme == "http":
        risk_score += 20
        findings.append({
            "severity": "MEDIUM",
            "indicator": "Unencrypted HTTP Scheme",
            "explanation": "URL uses plaintext HTTP. Legitimate organizations transmit login portals over HTTPS."
        })
    elif scheme == "https":
        # Defensive educational note: HTTPS is good for encryption, but not proof of legitimacy
        findings.append({
            "severity": "INFO",
            "indicator": "HTTPS Encrypted Protocol",
            "explanation": "Connection is encrypted via TLS. NOTE: Modern phishing sites frequently use valid HTTPS certificates to deceive victims."
        })
    else:
        risk_score += 15
        findings.append({
            "severity": "MEDIUM",
            "indicator": f"Unusual Scheme ({scheme})",
            "explanation": f"Non-standard web scheme '{scheme}' observed in link."
        })

    # Hostname extraction (stripping port if present)
    hostname = netloc.split(":")[0] if ":" in netloc else netloc

    # 2. Raw IP Address Hostname Detection
    is_raw_ip = bool(IPV4_REGEX.match(hostname))
    if is_raw_ip:
        risk_score += 40
        findings.append({
            "severity": "CRITICAL",
            "indicator": "Raw IP Address as Hostname",
            "explanation": f"URL links directly to numerical IP address '{hostname}' rather than a registered domain name. Legitimate public services use domain names; raw IPs are heavily associated with bulletproof hosting and evasive phishing infrastructure."
        })

    # 3. URL Shortener Detection
    is_shortener = hostname in KNOWN_SHORTENERS or any(short in hostname for short in KNOWN_SHORTENERS)
    if is_shortener:
        risk_score += 25
        findings.append({
            "severity": "HIGH",
            "indicator": "URL Shortener Service Detected",
            "explanation": f"Domain '{hostname}' obfuscates the final destination. Attackers use shorteners to bypass email gateway domain reputation filters."
        })

    # 4. Excessive Subdomains Check
    labels = hostname.split(".")
    # If not a raw IP, count subdomain depth (5 or more labels is suspicious deep nesting)
    if not is_raw_ip and len(labels) >= 5:
        risk_score += 20
        findings.append({
            "severity": "MEDIUM",
            "indicator": "Excessive Subdomains",
            "explanation": f"Hostname '{hostname}' has {len(labels)} domain labels. Deep subdomains can be used to visually camouflage deceptive terms in URLs."
        })

    # 5. Suspicious Authentication Keywords in Path/Query
    found_keywords = []
    combined_path_query = (path + " " + query).lower()
    for kw in SUSPICIOUS_URL_KEYWORDS:
        if kw in combined_path_query:
            found_keywords.append(kw)
            
    if found_keywords:
        risk_score += 20
        findings.append({
            "severity": "HIGH",
            "indicator": "Credential Solicitation Terms in URL Path",
            "explanation": f"URL path/query includes authentication-targeted keywords: {', '.join(found_keywords[:4])}."
        })

    # 6. Basic Auth Deception Trick (Presence of '@' in URL authority)
    if "@" in netloc or "@" in target_url.split("?")[0]:
        risk_score += 35
        findings.append({
            "severity": "CRITICAL",
            "indicator": "Deceptive '@' Character in URL",
            "explanation": "The '@' symbol in URLs can trick browsers into treating preceding text as credentials, routing to the domain after the '@'."
        })

    # 7. Unusually Long URL (Obfuscation / Buffer Trickery)
    if len(raw_url) > 120:
        risk_score += 15
        findings.append({
            "severity": "LOW",
            "indicator": "Excessive URL Length",
            "explanation": f"URL length ({len(raw_url)} chars) is unusually long, potentially hiding parameters or avoiding display in email clients."
        })

    # If clean baseline
    if not [f for f in findings if f["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]]:
        findings.append({
            "severity": "INFO",
            "indicator": "Standard Static Characteristics",
            "explanation": "Domain and path do not exhibit raw IP hosting, shortening, or obvious credential trap markers."
        })

    final_url_score = min(max(risk_score, 0), 100)

    return {
        "url": raw_url,
        "is_valid": True,
        "scheme": scheme,
        "hostname": hostname,
        "path": path,
        "query": query,
        "url_length": len(raw_url),
        "hostname_length": len(hostname),
        "is_raw_ip": is_raw_ip,
        "is_shortener": is_shortener,
        "subdomain_count": len(labels) if not is_raw_ip else 0,
        "url_risk_score": final_url_score,
        "findings": findings
    }


def analyze_multiple_urls(urls: List[str]) -> List[Dict[str, Any]]:
    """
    Batch static analyzer for list of URLs extracted from an email.
    """
    return [analyze_url(u) for u in urls if u]
