"""
=============================================================================
Module: backend.services.sender_analyzer
=============================================================================
Defensive Security Service: Sender Pattern & Domain Spoofing Analysis.

PURPOSE:
Examines the 'From' header, sender display name, and domain structure for
hallmarks of social engineering, spoofing, lookalike domains (typosquatting),
and brand impersonation.

IMPORTANT CYBERSECURITY PRINCIPLE:
Do NOT automatically label any unfamiliar domain as malicious. Legitimate
small businesses, regional universities, and vendors use varied domain names.
The analyzer flags anomalies as observable RISK SIGNALS for analyst triage.
=============================================================================
"""

import re
from typing import Dict, List, Any
from backend.utils.preprocessor import parse_sender_string


# High-value targeted brands commonly targeted by impersonation attacks
COMMONLY_SPOOFED_BRANDS = [
    "microsoft", "paypal", "google", "apple", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "dhl", "fedex", "ups",
    "dropbox", "linkedin", "meta", "facebook", "instagram"
]

# Free or public webmail providers (suspicious when claiming corporate/executive identity)
FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "zoho.com", "mail.com", "gmx.com"
}

# Suspicious TLDs or synthetic test domains frequently seen in lab phishing
SUSPICIOUS_DOMAIN_PATTERNS = [
    r"-security", r"-verify", r"-login", r"-account", r"-auth",
    r"-portal", r"-support", r"-update", r"-helpdesk", r"-wire",
    r"-disbursement", r"-confirm"
]


def analyze_sender(sender_raw: str, email_body: str = "") -> Dict[str, Any]:
    """
    Analyzes sender information for deceptive patterns, display name mismatch,
    excessive subdomains, brand lookalikes, and formatting anomalies.

    Args:
        sender_raw: Full From string (e.g. 'Security Team <alert@account-check.invalid.test>')
        email_body: Optional email body to check if sender matches internal claims

    Returns:
        Dictionary containing sender_risk_score (0-100), domain, findings, and metadata.
    """
    display_name, email_addr, domain = parse_sender_string(sender_raw)
    
    findings: List[Dict[str, str]] = []
    risk_score = 0
    
    if not sender_raw or not sender_raw.strip():
        return {
            "sender_raw": "",
            "display_name": "",
            "email_address": "",
            "domain": "",
            "sender_risk_score": 30,
            "findings": [{
                "severity": "MEDIUM",
                "indicator": "Missing Sender Header",
                "explanation": "No sender address was provided. Anonymous senders prevent sender validation (SPF/DKIM)."
            }]
        }

    # 1. Email Format Validation
    if not email_addr or "@" not in email_addr:
        risk_score += 40
        findings.append({
            "severity": "HIGH",
            "indicator": "Malformed Sender Address",
            "explanation": f"The sender '{sender_raw}' does not conform to standard RFC 5322 email syntax."
        })
        return {
            "sender_raw": sender_raw,
            "display_name": display_name,
            "email_address": email_addr,
            "domain": domain,
            "sender_risk_score": min(risk_score, 100),
            "findings": findings
        }

    domain_lower = domain.lower()
    display_lower = display_name.lower()
    
    # 2. Check for Display Name vs Domain Mismatch (Brand Impersonation)
    for brand in COMMONLY_SPOOFED_BRANDS:
        # If the display name or body claims to be a brand, but the domain is not that brand
        if brand in display_lower and brand not in domain_lower:
            risk_score += 35
            findings.append({
                "severity": "HIGH",
                "indicator": f"Display Name / Brand Mismatch ({brand.capitalize()})",
                "explanation": f"Display name references '{brand.capitalize()}' but the sending domain is '{domain}', indicating potential identity impersonation."
            })
            break

    # 3. Check for Executive / Corporate Impersonation using Free Webmail
    corporate_keywords = ["ceo", "cfo", "director", "hr", "payroll", "accounting", "administrator", "it support"]
    if any(kw in display_lower for kw in corporate_keywords) and domain_lower in FREEMAIL_DOMAINS:
        risk_score += 30
        findings.append({
            "severity": "HIGH",
            "indicator": "Corporate Role Using Free Webmail",
            "explanation": f"Display name claims an institutional role ('{display_name}') while using a consumer webmail provider ({domain})."
        })

    # 4. Excessive Subdomains Check
    # Normal domains have 2 or 3 labels (e.g. mail.example.com -> 3)
    domain_labels = domain_lower.split(".")
    if len(domain_labels) >= 4:
        risk_score += 20
        findings.append({
            "severity": "MEDIUM",
            "indicator": "Excessive Domain Labels / Deep Subdomains",
            "explanation": f"Domain '{domain}' contains {len(domain_labels)} labels. Deep subdomains are often created on shared hosting to simulate trusted URLs."
        })

    # 5. Suspicious Hyphenated Security / Verification Keywords in Domain
    for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
        if re.search(pattern, domain_lower):
            risk_score += 25
            findings.append({
                "severity": "HIGH",
                "indicator": "Deceptive Security Keywords in Domain",
                "explanation": f"Domain '{domain}' includes deceptive trust-inducing keyword pattern '{pattern}', frequently used in phishing infrastructure."
            })
            break

    # 6. Check Domain Length Anomaly
    if len(domain_lower) > 35:
        risk_score += 15
        findings.append({
            "severity": "MEDIUM",
            "indicator": "Unusually Long Sender Domain",
            "explanation": f"Domain length ({len(domain_lower)} characters) exceeds typical corporate naming conventions."
        })

    # 7. Check for Synthetic / Reserved Test Domains (Contextual Awareness)
    if domain_lower.endswith(".invalid") or domain_lower.endswith(".test") or "invalid.test" in domain_lower:
        # In a cybersecurity lab this represents simulated phishing infrastructure
        risk_score += 15
        findings.append({
            "severity": "LOW",
            "indicator": "Reserved Synthetic / Test TLD",
            "explanation": f"Sender domain uses '.invalid' or '.test' RFC 2606 reserved lab domain representing controlled testing environments."
        })

    # If no findings triggered, mark as baseline clean
    if not findings:
        findings.append({
            "severity": "INFO",
            "indicator": "Standard Sender Format",
            "explanation": f"Domain '{domain}' adheres to conventional structure without obvious display spoofing or deceptive keyword patterns."
        })

    sender_risk_score = min(max(risk_score, 0), 100)
    
    return {
        "sender_raw": sender_raw,
        "display_name": display_name,
        "email_address": email_addr,
        "domain": domain,
        "sender_risk_score": sender_risk_score,
        "findings": findings
    }
