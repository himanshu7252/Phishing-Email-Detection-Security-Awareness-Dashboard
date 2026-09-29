"""
=============================================================================
Module: backend.services.feature_extractor
=============================================================================
Defensive Security Service: Email Feature Engineering.

PURPOSE:
Converts unstructured email artifacts (headers, subject, body, hyperlinks,
and attachments) into a normalized, structured feature vector for both:
1. Rule-based cybersecurity scoring
2. Machine learning classifiers (scikit-learn)

FEATURE EXPLANATION:
- urgent_keyword_count: Frequency of artificial deadline / time pressure terms.
- credential_keyword_count: Frequency of direct login/password solicitation terms.
- financial_keyword_count: Frequency of overdue invoices, wire requests, or billing terms.
- threat_keyword_count: Frequency of account lock, police, or legal threat phrasing.
- url_count: Total count of embedded web links.
- suspicious_url_count: Number of links exhibiting high-risk static markers.
- has_ip_url: Binary flag indicating presence of numeric IP hostnames (e.g. 198.51.100.10).
- has_shortened_url_pattern: Binary flag indicating use of URL obscuring services (bit.ly, etc.).
- sender_domain_length: Character length of the sender's domain.
- subdomain_count: Number of labels in sender domain (depth indicator).
- suspicious_attachment: Binary flag for weaponized scripts, executables, or double extensions.
- generic_greeting: Binary flag indicating impersonal salutations (e.g. 'Dear Customer').
- contains_password_request: Binary flag indicating explicit password solicitations.
- contains_personal_info_request: Binary flag indicating PII (SSN, credit card, bank) requests.
- exclamation_count: Total count of exclamation marks indicating heightened emotional pressure.
- uppercase_ratio: Proportion of uppercase characters in body text.
- body_length: Total character count of email body.
- subject_length: Total character count of subject line.
=============================================================================
"""

from typing import Dict, Any, List
from backend.utils.preprocessor import extract_urls, parse_sender_string, compute_text_metrics
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import analyze_url
from backend.services.attachment_analyzer import analyze_attachment


def extract_email_features(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts 18+ cybersecurity and NLP features from raw email attributes.

    Args:
        email_data: Dictionary containing:
            - sender: str
            - subject: str
            - body: str
            - urls: Optional[str or List[str]]
            - attachment_name: Optional[str]

    Returns:
        Structured feature dictionary.
    """
    sender = email_data.get("sender", "") or ""
    subject = email_data.get("subject", "") or ""
    body = email_data.get("body", "") or ""
    attachment_name = email_data.get("attachment_name", "") or ""
    
    # 1. Parse sender
    _, _, domain = parse_sender_string(sender)
    sender_domain_length = len(domain)
    subdomain_count = len(domain.split(".")) if domain else 0

    # 2. Extract and analyze URLs
    raw_urls = email_data.get("urls", [])
    if isinstance(raw_urls, str):
        if raw_urls.strip():
            extracted_urls = [u.strip() for u in raw_urls.split(",") if u.strip()]
        else:
            extracted_urls = extract_urls(body)
    else:
        extracted_urls = list(raw_urls)
        
    url_analyses = [analyze_url(u) for u in extracted_urls if u]
    url_count = len(url_analyses)
    suspicious_url_count = sum(1 for ua in url_analyses if ua.get("url_risk_score", 0) >= 30)
    has_ip_url = 1 if any(ua.get("is_raw_ip", False) for ua in url_analyses) else 0
    has_shortened_url_pattern = 1 if any(ua.get("is_shortener", False) for ua in url_analyses) else 0

    # 3. Analyze content heuristics
    content_analysis = analyze_email_content(subject, body)
    matched = content_analysis.get("matched_snippets", {})
    text_metrics = content_analysis.get("text_metrics", {})
    
    urgent_keyword_count = len(matched.get("urgency", []))
    credential_keyword_count = len(matched.get("credential_harvesting", []))
    financial_keyword_count = len(matched.get("financial_coercion", []))
    threat_keyword_count = len(matched.get("fear_threat", []))
    
    generic_greeting = 1 if "generic_greeting" in content_analysis.get("detected_categories", []) else 0
    contains_password_request = 1 if credential_keyword_count > 0 else 0
    contains_personal_info_request = 1 if "pii_harvesting" in content_analysis.get("detected_categories", []) else 0

    # 4. Analyze attachment
    att_analysis = analyze_attachment(attachment_name)
    suspicious_attachment = 1 if att_analysis.get("attachment_risk_score", 0) >= 30 else 0

    # 5. Compile feature dictionary
    features = {
        "urgent_keyword_count": urgent_keyword_count,
        "credential_keyword_count": credential_keyword_count,
        "financial_keyword_count": financial_keyword_count,
        "threat_keyword_count": threat_keyword_count,
        "url_count": url_count,
        "suspicious_url_count": suspicious_url_count,
        "has_ip_url": has_ip_url,
        "has_shortened_url_pattern": has_shortened_url_pattern,
        "sender_domain_length": sender_domain_length,
        "subdomain_count": subdomain_count,
        "suspicious_attachment": suspicious_attachment,
        "generic_greeting": generic_greeting,
        "contains_password_request": contains_password_request,
        "contains_personal_info_request": contains_personal_info_request,
        "exclamation_count": text_metrics.get("exclamation_count", 0),
        "uppercase_ratio": text_metrics.get("uppercase_ratio", 0.0),
        "body_length": len(body),
        "subject_length": len(subject),
    }

    return features


def feature_dict_to_vector(features: Dict[str, Any]) -> List[float]:
    """
    Transforms the feature dictionary into an ordered numerical list suitable for ML classifiers.
    """
    keys = [
        "urgent_keyword_count", "credential_keyword_count", "financial_keyword_count",
        "threat_keyword_count", "url_count", "suspicious_url_count", "has_ip_url",
        "has_shortened_url_pattern", "sender_domain_length", "subdomain_count",
        "suspicious_attachment", "generic_greeting", "contains_password_request",
        "contains_personal_info_request", "exclamation_count", "uppercase_ratio",
        "body_length", "subject_length"
    ]
    return [float(features.get(k, 0.0)) for k in keys]
