"""
=============================================================================
Module: backend.services.risk_engine
=============================================================================
Defensive Security Service: Phishing Risk Scoring & Explainability Engine.

PURPOSE:
Synthesizes telemetry from sender, content, URL, and attachment analyzers
into a calibrated 0-100 Phishing Risk Score, actionable classification tier,
explainable indicator breakdown, and defensive security recommendations.

CALIBRATION & THRESHOLDS:
- 0 to 20:   SAFE (Normal informational communication)
- 21 to 40:  LOW RISK (Minor atypical phrasing, routine caution)
- 41 to 70:  SUSPICIOUS (Multiple anomalies, requires analyst verification)
- 71 to 100: HIGH RISK / LIKELY PHISHING (High confidence malicious social engineering)

NOTE ON CALIBRATION:
In enterprise email security gateways, thresholds are tuned to minimize
False Negatives (preventing breach) while maintaining acceptable False
Positive rates (avoiding employee disruption).
=============================================================================
"""

from typing import Dict, List, Any
from backend.utils.preprocessor import extract_urls, parse_sender_string
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import analyze_url
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.feature_extractor import extract_email_features


# MITRE ATT&CK Mapping definitions for Phishing Sub-techniques
MITRE_MAPPINGS = {
    "attachment": {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversaries send emails with weaponized attachments to execute malicious code on the target system."
    },
    "link": {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries send emails containing hyperlinks directed to malicious credential harvesting or exploit sites."
    },
    "service": {
        "id": "T1566.003",
        "name": "Phishing: Spearphishing via Service",
        "tactic": "Initial Access",
        "description": "Adversaries leverage third-party commercial, cloud, or free services to send deceptive phishing communications."
    }
}


def calculate_phishing_score(
    sender_analysis: Dict[str, Any],
    content_analysis: Dict[str, Any],
    url_analyses: List[Dict[str, Any]],
    attachment_analysis: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes weighted risk score and generates explainability justifications.
    """
    accumulated_score = 0.0
    indicator_summary: List[Dict[str, str]] = []
    mitre_tags: List[Dict[str, str]] = []

    # 1. Evaluate Sender Weight (Up to 25 pts)
    sender_risk = sender_analysis.get("sender_risk_score", 0)
    if sender_risk >= 30:
        sender_weight = (sender_risk / 100.0) * 25.0
        accumulated_score += sender_weight
        for f in sender_analysis.get("findings", []):
            if f.get("severity") in ["MEDIUM", "HIGH", "CRITICAL"]:
                indicator_summary.append({
                    "category": "Sender Pattern",
                    "title": f["indicator"],
                    "detail": f["explanation"],
                    "severity": f["severity"]
                })

    # 2. Evaluate Content Manipulations (Up to 45 pts total)
    detected_cats = content_analysis.get("detected_categories", [])
    
    if "credential_harvesting" in detected_cats:
        accumulated_score += 25.0
        indicator_summary.append({
            "category": "Social Engineering",
            "title": "Credential Solicitation Detected",
            "detail": "Email directly requests user passwords, authentication tokens, or credential confirmation.",
            "severity": "CRITICAL"
        })
        
    if "urgency" in detected_cats:
        accumulated_score += 15.0
        indicator_summary.append({
            "category": "Social Engineering",
            "title": "Artificial Urgency & Time Pressure",
            "detail": "Email imposes arbitrary deadlines ('within 24 hours', 'immediately') to discourage caution.",
            "severity": "HIGH"
        })

    if "fear_threat" in detected_cats:
        accumulated_score += 15.0
        indicator_summary.append({
            "category": "Social Engineering",
            "title": "Threat / Account Suspension Coercion",
            "detail": "Threatens permanent account termination, legal prosecution, or service shutoff.",
            "severity": "HIGH"
        })

    if "financial_coercion" in detected_cats:
        accumulated_score += 15.0
        indicator_summary.append({
            "category": "Social Engineering",
            "title": "Unscheduled Financial / Invoicing Pressure",
            "detail": "References overdue balances, wire requests, or clearance fees.",
            "severity": "HIGH"
        })

    if "reward_lure" in detected_cats:
        accumulated_score += 12.0
        indicator_summary.append({
            "category": "Social Engineering",
            "title": "Unsolicited Reward or Lottery Lure",
            "detail": "Offers unexpected monetary prizes, giveaways, or airdrops to exploit curiosity.",
            "severity": "MEDIUM"
        })

    if "pii_harvesting" in detected_cats:
        accumulated_score += 18.0
        indicator_summary.append({
            "category": "Social Engineering",
            "title": "Sensitive Personal Data Request",
            "detail": "Requests Social Security Numbers, banking details, or identity documents.",
            "severity": "HIGH"
        })

    if "generic_greeting" in detected_cats:
        accumulated_score += 6.0
        indicator_summary.append({
            "category": "Linguistic",
            "title": "Impersonal Salutation",
            "detail": "Uses depersonalized greetings typical of bulk automated phishing lures.",
            "severity": "LOW"
        })

    # 3. Evaluate URLs (Up to 30 pts)
    max_url_score = max([u.get("url_risk_score", 0) for u in url_analyses], default=0)
    if max_url_score > 0:
        url_weight = (max_url_score / 100.0) * 30.0
        accumulated_score += url_weight
        mitre_tags.append(MITRE_MAPPINGS["link"])
        
        for u in url_analyses:
            for f in u.get("findings", []):
                if f.get("severity") in ["HIGH", "CRITICAL"]:
                    indicator_summary.append({
                        "category": "Hyperlink Risk",
                        "title": f"{f['indicator']} ({u['hostname']})",
                        "detail": f["explanation"],
                        "severity": f["severity"]
                    })

    # 4. Evaluate Attachments (Up to 35 pts)
    att_risk = attachment_analysis.get("attachment_risk_score", 0)
    if att_risk > 0:
        att_weight = (att_risk / 100.0) * 35.0
        accumulated_score += att_weight
        mitre_tags.append(MITRE_MAPPINGS["attachment"])
        
        for f in attachment_analysis.get("findings", []):
            if f.get("severity") in ["MEDIUM", "HIGH", "CRITICAL"]:
                indicator_summary.append({
                    "category": "Attachment Risk",
                    "title": f["indicator"],
                    "detail": f["explanation"],
                    "severity": f["severity"]
                })

    # Bound score cleanly between 0 and 100
    final_score = int(round(min(max(accumulated_score, 0), 100)))

    # Determine classification tier
    if final_score <= 20:
        classification = "SAFE"
        classification_color = "success"
    elif final_score <= 40:
        classification = "LOW RISK"
        classification_color = "info"
    elif final_score <= 70:
        classification = "SUSPICIOUS"
        classification_color = "warning"
    else:
        classification = "HIGH RISK / LIKELY PHISHING"
        classification_color = "danger"

    # Generate actionable security recommendations
    recommendations = generate_recommendations(classification, indicator_summary, url_analyses, attachment_analysis)

    return {
        "risk_score": final_score,
        "classification": classification,
        "classification_color": classification_color,
        "indicator_summary": indicator_summary,
        "recommendations": recommendations,
        "mitre_attack": mitre_tags
    }


def generate_recommendations(
    classification: str,
    indicators: List[Dict[str, str]],
    url_analyses: List[Dict[str, Any]],
    attachment_analysis: Dict[str, Any]
) -> List[str]:
    """
    Generates actionable, defensive SOP steps tailored to identified threats.
    """
    recs = []

    if classification == "SAFE":
        recs.append("No immediate malicious indicators identified. Proceed with normal communication.")
        recs.append("Maintain baseline cyber hygiene: ensure multi-factor authentication (MFA) remains active.")
        return recs

    # General defensive advice for suspicious/phishing
    recs.append("DO NOT click any hyperlinks or embedded buttons within this message.")
    
    if attachment_analysis.get("has_attachment") and attachment_analysis.get("attachment_risk_score", 0) > 0:
        recs.append(f"DO NOT download, preview, or open attachment '{attachment_analysis.get('filename')}' under any circumstances.")

    recs.append("Verify the sender's identity through a secondary, trusted out-of-band channel (e.g., official internal chat, known company phone directory).")
    
    if any(u.get("is_raw_ip") for u in url_analyses):
        recs.append("SOC Alert: Hyperlink points directly to an unauthenticated numerical IP address, typical of hostile command-and-control or drop-sites.")

    recs.append("If this communication claims to represent an institution (bank, HR, cloud service), navigate directly to their official bookmarked portal instead of following email links.")
    recs.append("Report this message to your Security Operations Center (SOC) or IT Security department using your email client's 'Report Phishing' button.")

    return recs


def analyze_email_complete(
    sender: str,
    subject: str,
    body: str,
    attachment_name: str = "",
    urls_input: str = ""
) -> Dict[str, Any]:
    """
    Orchestrates end-to-end analysis across all modules.
    """
    # 1. Parse & analyze sender
    sender_result = analyze_sender(sender, body)

    # 2. Extract & analyze URLs
    extracted_urls = []
    if urls_input and urls_input.strip():
        extracted_urls = [u.strip() for u in urls_input.split(",") if u.strip()]
    else:
        extracted_urls = extract_urls(body)
    
    url_results = [analyze_url(u) for u in extracted_urls if u]

    # 3. Analyze content
    content_result = analyze_email_content(subject, body)

    # 4. Analyze attachment
    attachment_result = analyze_attachment(attachment_name)

    # 5. Extract engineered features
    features = extract_email_features({
        "sender": sender,
        "subject": subject,
        "body": body,
        "urls": extracted_urls,
        "attachment_name": attachment_name
    })

    # 6. Calculate risk score & explainability
    risk_assessment = calculate_phishing_score(
        sender_result,
        content_result,
        url_results,
        attachment_result
    )

    return {
        "sender_analysis": sender_result,
        "content_analysis": content_result,
        "url_analyses": url_results,
        "attachment_analysis": attachment_result,
        "features": features,
        "risk_assessment": risk_assessment
    }
