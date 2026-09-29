"""
=============================================================================
Module: backend.services.content_analyzer
=============================================================================
Defensive Security Service: Psychological & Social Engineering Content Analysis.

PURPOSE:
Detects cognitive manipulation vectors commonly employed in spearphishing and
mass credential-harvesting campaigns, including:
1. Urgency & Time Pressure (scarcity heuristics)
2. Fear, Intimidation & Account Suspension Threats
3. Financial Coercion & Fraudulent Invoicing
4. Direct Credential & Secret Harvesting
5. Lure of Unearned Rewards & Bonuses
6. Requests for Sensitive PII (SSN, Banking info)
7. Depersonalized / Generic Greetings
8. High-intensity Punctuation & Capitalization Pressure
=============================================================================
"""

import re
from typing import Dict, List, Any
from backend.utils.preprocessor import compute_text_metrics


# Linguistic pattern libraries with regex patterns and educational explanations
CONTENT_PATTERNS = {
    "urgency": {
        "severity": "HIGH",
        "weight": 18,
        "label": "Urgency & Artificial Time Pressure",
        "description": "Pressure to act rapidly bypasses critical thinking and defensive verification procedures.",
        "patterns": [
            r"\b(urgent|immediately|act now|action required|within 24 hours|within 12 hours|expires today|expiring soon|critical alert|final notice|immediate response|limited time|time-sensitive)\b"
        ]
    },
    "fear_threat": {
        "severity": "HIGH",
        "weight": 20,
        "label": "Fear & Intimidation Language",
        "description": "Threatening account deactivation, police action, or fines induces panic, nudging the user to comply.",
        "patterns": [
            r"\b(account (?:has been |will be )?suspended|account locked|unauthorized access|legal penalties|permanently deleted?|account frozen|service termination|immediate deactivation|collections agency|prosecution)\b"
        ]
    },
    "credential_harvesting": {
        "severity": "CRITICAL",
        "weight": 25,
        "label": "Credential / Secret Solicitation",
        "description": "Legitimate enterprise security systems do not solicit passwords, PINs, or credentials via insecure email links.",
        "patterns": [
            r"\b(verify your (?:password|credentials|account)|confirm your (?:password|login)|update your credentials|reset your password immediately|login to verify|security questions|enter credentials|password expiration|confirm your identity now)\b"
        ]
    },
    "financial_coercion": {
        "severity": "HIGH",
        "weight": 20,
        "label": "Financial Coercion & Unscheduled Invoicing",
        "description": "Fake invoices or wire demands exploit business payment workflows to divert funds or collect credit card data.",
        "patterns": [
            r"\b(outstanding payment|invoice past due|overdue invoice|wire transfer request|unpaid invoice|redelivery fee|customs clearance fee|disbursement authorization|direct deposit routing)\b"
        ]
    },
    "reward_lure": {
        "severity": "MEDIUM",
        "weight": 15,
        "label": "Unsolicited Reward / Giveaway Lure",
        "description": "Unexpected financial rewards, lotteries, or crypto airdrops exploit greed and curiosity to elicit clicks.",
        "patterns": [
            r"\b(you have won|claim your prize|crypto giveaway|exclusive bonus|lottery winnings|cash reward|airdrop|congratulations you were selected)\b"
        ]
    },
    "pii_harvesting": {
        "severity": "HIGH",
        "weight": 20,
        "label": "Personally Identifiable Information (PII) Request",
        "description": "Solicitation of national identity numbers, banking numbers, or birthdates for identity theft.",
        "patterns": [
            r"\b(social security number|\bssn\b|confirm your personal details|banking details|credit card number|routing number|passport copy|date of birth)\b"
        ]
    },
    "generic_greeting": {
        "severity": "LOW",
        "weight": 8,
        "label": "Impersonal / Generic Salutation",
        "description": "Mass phishing templates lack recipient database context, often opening with generic greetings.",
        "patterns": [
            r"\b(dear customer|dear user|valued customer|dear client|dear employee|dear member|attention staff|hello user|dear account holder)\b"
        ]
    }
}


def analyze_email_content(subject: str, body: str) -> Dict[str, Any]:
    """
    Analyzes subject and body for manipulation heuristics, coercion keywords,
    and linguistic anomalies.

    Args:
        subject: Email Subject line
        body: Email body text

    Returns:
        Structured dictionary with findings, categorized matches, text metrics, and score.
    """
    combined_text = f"{subject}\n{body}".strip()
    text_metrics = compute_text_metrics(combined_text)
    
    findings: List[Dict[str, Any]] = []
    detected_categories: List[str] = []
    content_risk_score = 0
    matched_snippets: Dict[str, List[str]] = {}

    # 1. Match categorized threat and social engineering patterns
    for cat_id, cat_info in CONTENT_PATTERNS.items():
        category_matches = []
        for pat in cat_info["patterns"]:
            matches = re.findall(pat, combined_text, flags=re.IGNORECASE)
            if matches:
                # Deduplicate snippets
                for m in matches:
                    snippet = m.strip() if isinstance(m, str) else m[0].strip()
                    if snippet and snippet.lower() not in [s.lower() for s in category_matches]:
                        category_matches.append(snippet)
                        
        if category_matches:
            detected_categories.append(cat_id)
            matched_snippets[cat_id] = category_matches
            content_risk_score += cat_info["weight"]
            findings.append({
                "category": cat_id,
                "severity": cat_info["severity"],
                "indicator": cat_info["label"],
                "explanation": cat_info["description"],
                "matched_terms": category_matches[:4]
            })

    # 2. Punctuation & Formatting Anomalies
    if text_metrics["uppercase_ratio"] >= 0.25 and text_metrics["char_count"] > 80:
        content_risk_score += 12
        findings.append({
            "category": "formatting_anomaly",
            "severity": "MEDIUM",
            "indicator": "Excessive Capitalization Pressure",
            "explanation": f"High uppercase character ratio ({int(text_metrics['uppercase_ratio']*100)}%). Excessive capital letters are used to induce urgency and panic.",
            "matched_terms": ["UPPERCASE_RATIO_TRIGGER"]
        })

    if text_metrics["exclamation_count"] >= 3:
        content_risk_score += 8
        findings.append({
            "category": "formatting_anomaly",
            "severity": "LOW",
            "indicator": "Multiple Exclamation Punctuation",
            "explanation": f"Detected {text_metrics['exclamation_count']} exclamation marks, common in pressure-laden social engineering lures.",
            "matched_terms": ["!!!"]
        })

    # If no findings triggered, record clean baseline
    if not findings:
        findings.append({
            "category": "baseline_clean",
            "severity": "INFO",
            "indicator": "Normal Informational Tone",
            "explanation": "No high-pressure urgency, credential solicitations, or coercive threats identified in text.",
            "matched_terms": []
        })

    normalized_score = min(max(content_risk_score, 0), 100)

    return {
        "content_risk_score": normalized_score,
        "detected_categories": detected_categories,
        "matched_snippets": matched_snippets,
        "text_metrics": text_metrics,
        "findings": findings
    }
