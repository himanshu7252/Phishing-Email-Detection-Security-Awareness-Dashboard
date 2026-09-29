"""
=============================================================================
Module: backend.services.hybrid_engine
=============================================================================
Defensive Security Service: Hybrid Phishing Detection (Rules + ML Ensemble).

PURPOSE:
Combines deterministic, interpretable heuristic rules with probabilistic NLP
machine learning to provide a robust, defense-in-depth phishing evaluation.

WHY HYBRID DETECTION IS INDUSTRY BEST-PRACTICE:
1. Pure Rule-Based Systems:
   - Strengths: 100% explainable, deterministic detection of technical indicators
     (e.g. raw IP hostnames, .pdf.exe double extensions, brand-domain mismatches).
   - Weaknesses: Rigid, easily bypassed by subtle wording shifts.
2. Pure Machine Learning Systems:
   - Strengths: Generalizes well across varied natural language phrasing.
   - Weaknesses: Black-box behavior; vulnerable to adversarial evasion; may ignore
     critical structural indicators (e.g., a benign-sounding email containing a .scr attachment).
3. Hybrid Ensemble:
   Synthesizes both paradigms so that technical compromise signals cannot be masked
   by polite text, while linguistic coercion is still effectively captured.
=============================================================================
"""

from typing import Dict, Any
from backend.services.risk_engine import calculate_phishing_score
from ml.predict import predict_phishing_probability


def compute_hybrid_assessment(
    rule_assessment: Dict[str, Any],
    email_text: str,
    rule_weight: float = 0.55,
    ml_weight: float = 0.45
) -> Dict[str, Any]:
    """
    Computes an integrated hybrid risk score and generates defensive reasoning.

    Args:
        rule_assessment: Output from risk_engine.calculate_phishing_score
        email_text: Full combined subject + body text for ML inference
        rule_weight: Relative weight for heuristic rules (default 0.55)
        ml_weight: Relative weight for ML model (default 0.45)

    Returns:
        Dictionary containing hybrid_score, rule_score, ml_score, classification,
        confidence, and explainability notes.
    """
    rule_score = rule_assessment.get("risk_score", 0)
    
    # Run ML prediction
    ml_result = predict_phishing_probability(email_text)
    
    if ml_result.get("is_available") and ml_result.get("confidence_pct") is not None:
        ml_score = ml_result["confidence_pct"]
        ml_prob = ml_result["probability"]
        
        # Calculate combined weighted score
        combined_score = (rule_score * rule_weight) + (ml_score * ml_weight)
        
        # Safety override: If rules flagged a CRITICAL technical threat (e.g., weaponized attachment or IP link)
        # do not let a polite text ML score drag the score down into 'SAFE'.
        has_critical_rule = any(
            ind.get("severity") == "CRITICAL" for ind in rule_assessment.get("indicator_summary", [])
        )
        if has_critical_rule and combined_score < 75:
            combined_score = max(combined_score, 75.0)
            
        final_score = int(round(min(max(combined_score, 0), 100)))
        
        # Determine classification
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

        # Hybrid explanation reasoning
        if abs(rule_score - ml_score) > 35:
            divergence_note = (
                f"Notice: Rule-based heuristics ({rule_score}/100) and ML language analysis ({int(ml_score)}%) "
                "diverged. The hybrid engine synthesized technical evidence with textual modeling to prevent blind spots."
            )
        else:
            divergence_note = (
                f"High consensus: Both deterministic rules ({rule_score}/100) and probabilistic ML ({int(ml_score)}%) "
                "agree on threat profile."
            )

        return {
            "is_hybrid": True,
            "hybrid_risk_score": final_score,
            "rule_score": rule_score,
            "ml_probability_pct": ml_score,
            "ml_predicted_label": ml_result.get("predicted_label"),
            "classification": classification,
            "classification_color": classification_color,
            "divergence_note": divergence_note,
            "weights": {"rule": rule_weight, "ml": ml_weight}
        }
    else:
        # Fallback cleanly to rule-based engine if ML artifacts are missing
        return {
            "is_hybrid": False,
            "hybrid_risk_score": rule_score,
            "rule_score": rule_score,
            "ml_probability_pct": None,
            "ml_predicted_label": None,
            "classification": rule_assessment.get("classification", "SAFE"),
            "classification_color": rule_assessment.get("classification_color", "success"),
            "divergence_note": "Rule-based engine active (ML module in standby mode).",
            "weights": {"rule": 1.0, "ml": 0.0}
        }
