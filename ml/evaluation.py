"""
=============================================================================
Module: ml.evaluation
=============================================================================
Cybersecurity Model Evaluation, Confusion Matrix Analysis & Tradeoffs.

DEFENSIVE SECURITY METRICS EXPLANATION:
In cybersecurity defense (and particularly email triage), evaluating an ML
model based solely on accuracy is critically flawed.

1. TRUE POSITIVE (TP):
   A genuine phishing attempt is correctly detected and quarantined.
   Outcome: Attack mitigated, credentials secured.

2. TRUE NEGATIVE (TN):
   A legitimate business/academic email is correctly recognized and delivered.
   Outcome: Seamless business operations.

3. FALSE POSITIVE (FP):
   A legitimate email (e.g. an urgent email from HR) is wrongly flagged as phishing.
   Security Cost: Causes alert fatigue for SOC analysts, degrades user trust,
   and disrupts communication. Controlled by optimizing PRECISION.

4. FALSE NEGATIVE (FN):
   A dangerous phishing email slips through unnoticed into the user inbox.
   Security Cost: Catastrophic potential (credential harvesting, malware infection,
   ransomware outbreak). Controlled by optimizing RECALL.

F1-Score: Harmonic mean of Precision and Recall:
   F1 = 2 * (Precision * Recall) / (Precision + Recall)
=============================================================================
"""

from typing import Dict, Any


def explain_confusion_matrix(cm_dict: Dict[str, int]) -> Dict[str, Any]:
    """
    Returns an educational breakdown of confusion matrix figures.
    """
    tp = cm_dict.get("true_positive", 0)
    tn = cm_dict.get("true_negative", 0)
    fp = cm_dict.get("false_positive", 0)
    fn = cm_dict.get("false_negative", 0)
    
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "raw_counts": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "total_tested": total
        },
        "computed_metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4)
        },
        "soc_analysis": {
            "recall_assessment": (
                "Excellent: Zero or minimal false negatives ensure phishing attacks do not slip past the gateway."
                if fn <= 2 else f"Caution: {fn} attacks were missed (False Negatives), which pose breach risks."
            ),
            "precision_assessment": (
                "High precision: Minimal false alarms keep SOC analyst fatigue low."
                if fp <= 2 else f"Notice: {fp} legitimate messages were misclassified (False Positives)."
            )
        }
    }
