"""
=============================================================================
Module: ml.predict
=============================================================================
Machine Learning Inference Engine for Phishing Detection.

PURPOSE:
Loads serialized TF-IDF vectorizer and trained classification model to compute
calibrated phishing probability scores (0.0 to 1.0) and classifications.
=============================================================================
"""

import os
import joblib
from typing import Dict, Any, Optional

DEFAULT_MODEL_PATH = "ml/best_phishing_model.joblib"
DEFAULT_VEC_PATH = "ml/tfidf_vectorizer.joblib"

_cached_model = None
_cached_vectorizer = None


def load_model_and_vectorizer(model_path: str = DEFAULT_MODEL_PATH, vec_path: str = DEFAULT_VEC_PATH):
    """
    Loads and caches model and vectorizer to avoid redundant disk I/O.
    """
    global _cached_model, _cached_vectorizer
    if _cached_model is not None and _cached_vectorizer is not None:
        return _cached_model, _cached_vectorizer

    if not os.path.exists(model_path) or not os.path.exists(vec_path):
        return None, None

    try:
        _cached_model = joblib.load(model_path)
        _cached_vectorizer = joblib.load(vec_path)
        return _cached_model, _cached_vectorizer
    except Exception as e:
        print(f"[!] Warning: Unable to load ML artifacts: {e}")
        return None, None


def predict_phishing_probability(text: str) -> Dict[str, Any]:
    """
    Predicts probability of text representing a phishing communication.

    Args:
        text: Combined subject and body string

    Returns:
        Dictionary with probability (0.0 to 1.0), predicted_label, and model_status.
    """
    model, vectorizer = load_model_and_vectorizer()
    
    if model is None or vectorizer is None:
        return {
            "is_available": False,
            "probability": None,
            "predicted_label": "MODEL_UNAVAILABLE",
            "confidence_pct": None,
            "message": "ML model artifacts not found. Run 'python ml/train_model.py' to generate."
        }

    try:
        features_vec = vectorizer.transform([text or ""])
        
        # Determine probability if model supports predict_proba
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(features_vec)[0]
            # Class 1 is PHISHING
            phish_prob = float(probs[1])
        elif hasattr(model, "decision_function"):
            decision = model.decision_function(features_vec)[0]
            # Sigmoid scaling
            import numpy as np
            phish_prob = float(1.0 / (1.0 + np.exp(-decision)))
        else:
            pred = model.predict(features_vec)[0]
            phish_prob = 1.0 if pred == 1 else 0.0

        label = "PHISHING" if phish_prob >= 0.50 else "LEGITIMATE"
        
        return {
            "is_available": True,
            "probability": round(phish_prob, 4),
            "predicted_label": label,
            "confidence_pct": round(phish_prob * 100.0, 1),
            "message": "ML inference successful."
        }
    except Exception as e:
        return {
            "is_available": False,
            "probability": None,
            "predicted_label": "ERROR",
            "confidence_pct": None,
            "message": f"ML prediction error: {str(e)}"
        }
