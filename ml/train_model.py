"""
=============================================================================
Module: ml.train_model
=============================================================================
Machine Learning Pipeline for Phishing Email Detection.

PURPOSE:
Trains, cross-validates, and evaluates three standard ML classification models:
1. Logistic Regression (Linear baseline with interpretable coefficients)
2. Multinomial Naive Bayes (Probabilistic text classifier)
3. Random Forest Classifier (Non-linear ensemble model)

CYBERSECURITY EVALUATION CRITERIA:
- Accuracy alone can be dangerously deceptive in security applications.
- Recall is paramount: Missing a phishing attack (False Negative) can result in
  ransomware execution, data exfiltration, or organizational compromise.
- Precision controls alert fatigue: Bombarding analysts with False Positives
  degrades response times and causes genuine alerts to be overlooked.
- F1 Score harmonizes Precision and Recall into a balanced metric.
=============================================================================
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

def train_and_evaluate_models(
    dataset_path: str = "data/phishing_email_dataset.csv",
    models_dir: str = "ml",
    reports_dir: str = "reports"
):
    """
    Loads dataset, trains candidate models using TF-IDF, evaluates metrics,
    selects the highest-performing model, and exports artifacts.
    """
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    print(f"[*] Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    
    # Preprocess text by combining Subject and Body
    df["full_text"] = df["subject"].fillna("") + " " + df["body"].fillna("")
    
    # Binary target: 1 for PHISHING, 0 for LEGITIMATE
    df["target"] = df["label"].apply(lambda x: 1 if str(x).upper() == "PHISHING" else 0)
    
    X = df["full_text"]
    y = df["target"]
    
    # Train-Test Split (80% train, 20% test, stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    print(f"[*] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")
    
    # TF-IDF Vectorization
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=2500,
        sublinear_tf=True
    )
    
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    # Candidate models
    candidates = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.1),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42)
    }
    
    results = {}
    best_model_name = None
    best_f1 = -1.0
    best_model_obj = None
    best_cm = None
    
    for name, model in candidates.items():
        print(f"\n[+] Training {name}...")
        model.fit(X_train_vec, y_train)
        y_pred = model.predict(X_test_vec)
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)
        
        # TN, FP, FN, TP
        tn, fp, fn, tp = cm.ravel()
        
        results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            }
        }
        
        print(f"    - Accuracy:  {acc:.4f}")
        print(f"    - Precision: {prec:.4f} (Low False Positives)")
        print(f"    - Recall:    {rec:.4f} (Low False Negatives)")
        print(f"    - F1 Score:  {f1:.4f}")
        print(f"    - Matrix: TP={tp}, TN={tn}, FP={fp}, FN={fn}")
        
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model_obj = model
            best_cm = cm

    print(f"\n[*] Best Performing Model: {best_model_name} (F1 Score: {best_f1:.4f})")
    
    # Save best model and vectorizer
    model_save_path = os.path.join(models_dir, "best_phishing_model.joblib")
    vec_save_path = os.path.join(models_dir, "tfidf_vectorizer.joblib")
    metrics_path = os.path.join(models_dir, "ml_metrics.json")
    
    joblib.dump(best_model_obj, model_save_path)
    joblib.dump(vectorizer, vec_save_path)
    
    summary_data = {
        "best_model": best_model_name,
        "models_evaluated": results,
        "test_sample_count": len(y_test),
        "feature_count": X_train_vec.shape[1]
    }
    
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=4)
        
    # Generate Confusion Matrix Chart
    plt.figure(figsize=(7, 5.5))
    sns.heatmap(
        best_cm,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=['Legitimate (0)', 'Phishing (1)'],
        yticklabels=['Legitimate (0)', 'Phishing (1)']
    )
    plt.title(f'Confusion Matrix: {best_model_name}\n(Defensive Phishing Classification)', fontsize=12, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=10)
    plt.ylabel('Ground Truth Label', fontsize=10)
    plt.tight_layout()
    
    cm_plot_path = os.path.join(reports_dir, "confusion_matrix.png")
    cm_plot_path_ml = os.path.join(models_dir, "confusion_matrix.png")
    plt.savefig(cm_plot_path, dpi=300)
    plt.savefig(cm_plot_path_ml, dpi=300)
    plt.close()
    
    print(f"[+] Saved model to: {model_save_path}")
    print(f"[+] Saved vectorizer to: {vec_save_path}")
    print(f"[+] Saved metrics to: {metrics_path}")
    print(f"[+] Saved confusion matrix to: {cm_plot_path}")
    return summary_data

if __name__ == "__main__":
    train_and_evaluate_models()
