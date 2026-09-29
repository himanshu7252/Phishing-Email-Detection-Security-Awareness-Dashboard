"""
=============================================================================
Seed Script: Seed Demo History for SOC Dashboard Analytics
=============================================================================
Populates 15 initial synthetic analysis audit records to showcase live
SOC dashboard charts, indicators, and historical triage logs.
=============================================================================
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd
from backend.database import init_db, save_analysis
from backend.services.risk_engine import analyze_email_complete
from backend.services.hybrid_engine import compute_hybrid_assessment

def seed_demo_data(csv_path: str = "data/phishing_email_dataset.csv", count: int = 16):
    init_db()
    df = pd.read_csv(csv_path)
    
    # Take a balanced sample of legitimate and phishing
    sample_df = pd.concat([
        df[df["label"] == "PHISHING"].head(count // 2),
        df[df["label"] == "LEGITIMATE"].head(count // 2)
    ]).sample(frac=1.0, random_state=42)
    
    print(f"[*] Seeding {len(sample_df)} sample analysis records into SQLite database...")
    for idx, row in sample_df.iterrows():
        sender = str(row.get("sender", ""))
        subject = str(row.get("subject", ""))
        body = str(row.get("body", ""))
        urls = str(row.get("urls", ""))
        attachment = str(row.get("attachment_name", ""))
        
        # Analyze
        full_res = analyze_email_complete(sender, subject, body, attachment, urls)
        combined_text = f"{subject}\n{body}"
        hybrid_res = compute_hybrid_assessment(full_res["risk_assessment"], combined_text)
        full_res["hybrid_assessment"] = hybrid_res
        
        # Save
        aid = save_analysis(full_res, subject, sender, body, attachment)
        print(f"    [+] Created record {aid} - {hybrid_res['classification']} ({hybrid_res['hybrid_risk_score']}/100)")
        
    print("[*] Database seeding completed.")

if __name__ == "__main__":
    seed_demo_data()
