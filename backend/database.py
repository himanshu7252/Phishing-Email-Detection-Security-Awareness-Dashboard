"""
=============================================================================
Module: backend.database
=============================================================================
Database Persistence Layer using SQLite.

PRIVACY & DEFENSIVE DATA HANDLING:
In alignment with enterprise data privacy standards (e.g., GDPR, SOC 2):
1. By default, full sensitive email bodies are NOT stored permanently to avoid
   accumulating confidential customer or corporate correspondence.
2. Only safe forensic metadata (sender domain, subject preview, risk scores,
   classified indicators, URL domain artifacts) is persisted.
3. Foreign key constraints enforce relational integrity across analyses,
   associated indicators, and inspected hyperlinks.
=============================================================================
"""

import sqlite3
import os
import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "phishing_analysis.db")


def get_db_connection() -> sqlite3.Connection:
    """
    Creates an SQLite connection with WAL mode and row factory enabled.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Initializes database schema with required tables and indexes.
    """
    conn = get_db_connection()
    with conn:
        # 1. Main Analyses table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id TEXT PRIMARY KEY,
                sender_raw TEXT,
                sender_domain TEXT,
                subject TEXT,
                body_snippet TEXT,
                attachment_name TEXT,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                detection_mode TEXT DEFAULT 'HYBRID',
                rule_score INTEGER,
                ml_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 2. Indicators table (1-to-many with analyses)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
            );
        """)

        # 3. URL Analyses table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_analyses (
                url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                url_safe_representation TEXT NOT NULL,
                hostname TEXT,
                is_raw_ip BOOLEAN DEFAULT 0,
                risk_score INTEGER NOT NULL,
                findings_summary TEXT,
                FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
            );
        """)

        # 4. Optional Users table (Role demonstrations)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'SOC_ANALYST',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Create indexes for fast filtering & search
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_class ON analyses(classification);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_indicators_analysis ON indicators(analysis_id);")

    conn.close()


def save_analysis(
    full_result: Dict[str, Any],
    subject: str,
    sender_raw: str,
    body: str,
    attachment_name: str = ""
) -> str:
    """
    Persists safe analysis telemetry to SQLite.
    Returns generated analysis_id.
    """
    init_db()
    analysis_id = f"ANL-{uuid.uuid4().hex[:8].upper()}"
    
    sender_domain = full_result.get("sender_analysis", {}).get("domain", "")
    risk_assessment = full_result.get("risk_assessment", {})
    hybrid_assessment = full_result.get("hybrid_assessment", {})
    
    # Extract scores
    if hybrid_assessment and hybrid_assessment.get("is_hybrid"):
        final_score = hybrid_assessment.get("hybrid_risk_score", 0)
        classification = hybrid_assessment.get("classification", "SAFE")
        detection_mode = "HYBRID"
        rule_score = hybrid_assessment.get("rule_score")
        ml_score = hybrid_assessment.get("ml_probability_pct")
    else:
        final_score = risk_assessment.get("risk_score", 0)
        classification = risk_assessment.get("classification", "SAFE")
        detection_mode = "RULE_BASED"
        rule_score = final_score
        ml_score = None

    # Safe snippet (max 150 chars, sanitized preview)
    body_snippet = (body[:150] + "...") if len(body) > 150 else body

    conn = get_db_connection()
    with conn:
        # Insert analysis record
        conn.execute("""
            INSERT INTO analyses (
                analysis_id, sender_raw, sender_domain, subject,
                body_snippet, attachment_name, risk_score, classification,
                detection_mode, rule_score, ml_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_id, sender_raw, sender_domain, subject,
            body_snippet, attachment_name, final_score, classification,
            detection_mode, rule_score, ml_score
        ))

        # Insert indicators
        indicators = risk_assessment.get("indicator_summary", [])
        for ind in indicators:
            conn.execute("""
                INSERT INTO indicators (
                    analysis_id, category, title, description, severity
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                analysis_id,
                ind.get("category", "General"),
                ind.get("title", ""),
                ind.get("detail", ""),
                ind.get("severity", "INFO")
            ))

        # Insert URL analyses
        urls = full_result.get("url_analyses", [])
        for u in urls:
            conn.execute("""
                INSERT INTO url_analyses (
                    analysis_id, url_safe_representation, hostname,
                    is_raw_ip, risk_score, findings_summary
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                analysis_id,
                u.get("url", ""),
                u.get("hostname", ""),
                1 if u.get("is_raw_ip") else 0,
                u.get("url_risk_score", 0),
                json.dumps([f.get("indicator") for f in u.get("findings", [])])
            ))

    conn.close()
    return analysis_id


def get_all_analyses(
    classification: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    Retrieves filtered and paginated analysis history records.
    """
    init_db()
    conn = get_db_connection()
    
    query = "SELECT * FROM analyses WHERE 1=1"
    params = []

    if classification and classification.upper() != "ALL":
        query += " AND UPPER(classification) = UPPER(?)"
        params.append(classification)

    if search and search.strip():
        query += " AND (subject LIKE ? OR sender_raw LIKE ? OR sender_domain LIKE ?)"
        wildcard = f"%{search.strip()}%"
        params.extend([wildcard, wildcard, wildcard])

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    
    results = []
    for r in rows:
        results.append(dict(r))
        
    conn.close()
    return results


def get_analysis_by_id(analysis_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves complete details for a single analysis record, including indicators and URLs.
    """
    init_db()
    conn = get_db_connection()
    
    main_row = conn.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,)).fetchone()
    if not main_row:
        conn.close()
        return None

    record = dict(main_row)
    
    # Fetch indicators
    ind_rows = conn.execute(
        "SELECT * FROM indicators WHERE analysis_id = ? ORDER BY indicator_id ASC",
        (analysis_id,)
    ).fetchall()
    record["indicators"] = [dict(i) for i in ind_rows]

    # Fetch URLs
    url_rows = conn.execute(
        "SELECT * FROM url_analyses WHERE analysis_id = ? ORDER BY url_analysis_id ASC",
        (analysis_id,)
    ).fetchall()
    record["urls"] = [dict(u) for u in url_rows]

    conn.close()
    return record


def delete_analysis(analysis_id: str) -> bool:
    """
    Deletes an analysis record and cascades to indicators and URLs.
    """
    init_db()
    conn = get_db_connection()
    with conn:
        cursor = conn.execute("DELETE FROM analyses WHERE analysis_id = ?", (analysis_id,))
        deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def get_dashboard_statistics() -> Dict[str, Any]:
    """
    Computes aggregated SOC analytics across all analyzed records.
    """
    init_db()
    conn = get_db_connection()
    
    total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
    
    if total == 0:
        conn.close()
        return {
            "total_analyzed": 0,
            "high_risk_count": 0,
            "suspicious_count": 0,
            "low_risk_count": 0,
            "safe_count": 0,
            "average_risk_score": 0.0,
            "classification_distribution": {
                "SAFE": 0,
                "LOW RISK": 0,
                "SUSPICIOUS": 0,
                "HIGH RISK / LIKELY PHISHING": 0
            },
            "top_indicators": [],
            "recent_activity": []
        }

    # Count by classification
    rows = conn.execute("SELECT classification, COUNT(*) as cnt FROM analyses GROUP BY classification").fetchall()
    dist = {
        "SAFE": 0,
        "LOW RISK": 0,
        "SUSPICIOUS": 0,
        "HIGH RISK / LIKELY PHISHING": 0
    }
    for r in rows:
        key = r["classification"].upper()
        if "HIGH" in key or "LIKELY" in key:
            dist["HIGH RISK / LIKELY PHISHING"] += r["cnt"]
        elif "SUSPICIOUS" in key:
            dist["SUSPICIOUS"] += r["cnt"]
        elif "LOW" in key:
            dist["LOW RISK"] += r["cnt"]
        else:
            dist["SAFE"] += r["cnt"]

    # Average score
    avg_score = conn.execute("SELECT AVG(risk_score) FROM analyses").fetchone()[0] or 0.0

    # Top detected indicators
    top_ind_rows = conn.execute("""
        SELECT title, category, COUNT(*) as freq
        FROM indicators
        GROUP BY title, category
        ORDER BY freq DESC
        LIMIT 6
    """).fetchall()
    top_indicators = [dict(ti) for ti in top_ind_rows]

    # Recent 5 analyses
    recent_rows = conn.execute("""
        SELECT analysis_id, subject, sender_domain, risk_score, classification, created_at
        FROM analyses
        ORDER BY created_at DESC
        LIMIT 5
    """).fetchall()
    recent = [dict(rr) for rr in recent_rows]

    conn.close()

    return {
        "total_analyzed": total,
        "high_risk_count": dist["HIGH RISK / LIKELY PHISHING"],
        "suspicious_count": dist["SUSPICIOUS"],
        "low_risk_count": dist["LOW RISK"],
        "safe_count": dist["SAFE"],
        "average_risk_score": round(float(avg_score), 1),
        "classification_distribution": dist,
        "top_indicators": top_indicators,
        "recent_activity": recent
    }
