"""
=============================================================================
Module: tests.test_detection_suite
=============================================================================
Comprehensive Automated Security Testing Suite (25+ Tests).

PURPOSE:
Validates cybersecurity heuristics, ML inferences, REST endpoints, database
integrity, and edge-case handling across all defensive components.
=============================================================================
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app import app
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import analyze_url
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.risk_engine import analyze_email_complete, calculate_phishing_score
from backend.services.hybrid_engine import compute_hybrid_assessment
from backend.database import init_db, save_analysis, get_all_analyses, get_analysis_by_id
from ml.predict import predict_phishing_probability


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Test 1: Legitimate Email Analysis
# ---------------------------------------------------------------------------
def test_01_legitimate_email():
    res = analyze_email_complete(
        sender="Registrar <registrar@university.example.edu>",
        subject="Fall Semester Course Schedule Announced",
        body="Dear students, the course registration schedule is now live. Please review your portal at https://portal.university.example.edu.",
        attachment_name="course_schedule.pdf"
    )
    score = res["risk_assessment"]["risk_score"]
    assert score <= 30
    assert res["risk_assessment"]["classification"] in ["SAFE", "LOW RISK"]


# ---------------------------------------------------------------------------
# Test 2: Urgent Phishing-Style Email
# ---------------------------------------------------------------------------
def test_02_urgent_phishing_email():
    res = analyze_email_complete(
        sender="Security Alert <alert@account-check.invalid.test>",
        subject="URGENT: Your Account Will Be Suspended Within 24 Hours",
        body="Dear customer, your account will be suspended immediately unless you confirm your password now at http://198.51.100.10/verify.",
        attachment_name=""
    )
    assert res["risk_assessment"]["risk_score"] >= 65
    assert res["risk_assessment"]["classification"] in ["SUSPICIOUS", "HIGH RISK / LIKELY PHISHING"]


# ---------------------------------------------------------------------------
# Test 3: Credential Request Detection
# ---------------------------------------------------------------------------
def test_03_credential_request():
    content = analyze_email_content("Verify Account", "Please verify your password and login credentials immediately.")
    assert "credential_harvesting" in content["detected_categories"]
    assert content["content_risk_score"] >= 25


# ---------------------------------------------------------------------------
# Test 4: Financial Pressure / Fake Invoice
# ---------------------------------------------------------------------------
def test_04_financial_request():
    content = analyze_email_content("Overdue Invoice", "You have an outstanding payment. Settle the unpaid invoice or face legal collections.")
    assert "financial_coercion" in content["detected_categories"]
    assert content["content_risk_score"] >= 20


# ---------------------------------------------------------------------------
# Test 5: Generic Greeting Detection
# ---------------------------------------------------------------------------
def test_05_generic_greeting():
    content = analyze_email_content("Notice", "Dear Customer, please review our updated privacy terms.")
    assert "generic_greeting" in content["detected_categories"]


# ---------------------------------------------------------------------------
# Test 6: Safe URL Analysis
# ---------------------------------------------------------------------------
def test_06_safe_url():
    u = analyze_url("https://portal.university.example.edu/records")
    assert u["url_risk_score"] == 0
    assert not u["is_raw_ip"]
    assert not u["is_shortener"]


# ---------------------------------------------------------------------------
# Test 7: Raw IP URL Detection
# ---------------------------------------------------------------------------
def test_07_raw_ip_url():
    u = analyze_url("http://198.51.100.10/verify-account")
    assert u["is_raw_ip"] is True
    assert u["url_risk_score"] >= 40
    assert any("Raw IP Address" in f["indicator"] for f in u["findings"])


# ---------------------------------------------------------------------------
# Test 8: Non-HTTPS (Plaintext HTTP) Warning
# ---------------------------------------------------------------------------
def test_08_non_https_url():
    u = analyze_url("http://example.org/login")
    assert u["scheme"] == "http"
    assert u["url_risk_score"] >= 20


# ---------------------------------------------------------------------------
# Test 9: Excessive Subdomains in Hostname
# ---------------------------------------------------------------------------
def test_09_excessive_subdomains():
    u = analyze_url("https://account.security.verification.checkpoint.invalid.test/login")
    assert u["subdomain_count"] >= 5
    assert any("Excessive Subdomains" in f["indicator"] for f in u["findings"])


# ---------------------------------------------------------------------------
# Test 10: Suspicious Keywords in URL Path
# ---------------------------------------------------------------------------
def test_10_suspicious_url_keywords():
    u = analyze_url("https://example.com/signin/confirm-password/update")
    assert any("Credential Solicitation Terms" in f["indicator"] for f in u["findings"])


# ---------------------------------------------------------------------------
# Test 11: No URL Handling
# ---------------------------------------------------------------------------
def test_11_no_url():
    u = analyze_url("")
    assert u["url_risk_score"] == 0
    assert u["is_valid"] is False


# ---------------------------------------------------------------------------
# Test 12: Multiple URLs Extraction & Evaluation
# ---------------------------------------------------------------------------
def test_12_multiple_urls():
    res = analyze_email_complete(
        sender="info@example.org",
        subject="Updates",
        body="Visit https://example.org or check backup at http://198.51.100.25/login",
    )
    assert len(res["url_analyses"]) >= 2
    assert any(ua["is_raw_ip"] for ua in res["url_analyses"])


# ---------------------------------------------------------------------------
# Test 13: Normal Attachment (.pdf)
# ---------------------------------------------------------------------------
def test_13_normal_attachment():
    att = analyze_attachment("annual_report.pdf")
    assert att["attachment_risk_score"] == 0
    assert not att["is_double_extension"]


# ---------------------------------------------------------------------------
# Test 14: Executable Attachment (.exe)
# ---------------------------------------------------------------------------
def test_14_executable_attachment():
    att = analyze_attachment("payload.exe")
    assert att["attachment_risk_score"] >= 40
    assert any("Executable" in f["indicator"] for f in att["findings"])


# ---------------------------------------------------------------------------
# Test 15: Double Extension Deception (.pdf.exe)
# ---------------------------------------------------------------------------
def test_15_double_extension():
    att = analyze_attachment("Invoice_March.pdf.exe")
    assert att["is_double_extension"] is True
    assert att["attachment_risk_score"] >= 70
    assert any("Double Extension" in f["indicator"] for f in att["findings"])


# ---------------------------------------------------------------------------
# Test 16: Empty Subject Handling
# ---------------------------------------------------------------------------
def test_16_empty_subject():
    res = analyze_email_complete(
        sender="user@example.org",
        subject="",
        body="This is an informational message with an empty subject."
    )
    assert res["risk_assessment"]["risk_score"] >= 0


# ---------------------------------------------------------------------------
# Test 17: Empty Body Handling
# ---------------------------------------------------------------------------
def test_17_empty_body():
    content = analyze_email_content("Subject", "")
    assert content["content_risk_score"] == 0


# ---------------------------------------------------------------------------
# Test 18: Malformed Sender Address
# ---------------------------------------------------------------------------
def test_18_malformed_sender():
    s = analyze_sender("not-an-email")
    assert s["sender_risk_score"] >= 30
    assert any("Malformed" in f["indicator"] for f in s["findings"])


# ---------------------------------------------------------------------------
# Test 19: High Uppercase Ratio Pressure
# ---------------------------------------------------------------------------
def test_19_high_uppercase_ratio():
    content = analyze_email_content("ALERT", "ACT NOW TO PREVENT IMMEDIATE SUSPENSION OF YOUR SERVICES RIGHT THIS SECOND!")
    assert any("Capitalization" in f["indicator"] for f in content["findings"])


# ---------------------------------------------------------------------------
# Test 20: Multiple Exclamation Marks
# ---------------------------------------------------------------------------
def test_20_multiple_exclamations():
    content = analyze_email_content("Notice", "Do not ignore this warning!!! Your account is at risk!!!")
    assert any("Exclamation" in f["indicator"] for f in content["findings"])


# ---------------------------------------------------------------------------
# Test 21: Score Boundary Clamping (0-100)
# ---------------------------------------------------------------------------
def test_21_score_boundaries():
    # Extremely malicious combination designed to trigger every rule
    res = analyze_email_complete(
        sender="PayPal Security <fraud-alert@paypal-login-verify.invalid.test>",
        subject="URGENT FINAL NOTICE: CONFIRM PASSWORD IMMEDIATELY",
        body="Dear customer, your account has been suspended! Verify your password and ssn immediately at http://198.51.100.10/verify-login or face prosecution!",
        attachment_name="Statement.pdf.exe"
    )
    score = res["risk_assessment"]["risk_score"]
    assert 0 <= score <= 100
    assert score >= 90
    assert res["risk_assessment"]["classification"] == "HIGH RISK / LIKELY PHISHING"


# ---------------------------------------------------------------------------
# Test 22: Database Persistence
# ---------------------------------------------------------------------------
def test_22_database_persistence():
    res = analyze_email_complete(
        sender="billing@company.example.com",
        subject="Test Invoice Persistence",
        body="Hello, here is your regular monthly receipt.",
        attachment_name="receipt.pdf"
    )
    aid = save_analysis(res, "Test Invoice Persistence", "billing@company.example.com", "Hello, here is your regular monthly receipt.", "receipt.pdf")
    assert aid.startswith("ANL-")

    retrieved = get_analysis_by_id(aid)
    assert retrieved is not None
    assert retrieved["subject"] == "Test Invoice Persistence"


# ---------------------------------------------------------------------------
# Test 23: REST API Endpoint Validation (Missing fields)
# ---------------------------------------------------------------------------
def test_23_api_validation(client):
    # Missing required body field
    response = client.post("/api/analyze", json={"sender": "test@example.com"})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Test 24: Machine Learning Inference
# ---------------------------------------------------------------------------
def test_24_ml_prediction():
    phish_pred = predict_phishing_probability("URGENT: Verify your account password immediately to avoid suspension.")
    legit_pred = predict_phishing_probability("Dear students, the campus library will be open 24 hours during finals week.")

    assert phish_pred["is_available"] is True
    assert legit_pred["is_available"] is True
    assert phish_pred["probability"] > legit_pred["probability"]


# ---------------------------------------------------------------------------
# Test 25: Analysis History Retrieval API
# ---------------------------------------------------------------------------
def test_25_history_retrieval(client):
    response = client.get("/api/analyses?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "analyses" in data
    assert isinstance(data["analyses"], list)


# ---------------------------------------------------------------------------
# Test 26: Standalone URL Sandbox API
# ---------------------------------------------------------------------------
def test_26_url_sandbox_api(client):
    response = client.post("/api/analyze/url", json={"url": "http://198.51.100.99/auth-login"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_raw_ip"] is True
    assert data["url_risk_score"] >= 40
