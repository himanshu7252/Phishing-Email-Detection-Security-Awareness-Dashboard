"""
=============================================================================
Module: backend.app
=============================================================================
FastAPI Application & REST API Gateway for Phishing Email Detection Dashboard.

FEATURES:
- Live Email Analysis & Threat Scoring
- Isolated Static URL Inspection Sandbox
- Safe File Upload Parser (.eml / .txt)
- Aggregated SOC Analytics & Metric Reporting
- Relational Audit Log History Storage (SQLite)
- Built-in Curated Educational Email Samples
- Single-command full-stack server serving the cybersecurity frontend UI
=============================================================================
"""

import os
import sys
# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from typing import Optional, List, Dict, Any

from backend.models.schemas import EmailAnalysisRequest, URLAnalysisRequest
from backend.services.risk_engine import analyze_email_complete
from backend.services.hybrid_engine import compute_hybrid_assessment
from backend.services.url_analyzer import analyze_url
from backend.utils.preprocessor import parse_eml_content
from backend.database import (
    init_db, save_analysis, get_all_analyses,
    get_analysis_by_id, delete_analysis, get_dashboard_statistics
)

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database on startup
    init_db()
    yield

# Initialize application
app = FastAPI(
    title="Phishing Email Detection & Security Awareness API",
    description="Defensive cybersecurity API for analyzing email indicators, URLs, and social engineering vectors.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health", tags=["System"])
def health_check():
    """Health check endpoint confirming API operational status."""
    return {"status": "healthy", "service": "Phishing Detection Engine", "version": "1.0.0"}


@app.post("/api/analyze", tags=["Detection"])
def analyze_email(req: EmailAnalysisRequest):
    """
    Analyzes an email payload for phishing indicators, deceptive URLs,
    weaponized attachments, and psychological coercion techniques.
    """
    try:
        # 1. Run complete rule-based analysis
        result = analyze_email_complete(
            sender=req.sender,
            subject=req.subject,
            body=req.body,
            attachment_name=req.attachment_name or "",
            urls_input=req.urls or ""
        )

        # 2. Run hybrid evaluation if enabled
        combined_text = f"{req.subject}\n{req.body}"
        if req.enable_hybrid:
            hybrid_eval = compute_hybrid_assessment(result["risk_assessment"], combined_text)
            result["hybrid_assessment"] = hybrid_eval
            final_risk = hybrid_eval["hybrid_risk_score"]
            classification = hybrid_eval["classification"]
            classification_color = hybrid_eval["classification_color"]
        else:
            result["hybrid_assessment"] = {
                "is_hybrid": False,
                "hybrid_risk_score": result["risk_assessment"]["risk_score"],
                "rule_score": result["risk_assessment"]["risk_score"],
                "ml_probability_pct": None,
                "classification": result["risk_assessment"]["classification"],
                "classification_color": result["risk_assessment"]["classification_color"],
                "divergence_note": "Rule-based analysis mode."
            }
            final_risk = result["risk_assessment"]["risk_score"]
            classification = result["risk_assessment"]["classification"]
            classification_color = result["risk_assessment"]["classification_color"]

        # 3. Persist safe forensic metadata to database
        analysis_id = save_analysis(
            full_result=result,
            subject=req.subject,
            sender_raw=req.sender,
            body=req.body,
            attachment_name=req.attachment_name or ""
        )
        result["analysis_id"] = analysis_id
        result["final_risk_score"] = final_risk
        result["classification"] = classification
        result["classification_color"] = classification_color

        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline error: {str(e)}"
        )


@app.post("/api/analyze/url", tags=["Sandbox"])
def analyze_single_url(req: URLAnalysisRequest):
    """
    Statically analyzes a single target URL without initiating network connections.
    """
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL parameter cannot be empty.")
    
    analysis = analyze_url(req.url.strip())
    return analysis


@app.post("/api/analyze/file", tags=["File Ingestion"])
async def analyze_email_file(file: UploadFile = File(...)):
    """
    Safely parses an uploaded RFC 822 (.eml) or text (.txt) email file without executing scripts.
    """
    filename = file.filename.lower()
    if not (filename.endswith(".eml") or filename.endswith(".txt")):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format. Please upload standard .eml or .txt email files."
        )

    content_bytes = await file.read()
    if len(content_bytes) > 2_000_000: # 2MB defensive limit
        raise HTTPException(status_code=400, detail="File size exceeds maximum 2MB security threshold.")

    parsed_data = parse_eml_content(content_bytes)
    return {
        "filename": file.filename,
        "parsed_email": parsed_data,
        "message": "File parsed successfully. Ready for inspection."
    }


@app.get("/api/analyses", tags=["History & Audit"])
def get_analyses_history(
    classification: Optional[str] = Query(None, description="Filter by classification tier"),
    search: Optional[str] = Query(None, description="Search term for subject or sender"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """Retrieves paginated historical triage records."""
    records = get_all_analyses(classification=classification, search=search, limit=limit, offset=offset)
    return {"count": len(records), "analyses": records}


@app.get("/api/analyses/{analysis_id}", tags=["History & Audit"])
def get_single_analysis(analysis_id: str):
    """Retrieves complete details for a specific analysis record."""
    record = get_analysis_by_id(analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    return record


@app.delete("/api/analyses/{analysis_id}", tags=["History & Audit"])
def delete_single_analysis(analysis_id: str):
    """Removes an analysis record from the historical audit log."""
    success = delete_analysis(analysis_id)
    if not success:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    return {"success": True, "message": f"Record {analysis_id} deleted."}


@app.get("/api/dashboard/stats", tags=["SOC Dashboard"])
def get_dashboard_stats():
    """Computes aggregated statistics for the SOC Dashboard."""
    return get_dashboard_statistics()


@app.get("/api/samples", tags=["Education & Samples"])
def get_sample_scenarios():
    """Returns curated educational sample emails for one-click testing."""
    return [
        {
            "id": "sample-phish-urgent",
            "title": "Credential Harvest: Urgent Account Suspension",
            "category": "HIGH RISK / LIKELY PHISHING",
            "sender": "Security Operations <security-alert@account-check.invalid.test>",
            "subject": "URGENT: Your Account Has Been Suspended Due to Unauthorized Activity",
            "body": "Dear Valued Customer,\n\nWe detected multiple unauthorized login attempts to your corporate account from an unknown IP address. To prevent permanent suspension, you must verify your identity immediately. Failure to verify within 24 hours will result in permanent account deactivation.\n\nClick the link below to verify your password and identity now:\nhttp://198.51.100.10/verify-account\n\nDo not ignore this message. Your security is at risk.\n\nCustomer Support Team",
            "attachment_name": "Security_Verification_Guide.pdf.exe",
            "urls": "http://198.51.100.10/verify-account"
        },
        {
            "id": "sample-phish-invoice",
            "title": "Financial Fraud: Past-Due Overdue Invoice",
            "category": "HIGH RISK / LIKELY PHISHING",
            "sender": "Accounting Dept <billing@financial-records.invalid.test>",
            "subject": "OVERDUE INVOICE #89421: Immediate Payment Required to Avoid Collections",
            "body": "Attention Accounts Payable,\n\nAttached is the overdue invoice #89421 totaling $4,850.00. Payment is 45 days past due. If funds are not received within 24 hours, this case will be transferred to our legal collections agency with penalty fees applied.\n\nUpdate billing profile and download statement:\nhttp://urgent-invoice-portal.invalid.test/settle\n\nAccounting Department",
            "attachment_name": "Overdue_Statement.js",
            "urls": "http://urgent-invoice-portal.invalid.test/settle"
        },
        {
            "id": "sample-legit-university",
            "title": "Legitimate: University Course Registration",
            "category": "SAFE",
            "sender": "Dr. Robert Davis <registrar@university.example.edu>",
            "subject": "Spring Semester Course Registration Schedule Announced",
            "body": "Dear Student,\n\nPlease review the updated academic calendar for the upcoming semester. Registration appointment windows have been posted to your student self-service portal at https://portal.university.example.edu/records. If you have any advising holds, please contact your faculty advisor before the deadline.\n\nBest regards,\nOffice of the Registrar",
            "attachment_name": "course_schedule.pdf",
            "urls": "https://portal.university.example.edu/records"
        },
        {
            "id": "sample-legit-hr",
            "title": "Legitimate: HR Benefits Open Enrollment",
            "category": "SAFE",
            "sender": "Alice Chen (HR Department) <hr-notifications@example.org>",
            "subject": "Open Enrollment Period: Health and Wellness Benefits 2026",
            "body": "Dear Team Members,\n\nOur annual benefits open enrollment is now active and will remain open through the 15th of next month. You can review available plan options, compare coverage, and update dependents by visiting our intranet portal at https://workforce.example.org/benefits. If no changes are needed, your current selections will automatically roll over.\n\nSincerely,\nHuman Resources Benefits Team",
            "attachment_name": "benefits_summary_2026.pdf",
            "urls": "https://workforce.example.org/benefits"
        }
    ]


# ---------------------------------------------------------------------------
# Mount Frontend Static Assets
# ---------------------------------------------------------------------------
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
def serve_index():
    index_file = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Phishing Detection Dashboard API online. Frontend index.html not found."}


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*70)
    print("  PHISHING EMAIL DETECTION & AWARENESS DASHBOARD SERVER")
    print("  Defensive Cybersecurity Platform (SOC Analyst & Educational Lab)")
    print("="*70)
    print("  [+] Web Dashboard:  http://127.0.0.1:8000")
    print("  [+] API Docs:       http://127.0.0.1:8000/docs")
    print("="*70 + "\n")
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)
