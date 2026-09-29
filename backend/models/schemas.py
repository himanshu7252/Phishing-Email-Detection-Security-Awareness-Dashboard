"""
=============================================================================
Module: backend.models.schemas
=============================================================================
Pydantic Schemas for Request Validation and Response Contracts.
=============================================================================
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class EmailAnalysisRequest(BaseModel):
    sender: str = Field(..., description="From sender line or email address")
    subject: str = Field("", description="Subject of the email")
    body: str = Field(..., description="Body text content of the email")
    attachment_name: Optional[str] = Field("", description="Filename of any attached file")
    urls: Optional[str] = Field("", description="Explicit URL list (comma-separated or empty to auto-extract)")
    enable_hybrid: bool = Field(True, description="Enable hybrid rule-based + ML ensemble scoring")


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="Target URL string to statically inspect")


class FindingSchema(BaseModel):
    category: Optional[str] = "General"
    severity: str
    indicator: str
    explanation: str
    matched_terms: Optional[List[str]] = []


class AnalysisResponse(BaseModel):
    analysis_id: Optional[str] = None
    risk_score: int
    classification: str
    classification_color: str
    is_hybrid: bool = False
    rule_score: Optional[int] = None
    ml_score_pct: Optional[float] = None
    ml_predicted_label: Optional[str] = None
    hybrid_divergence_note: Optional[str] = None
    indicator_summary: List[Dict[str, Any]]
    recommendations: List[str]
    mitre_attack: List[Dict[str, Any]]
    sender_analysis: Dict[str, Any]
    content_analysis: Dict[str, Any]
    url_analyses: List[Dict[str, Any]]
    attachment_analysis: Dict[str, Any]
    features: Dict[str, Any]


class DashboardStatsResponse(BaseModel):
    total_analyzed: int
    high_risk_count: int
    suspicious_count: int
    low_risk_count: int
    safe_count: int
    average_risk_score: float
    classification_distribution: Dict[str, int]
    top_indicators: List[Dict[str, Any]]
    recent_activity: List[Dict[str, Any]]
