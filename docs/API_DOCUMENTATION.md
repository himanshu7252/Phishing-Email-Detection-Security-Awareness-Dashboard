# REST API DOCUMENTATION

## Defender PhishGuard: Phishing Detection & Security Awareness API
**Base URL:** `http://127.0.0.1:8000`  
**Interactive Swagger UI:** `http://127.0.0.1:8000/docs`  
**OpenAPI Specification:** `http://127.0.0.1:8000/openapi.json`  

---

### Endpoints Overview

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status check |
| `POST` | `/api/analyze` | Multi-vector email phishing analysis & risk scoring |
| `POST` | `/api/analyze/url` | Offline static URL inspection sandbox |
| `POST` | `/api/analyze/file` | Safe upload & parsing of `.eml` or `.txt` email files |
| `GET` | `/api/analyses` | Paginated forensic audit log history |
| `GET` | `/api/analyses/{id}` | Detailed forensic record by audit ID |
| `DELETE` | `/api/analyses/{id}` | Remove forensic record from database |
| `GET` | `/api/dashboard/stats` | High-level SOC metrics, distributions & top indicators |
| `GET` | `/api/samples` | Curated educational demonstration samples |

---

### Detailed Endpoints

#### 1. Analyze Email (`POST /api/analyze`)
Performs complete threat triage across sender, content, URLs, and attachments.
- **Request Body (JSON):**
  ```json
  {
    "sender": "Security Desk <alert@account-check.invalid.test>",
    "subject": "URGENT: Verify Your Account Immediately",
    "body": "Dear customer, your account will be suspended unless you verify credentials now at http://198.51.100.10/verify.",
    "attachment_name": "Invoice.pdf.exe",
    "urls": "",
    "enable_hybrid": true
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "analysis_id": "ANL-9382AB12",
    "final_risk_score": 86,
    "classification": "HIGH RISK / LIKELY PHISHING",
    "classification_color": "danger",
    "hybrid_assessment": {
      "is_hybrid": true,
      "hybrid_risk_score": 86,
      "rule_score": 88,
      "ml_probability_pct": 100.0,
      "ml_predicted_label": "PHISHING"
    },
    "risk_assessment": {
      "risk_score": 88,
      "classification": "HIGH RISK / LIKELY PHISHING",
      "indicator_summary": [
        {
          "category": "Social Engineering",
          "title": "Credential Solicitation Detected",
          "severity": "CRITICAL"
        }
      ],
      "recommendations": [
        "DO NOT click any hyperlinks or embedded buttons within this message.",
        "DO NOT open unexpected attachments."
      ],
      "mitre_attack": [
        {
          "id": "T1566.002",
          "name": "Phishing: Spearphishing Link",
          "tactic": "Initial Access"
        }
      ]
    }
  }
  ```

#### 2. Static URL Inspection (`POST /api/analyze/url`)
- **Request Body (JSON):**
  ```json
  {
    "url": "http://198.51.100.10/verify-account"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "url": "http://198.51.100.10/verify-account",
    "is_valid": true,
    "scheme": "http",
    "hostname": "198.51.100.10",
    "is_raw_ip": true,
    "is_shortener": false,
    "url_risk_score": 60,
    "findings": [
      {
        "severity": "MEDIUM",
        "indicator": "Unencrypted HTTP Scheme"
      },
      {
        "severity": "CRITICAL",
        "indicator": "Raw IP Address as Hostname"
      }
    ]
  }
  ```

#### 3. Upload Email File (`POST /api/analyze/file`)
- **Form-Data:** `file` (`.eml` or `.txt` format, max 2MB)
- **Response (200 OK):**
  ```json
  {
    "filename": "suspicious_alert.eml",
    "parsed_email": {
      "sender": "alert@invalid.test",
      "subject": "Action Required",
      "body": "Please login to your portal...",
      "attachment_name": ""
    },
    "message": "File parsed successfully. Ready for inspection."
  }
  ```

#### 4. SOC Dashboard Statistics (`GET /api/dashboard/stats`)
- **Response (200 OK):**
  ```json
  {
    "total_analyzed": 18,
    "high_risk_count": 8,
    "suspicious_count": 0,
    "low_risk_count": 0,
    "safe_count": 10,
    "average_risk_score": 39.7,
    "classification_distribution": {
      "SAFE": 10,
      "LOW RISK": 0,
      "SUSPICIOUS": 0,
      "HIGH RISK / LIKELY PHISHING": 8
    },
    "top_indicators": [
      { "title": "Artificial Urgency & Time Pressure", "category": "Social Engineering", "freq": 8 }
    ]
  }
  ```
