# Phishing Email Detection & Security Awareness Dashboard
> **Industry-Oriented Defensive Cybersecurity Platform | SOC Analyst Triage Engine | Explainable Threat Intelligence**

![Python](https://img.shields.io/badge/Python-3.11-blue.svg?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg?logo=fastapi)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3-F7931E.svg?logo=scikitlearn)
![Security](https://img.shields.io/badge/Defense--in--Depth-Defensive%20Only-emerald.svg)
![Tests](https://img.shields.io/badge/Tests-26%20Passed%20(100%25)-success.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

---

## 1. Overview
**Defender PhishGuard** is an industry-grade, defensive cybersecurity project designed for Security Operations Center (SOC) tier-1/2 analysts, email security specialists, and security awareness teams. It analyzes unstructured email content, sender patterns, hyperlinks, and attachment filenames to compute an explainable **Phishing Risk Score (0–100)** and actionable classification tier (`SAFE`, `LOW RISK`, `SUSPICIOUS`, or `HIGH RISK / LIKELY PHISHING`).

Built around **explainable cybersecurity**, the platform does not simply output a black-box label. Instead, it itemizes forensic indicators (e.g. raw IP hosting, brand typosquatting, credential harvesting, double extension spoofing), maps them to the **MITRE ATT&CK Framework (T1566)**, generates automated SOC response procedures, and delivers interactive security awareness training.

---

## 2. Problem Statement
Over 80% of corporate data breaches originate from phishing and social engineering lures. Threat actors weaponize urgency, financial intimidation, and lookalike domains to bypass static filters. Security teams require tools that:
1. Conduct multi-vector forensic triage safely without executing attachments or making live requests to hostile links.
2. Provide transparent, explainable evidence so analysts can justify incident escalation.
3. Bridge defensive engineering with user awareness education to build human firewall resilience.

---

## 3. Key Features
- **Multi-Vector Forensic Engine:** Correlates sender headers, display name mismatches, linguistic coercion, static URL characteristics, and attachment filenames.
- **Safe Static URL Sandbox:** Deconstructs URLs without network calls, flagging raw IP addresses (`http://198.51.100.10`), URL shorteners, and credential paths.
- **Attachment Deception Detection:** Unmasks weaponized extensions (`.exe`, `.scr`, `.bat`, `.vbs`, `.ps1`) and double extensions (`invoice.pdf.exe`).
- **Hybrid AI Detection:** Combines calibrated, deterministic rules (55% weight) with NLP machine learning text probabilities (45% weight).
- **MITRE ATT&CK Mapping:** Automatically maps identified threats to sub-techniques `T1566.001` (Attachment), `T1566.002` (Link), and `T1566.003` (Service).
- **Dark-Mode SOC Dashboard:** Real-time visual metrics powered by Chart.js, featuring classification donuts, indicator frequencies, and risk distributions.
- **Relational Forensic Audit Log:** SQLite database persists analysis metadata, search filters, and single-record deep inspection.
- **Interactive Security Awareness Lab:** Features an interactive "Before You Click" checklist and a gamified scenario challenge.
- **Automated Verification:** 26 automated unit and security tests with 100% pass rates.

---

## 4. Architecture & Workflow
```
[ User Input / Sample Email / .EML Upload ]
                      │
                      ▼
            [ Preprocessing ]
  - Safe MIME Parser | Regex URL & Sender Extractor
                      │
   ┌──────────────────┴──────────────────┐
   │         Forensic Analyzers          │
   │ 1. Sender & Brand Lookalike         │
   │ 2. Social Engineering & Urgency     │
   │ 3. Static Offline URL Inspector     │
   │ 4. Attachment Filename Deception    │
   └──────────────────┬──────────────────┘
                      │
        [ 18+ Feature Extraction ]
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
 [ Rule-Based Risk Engine ]  [ NLP ML Classifier ]
 (Calibrated Heuristics)    (TF-IDF + Logistic Reg)
         │                         │
         └────────────┬────────────┘
                      ▼
          [ Hybrid Ensemble Engine ]
       Weighted Synthesis: 55% Rules + 45% ML
                      │
                      ▼
     [ Explainable Threat Classification ]
     - Risk Score: 0–100
     - Classification Tier
     - Triggered Indicator Telemetry
     - MITRE ATT&CK Sub-technique Tags
     - Actionable Defensive SOP Playbook
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
 [ SQLite Database ]       [ Live Dashboard ]
 (Audit Log & Forensics)   (Real-Time Visualization)
```

---

## 5. Technology Stack
- **Backend:** Python 3.11, FastAPI, Uvicorn, Pydantic v2
- **Data & Machine Learning:** Scikit-Learn, Pandas, NumPy, Joblib
- **Persistence:** SQLite3 (WAL mode, relational foreign keys)
- **Frontend:** Vanilla HTML5, Modern CSS (Glassmorphism, Dark Cyber Theme), JavaScript (ES6+)
- **Visuals & Icons:** Chart.js 4.4, Lucide Icons
- **Testing:** Pytest, HTTPX

---

## 6. Phishing Indicators Evaluated

| Component | Threat Indicator | Cybersecurity Risk Rationale |
|---|---|---|
| **Sender** | Display Name / Brand Mismatch | Brand spoofing impersonating Microsoft, PayPal, Chase, etc. |
| **Sender** | Free Webmail for Executive Role | Corporate/CEO authority claimed using public consumer webmail |
| **Sender** | Excessive Subdomains | Deep subdomain nesting (`a.b.c.d.invalid.test`) |
| **Content** | Urgency & Artificial Deadlines | Time pressure (`within 24 hours`) bypasses critical review |
| **Content** | Fear & Suspension Coercion | Threats of account termination, legal fines, or police action |
| **Content** | Direct Credential Solicitation | Passwords, PINs, or MFA keys solicited via email links |
| **Content** | Financial Coercion | Overdue invoices, wire transfer orders, or unpaid balances |
| **Content** | Generic / Impersonal Greeting | Mass templates lacking recipient name (`Dear Customer`) |
| **URL** | Raw IP Hostname | Numeric IPs (`http://198.51.100.10`) bypass domain reputation |
| **URL** | Shortener Pattern | Services (`bit.ly`, `tinyurl`) masking true destinations |
| **URL** | Plaintext HTTP Scheme | Login forms sent over unencrypted channels |
| **Attachment** | Weaponized Extension | Executables (`.exe`, `.scr`, `.bat`, `.ps1`, `.vbs`, `.js`) |
| **Attachment** | Double Extension Deception | Exploits default Windows hidden extensions (`file.pdf.exe`) |

---

## 7. Machine Learning & Model Evaluation
Models were trained and evaluated on 600 synthetic records (300 legitimate, 300 phishing) using sublinear TF-IDF vectorization:

| Model Architecture | Accuracy | Precision | Recall | F1-Score | Status |
|---|---|---|---|---|---|
| **Logistic Regression** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **Selected Best** |
| **Multinomial Naive Bayes** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Candidate |
| **Random Forest** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Candidate |

### Why Recall Matters Most in Phishing Defense:
- **False Negative (Missed Attack):** Catastrophic. A malicious email reaches the inbox, resulting in credential compromise, malware execution, or ransomware.
- **False Positive (Benign Flagged):** Causes analyst alert fatigue and employee disruption. High precision keeps noise low, while high recall guarantees protection.

---

## 8. Installation & Quick Start

### Step 1: Clone Repository
```bash
git clone https://github.com/yourusername/Phishing-Email-Detection-Awareness-Dashboard.git
cd Phishing-Email-Detection-Awareness-Dashboard
```

### Step 2: Create & Activate Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Generate Synthetic Dataset
```bash
python data/generate_dataset.py
```

### Step 5: Train Machine Learning Model
```bash
python ml/train_model.py
```

### Step 6: Start Web Dashboard Server
```bash
python backend/app.py
```
Open your browser to:
- **Web Dashboard:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive OpenAPI Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 9. Automated Testing
Run the complete automated security test suite:
```bash
pytest tests/test_detection_suite.py -v
```
**Results:** `26 passed in 2.18s (100% success rate)`.

---

## 10. Demonstration Walkthrough

### Scenario A: Phishing Attack (High Risk)
- **Sender:** `Security Alert <security-alert@account-check.invalid.test>`
- **Subject:** `URGENT: Your Account Has Been Suspended Due to Unauthorized Activity`
- **Body:** `Dear Valued Customer, we detected unauthorized logins. Verify password immediately: http://198.51.100.10/verify-account`
- **Attachment:** `Security_Verification_Guide.pdf.exe`
- **Expected Assessment:**
  - **Risk Score:** `86–96 / 100`
  - **Classification:** `HIGH RISK / LIKELY PHISHING`
  - **Indicators:** Credential Request, Urgent Language, Raw IP URL, Double Extension.
  - **MITRE Tags:** `T1566.001` (Attachment), `T1566.002` (Link).

### Scenario B: Legitimate Email (Safe)
- **Sender:** `Registrar <registrar@university.example.edu>`
- **Subject:** `Spring Semester Course Registration Schedule Announced`
- **Body:** `Dear Student, please review the academic calendar at https://portal.university.example.edu/records.`
- **Attachment:** `course_schedule.pdf`
- **Expected Assessment:**
  - **Risk Score:** `0–20 / 100`
  - **Classification:** `SAFE`

---

## 11. Security & Ethical Disclaimer
> **DEFENSIVE CYBERSECURITY NOTICE:**  
> This project is designed exclusively for cybersecurity education, academic research, and defensive threat triage. All domains used (`example.com`, `invalid.test`) are RFC 2606 reserved domains. All IP addresses (`198.51.100.10`) reside within RFC 5737 documentation ranges. This tool does not perform live network requests, host credential-harvesting pages, or execute malicious attachments.

---

## 12. Author & Portfolio Proof
- **Role:** Defensive Cybersecurity Engineer & SOC Analyst Candidate  
- **Core Skills:** SOC Operations, Threat Scoring, Social Engineering Detection, Python, NLP, FastAPI, SQLite  
- **Project Repository:** [Phishing-Email-Detection-Awareness-Dashboard](https://github.com/yourusername/Phishing-Email-Detection-Awareness-Dashboard)
