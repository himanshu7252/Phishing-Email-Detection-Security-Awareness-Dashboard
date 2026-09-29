# TECHNICAL PROJECT REPORT

## Title: Phishing Email Detection & Security Awareness Dashboard
**Sub-title:** A Defensive Cybersecurity Engineering & Social Engineering Triage System  
**Author / Security Engineer:** Defensive Security Analyst & Python Engineer  
**Course / Discipline:** Cybersecurity & Applied Machine Learning  
**Target Roles:** SOC Analyst Tier 1/2, Email Security Engineer, Incident Response Analyst, Threat Intelligence Specialist  
**Repository:** `Phishing-Email-Detection-Awareness-Dashboard`  

---

## 1. ABSTRACT
Phishing represents the primary initial access vector (MITRE ATT&CK T1566) across over 80% of modern cyber incidents, encompassing ransomware distribution, financial wire fraud, and credential harvesting. Traditional detection mechanisms rely heavily on static signature matching or simplistic keyword filtering, which are susceptible to evasive modifications such as brand typosquatting, raw IP hosting, double-extension masking, and psychological coercion techniques.

This project introduces **Defender PhishGuard**, an industry-oriented, multi-layered defensive email triage engine and interactive security awareness dashboard. The system evaluates unstructured email payloads across four specialized forensic modules: (1) Sender and Domain Spoofing Analysis, (2) Psychological Content and Social Engineering Detection, (3) Static Lexical URL Analysis, and (4) Static Attachment Filename Inspection. Telemetry from these modules feeds into a calibrated 0–100 Rule-Based Risk Engine and an optional NLP Machine Learning Classifier (Logistic Regression, Naive Bayes, Random Forest) via a Hybrid Ensemble architecture. 

All communications are evaluated in 100% offline, safe sandbox conditions without live network requests, eliminating secondary exploitation risks. The system persists forensic audit metadata to an SQLite relational database, visualizes threat metrics via a dark-mode glassmorphic SOC dashboard, and delivers interactive awareness training through an interactive "Before You Click" checklist and simulation lab. Automated unit testing with `pytest` verifies 26 distinct operational conditions with 100% pass rates.

---

## 2. PROBLEM STATEMENT & CYBERSECURITY OBJECTIVES
### 2.1 The Threat Landscape
Modern email threat actors exploit human cognitive biases—specifically scarcity, fear, authority, and greed—to bypass conventional perimeter protections. Attackers employ evasive infrastructure tactics, including:
- Registering lookalike domains (typosquatting and brand-in-name spoofing)
- Leveraging numeric raw IP addresses to bypass domain reputation filters
- Employing URL shorteners and deep subdomains to mask destination destinations
- Concealing executable payloads behind double extensions (e.g. `Invoice.pdf.exe`)

### 2.2 System Objectives
1. **Defensive Safety:** Perform complete threat extraction statically without executing untrusted code or initiating web requests to potential command-and-control (C2) domains.
2. **Multi-Vector Threat Correlation:** Correlate signals from sender headers, linguistic markers, hyperlink architectures, and attachment metadata.
3. **Explainable AI & Security Triage:** Provide clear, human-understandable evidence for every score rather than a binary "black-box" decision.
4. **Actionable SOC Playbooks:** Automatically generate incident response recommendations for security operations center (SOC) analysts.
5. **Interactive Awareness Education:** Reinforce user resilience through interactive checklists and gamified scenario challenges.

---

## 3. SYSTEM ARCHITECTURE & DATA FLOW
The platform utilizes a modular, decoupled architecture consisting of an ASGI REST API backend (FastAPI), an SQLite persistence layer, and a Vanilla JS/CSS dark cyber dashboard.

```
       [ User / SOC Analyst / Learner ]
                      │
                      ▼
         [ Web Dashboard (Frontend) ]
         - Real-time Email Triage Form
         - SOC Analytics & Metric Cards
         - Static URL Sandbox Inspector
         - Relational Audit Log Table
         - Awareness Challenge Simulator
                      │
                      ▼ (HTTP POST / REST API)
    ┌─────────────────┴─────────────────┐
    │       FastAPI Application         │
    │  (Routes, Validation, CORS, Rate)  │
    └─────────────────┬─────────────────┘
                      │
         [ Preprocessing Pipeline ]
         - Regex URL & Email Extraction
         - Safe MIME / RFC 822 Parsing
         - Case, Punctuation & Length Metrics
                      │
    ┌─────────────────┴─────────────────┐
    │     Modular Forensic Analyzers    │
    │  1. Sender & Lookalike Analyzer   │
    │  2. Content & Urgency Analyzer    │
    │  3. Static Offline URL Analyzer   │
    │  4. Attachment Filename Analyzer  │
    └─────────────────┬─────────────────┘
                      │
       [ Feature Engineering Pipeline ]
       - 18+ Structured Vector Features
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
     - Tier: SAFE | LOW RISK | SUSPICIOUS | HIGH RISK
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

## 4. DETAILED METHODOLOGY & COMPONENT IMPLEMENTATION

### 4.1 Sender Analysis Engine (`backend/services/sender_analyzer.py`)
Analyzes RFC 5322 sender formats and domain structures:
- **Display Name / Brand Mismatch:** Compares the visible display name against recognized high-value enterprise brands (Microsoft, PayPal, Apple, Amazon, Chase). If the display name references a brand but the sending domain is unrelated, a HIGH-severity spoofing finding is generated (+35 risk).
- **Executive Role via Free Webmail:** Detects executive titles (CEO, CFO, HR Director) paired with public consumer webmail domains (Gmail, Yahoo, Hotmail).
- **Excessive Subdomain Depth:** Flags domains containing four or more dot-separated labels (+20 risk).
- **Deceptive Keyword Ingestion:** Identifies suspicious hyphenated security tokens in domain names (`-verify`, `-security`, `-auth`, `-wire`).

### 4.2 Content & Social Engineering Analyzer (`backend/services/content_analyzer.py`)
Detects cognitive manipulation vectors using regular expression patterns across seven distinct categories:
1. **Urgency & Artificial Time Constraints:** Words enforcing immediate deadlines (`within 24 hours`, `immediately`, `critical alert`).
2. **Fear, Intimidation & Suspension Coercion:** Explicit threats of deactivation, service termination, or legal prosecution.
3. **Credential Harvesting:** Explicit solicitations for passwords, PINs, or authentication tokens.
4. **Financial Coercion & Fraudulent Billing:** Overdue balances, unapproved invoices, or wire transfers.
5. **Reward & Giveaway Lures:** Unsolicited lottery, crypto giveaway, or bonus offers.
6. **Personally Identifiable Information (PII) Harvesting:** Social Security Numbers, banking details, or identity document copies.
7. **Depersonalized Salutations:** Impersonal openers (`Dear Customer`, `Attention Staff`).
8. **Linguistic Pressure:** Uppercase character ratios exceeding 25% and multiple exclamation marks (`!!!`).

### 4.3 Static URL Analyzer (`backend/services/url_analyzer.py`)
Strictly adheres to defensive security hygiene by parsing hyperlink strings without initiating network calls:
- **Raw IP Address Usage:** Detects numerical IPv4 hostnames (e.g. `http://198.51.100.10/verify-account`). Hostnames resolving directly to IPs receive a CRITICAL risk penalty (+40 points).
- **URL Shortener Pattern Recognition:** Detects domains matching known shortener services (`bit.ly`, `tinyurl.com`, `t.co`) used to evade email gateway reputation checks.
- **Protocol Evaluation:** Flags unencrypted HTTP transmissions while educating analysts that modern phishing campaigns frequently provision valid HTTPS certificates.
- **Credential Path Patterns:** Scans path and query components for credential-harvesting tokens (`/signin`, `/auth`, `/password-reset`).

### 4.4 Attachment Filename Analyzer (`backend/services/attachment_analyzer.py`)
Inspects file extensions without executing binaries:
- **Dangerous Extensions:** Flags direct executables (`.exe`, `.scr`, `.bat`, `.cmd`, `.js`, `.vbs`, `.ps1`, `.hta`, `.jar`, `.iso`).
- **Double Extension Deception:** Detects patterns such as `invoice.pdf.exe` or `contract.docx.vbs` designed to exploit default Windows configurations that hide known file extensions.
- **Compressed Archive Scrutiny:** Identifies `.zip` and `.rar` containers commonly used to deliver evasive malware.

### 4.5 Feature Engineering (`backend/services/feature_extractor.py`)
Extracts 18 structured, numerical and categorical features:
`urgent_keyword_count`, `credential_keyword_count`, `financial_keyword_count`, `threat_keyword_count`, `url_count`, `suspicious_url_count`, `has_ip_url`, `has_shortened_url_pattern`, `sender_domain_length`, `subdomain_count`, `suspicious_attachment`, `generic_greeting`, `contains_password_request`, `contains_personal_info_request`, `exclamation_count`, `uppercase_ratio`, `body_length`, `subject_length`.

### 4.6 Rule-Based Scoring Engine (`backend/services/risk_engine.py`)
Computes an accumulated score capped at 0–100 based on weighted forensic signals:
- **0–20:** `SAFE` (Normal communication)
- **21–40:** `LOW RISK` (Atypical elements, standard caution)
- **41–70:** `SUSPICIOUS` (Multiple threat markers, manual triage advised)
- **71–100:** `HIGH RISK / LIKELY PHISHING` (Immediate containment recommended)

### 4.7 Machine Learning Classifier (`ml/train_model.py`)
Trained on 600 synthetic records (300 legitimate, 300 phishing):
- Vectorization: Sublinear TF-IDF with unigrams and bigrams (`ngram_range=(1,2)`, `max_features=2500`).
- Models Evaluated:
  - **Logistic Regression:** Accuracy: 1.0000, Precision: 1.0000, Recall: 1.0000, F1: 1.0000 (Selected)
  - **Multinomial Naive Bayes:** Accuracy: 1.0000, Precision: 1.0000, Recall: 1.0000, F1: 1.0000
  - **Random Forest Classifier:** Accuracy: 1.0000, Precision: 1.0000, Recall: 1.0000, F1: 1.0000

### 4.8 Hybrid Ensemble Architecture (`backend/services/hybrid_engine.py`)
Blends deterministic rule heuristics (55% weight) with probabilistic ML inferences (45% weight):
$$\text{Hybrid Score} = (0.55 \times \text{Rule Score}) + (0.45 \times \text{ML Probability})$$
Includes a safety override: If rules identify a CRITICAL technical compromise (e.g. raw IP URL or weaponized double extension), the hybrid score is locked to $\ge 75$, preventing benign-sounding text from masking an active technical exploit.

---

## 5. MITRE ATT&CK FRAMEWORK MAPPING
The system maps identified indicators directly to the MITRE ATT&CK knowledge base:
- **T1566 - Phishing (Initial Access):**
  - **T1566.001 - Spearphishing Attachment:** Detected via static attachment analysis (`.exe`, `.scr`, `.pdf.exe`).
  - **T1566.002 - Spearphishing Link:** Detected via static URL inspection (raw IPs, credential path tokens, unencrypted schemes).
  - **T1566.003 - Spearphishing via Service:** Detected via sender analysis (free webmail masquerading as corporate executives).

---

## 6. SOC ANALYST TRIAGE PLAYBOOK
When an email alert triggers on the dashboard:
1. **Initial Triage:** Analyst reviews the overall Risk Score and Classification Badge.
2. **Sender Forensic Review:** Inspect sender domain and display name consistency.
3. **URL Sandboxing:** Review static URL flags. Verify if links point to IP addresses or redirectors.
4. **Attachment Safety:** Verify whether double extensions or script formats are present.
5. **Disposition & Mitigation:**
   - If `SAFE`: Close ticket as benign.
   - If `SUSPICIOUS`: Contact sender out-of-band to verify legitimacy.
   - If `HIGH RISK`: Block sender domain at Secure Email Gateway (SEG), add URL/IP to firewall blocklists, and notify users who received matching messages.

---

## 7. AUTOMATED VERIFICATION & TEST RESULTS
The project includes a 26-test automated verification suite (`tests/test_detection_suite.py`) executed via `pytest`:
- Legitimate email classification: **PASSED**
- Urgent credential phishing detection: **PASSED**
- Financial coercion keyword extraction: **PASSED**
- Generic greeting detection: **PASSED**
- Raw IP URL detection: **PASSED**
- Non-HTTPS HTTP warning: **PASSED**
- Excessive subdomain detection: **PASSED**
- Executable binary attachment detection: **PASSED**
- Double extension deception detection: **PASSED**
- Empty subject/body edge cases: **PASSED**
- Malformed sender handling: **PASSED**
- Score boundary clamping (0–100): **PASSED**
- SQLite persistence & relational retrieval: **PASSED**
- REST API validation & error handling: **PASSED**
- Machine learning probability inference: **PASSED**
- **Test Summary:** 26 passed, 0 failed (100% pass rate).

---

## 8. SECURITY & PRIVACY CONSIDERATIONS
1. **No External Network Calls:** The URL analyzer does not resolve DNS or send HTTP requests.
2. **No Payload Execution:** Attachments are inspected purely through filename metadata.
3. **Privacy by Design:** Full email bodies are not retained permanently in SQLite; only truncated 150-character previews and metadata are stored.
4. **Input Sanitization:** HTML escaping is applied to all user input before DOM rendering to prevent Cross-Site Scripting (XSS).
5. **Defensive RFC Conformance:** All synthetic training samples use RFC 2606 reserved domains (`example.com`, `invalid.test`) and RFC 5737 documentation IPs (`198.51.100.0/24`).

---

## 9. LIMITATIONS & FUTURE SCOPE
- **Email Header Ingestion:** Future iterations will parse full raw email headers to ingest SPF, DKIM, and DMARC authentication verification results.
- **Threat Intelligence Enrichment:** Integration with open-source threat intelligence feeds (e.g. AlienVault OTX, URLhaus) via offline caching.
- **Transformer NLP Models:** Upgrading text classification to fine-tuned transformer architectures (e.g., RoBERTa or DistilBERT) for improved contextual comprehension.

---

## 10. CONCLUSION
**Defender PhishGuard** demonstrates that combining explainable, rule-based cybersecurity heuristics with machine learning text classification yields a resilient defense-in-depth security tool. By prioritizing explainability, defensive sandboxing, and interactive user education, the project provides an exceptional proof of work for junior cybersecurity and SOC engineering roles.
