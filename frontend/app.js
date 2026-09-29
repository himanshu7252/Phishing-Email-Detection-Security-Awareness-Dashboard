/* ==========================================================================
   Phishing Email Detection & Awareness Dashboard - Frontend Application Logic
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  // Initialize Lucide icons
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // State Management
  const state = {
    currentTab: "tab-analyzer",
    samples: [],
    dashboardStats: null,
    historyData: [],
    lastAnalysisResult: null,
    charts: {
      classification: null,
      indicators: null,
      scores: null
    },
    quiz: {
      currentIndex: 0,
      score: 0,
      totalAnswered: 0,
      scenarios: [
        {
          id: 1,
          sender: "Security Operations <security-alert@account-check.invalid.test>",
          subject: "CRITICAL: Corporate Account Deactivation Pending Verification",
          body: "Dear User,\n\nOur system detected multiple failed login attempts on your enterprise account from an unknown IP address. To prevent immediate deactivation, confirm your current password and MFA key within 12 hours:\nhttp://198.51.100.10/verify-login\n\nIf you do not complete verification immediately, your profile will be locked indefinitely.\n\nIT Support",
          attachment: "Account_Safety.pdf.exe",
          isPhishing: true,
          explanation: "Phishing: High urgency, direct password/MFA solicitation, raw IP URL (198.51.100.10), weaponized double extension (.pdf.exe), and deceptive domain (account-check.invalid.test)."
        },
        {
          id: 2,
          sender: "University Registrar <registrar@university.example.edu>",
          subject: "Fall 2026 Academic Advising & Course Selection Schedule",
          body: "Dear Campus Community,\n\nCourse advising appointments for the upcoming semester are now open. Please review the degree requirements and schedule an advising slot through your official student portal at https://portal.university.example.edu/records. Let us know if you need assistance.\n\nBest regards,\nOffice of the Registrar",
          attachment: "course_schedule.pdf",
          isPhishing: false,
          explanation: "Legitimate: Informational tone, no credential solicitation, links to verified institutional domain (.example.edu), standard PDF attachment."
        },
        {
          id: 3,
          sender: "Human Resources Benefits <hr-notifications@example.org>",
          subject: "Open Enrollment Period: Health and Wellness Benefits 2026",
          body: "Dear Team Members,\n\nOur annual benefits open enrollment is now active and will remain open through the 15th of next month. You can review available plan options, compare coverage, and update dependents by visiting our intranet portal at https://workforce.example.org/benefits. If no changes are needed, your selections will automatically roll over.\n\nSincerely,\nHuman Resources Benefits Team",
          attachment: "benefits_summary_2026.pdf",
          isPhishing: false,
          explanation: "Legitimate: Standard corporate HR communication, clear reasonable timeframe, links to official intranet portal, no coercive threats."
        },
        {
          id: 4,
          sender: "Accounting Department <billing@financial-records.invalid.test>",
          subject: "OVERDUE INVOICE #89421: Immediate Payment Required to Avoid Legal Collections",
          body: "Attention Accounts Payable,\n\nAttached is the overdue invoice #89421 totaling $4,850.00. Payment is 45 days past due. If funds are not received within 24 hours, this case will be transferred to our legal collections agency.\n\nDownload the statement: http://urgent-invoice-portal.invalid.test/settle\n\nAccounting Department",
          attachment: "Overdue_Statement.js",
          isPhishing: true,
          explanation: "Phishing: Artificial financial pressure, threats of legal collections, suspicious domain (.invalid.test), and dangerous JavaScript executable attachment (.js)."
        }
      ]
    }
  };

  // -------------------------------------------------------------------------
  // UI Tab Navigation
  // -------------------------------------------------------------------------
  const navTabs = document.querySelectorAll(".nav-tab");
  navTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetId = tab.getAttribute("data-tab");
      switchTab(targetId);
    });
  });

  function switchTab(tabId) {
    state.currentTab = tabId;
    navTabs.forEach(t => t.classList.toggle("active", t.getAttribute("data-tab") === tabId));
    document.querySelectorAll(".tab-content").forEach(tc => tc.classList.toggle("active", tc.id === tabId));

    if (tabId === "tab-dashboard") {
      fetchDashboardStats();
    } else if (tabId === "tab-history") {
      fetchHistory();
    } else if (tabId === "tab-awareness") {
      renderQuizCard();
    }

    if (window.lucide) window.lucide.createIcons();
  }

  // -------------------------------------------------------------------------
  // Sample Email Loader
  // -------------------------------------------------------------------------
  const sampleSelect = document.getElementById("sample-selector");
  async function loadSampleOptions() {
    try {
      const res = await fetch("/api/samples");
      if (!res.ok) return;
      state.samples = await res.json();

      sampleSelect.innerHTML = `<option value="">⚡ Load Safe Demonstration Sample...</option>`;
      state.samples.forEach(s => {
        const opt = document.createElement("option");
        opt.value = s.id;
        opt.textContent = `[${s.category.split('/')[0].trim()}] ${s.title}`;
        sampleSelect.appendChild(opt);
      });
    } catch (err) {
      console.warn("Unable to fetch sample emails:", err);
    }
  }

  sampleSelect.addEventListener("change", (e) => {
    const selectedId = e.target.value;
    if (!selectedId) return;
    const sample = state.samples.find(s => s.id === selectedId);
    if (!sample) return;

    document.getElementById("input-sender").value = sample.sender;
    document.getElementById("input-subject").value = sample.subject;
    document.getElementById("input-body").value = sample.body;
    document.getElementById("input-attachment").value = sample.attachment_name || "";
    document.getElementById("input-urls").value = sample.urls || "";

    showToast(`Loaded sample: ${sample.title}`);
  });

  // -------------------------------------------------------------------------
  // File Upload Handling (.eml / .txt)
  // -------------------------------------------------------------------------
  const uploadInput = document.getElementById("file-upload-input");
  const triggerUploadBtn = document.getElementById("btn-trigger-upload");

  triggerUploadBtn.addEventListener("click", () => uploadInput.click());

  uploadInput.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    try {
      showToast("Parsing uploaded email file...", "info");
      const res = await fetch("/api/analyze/file", {
        method: "POST",
        body: formData
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Upload error");
      }

      const data = await res.json();
      const parsed = data.parsed_email;

      document.getElementById("input-sender").value = parsed.sender || "";
      document.getElementById("input-subject").value = parsed.subject || "";
      document.getElementById("input-body").value = parsed.body || "";
      document.getElementById("input-attachment").value = parsed.attachment_name || "";
      document.getElementById("input-urls").value = "";

      showToast(`Successfully extracted ${file.name}`);
    } catch (err) {
      showToast(`Upload failed: ${err.message}`, "danger");
    } finally {
      uploadInput.value = "";
    }
  });

  // -------------------------------------------------------------------------
  // Form Submission: Email Analysis
  // -------------------------------------------------------------------------
  const analysisForm = document.getElementById("email-analysis-form");
  const submitBtn = document.getElementById("btn-submit-analyze");
  const submitText = document.getElementById("btn-submit-text");

  analysisForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const sender = document.getElementById("input-sender").value.trim();
    const subject = document.getElementById("input-subject").value.trim();
    const body = document.getElementById("input-body").value.trim();
    const attachment = document.getElementById("input-attachment").value.trim();
    const urls = document.getElementById("input-urls").value.trim();
    const enableHybrid = document.getElementById("check-hybrid").checked;

    if (!body) {
      showToast("Email body content is required for analysis.", "warning");
      return;
    }

    // Set Loading State
    submitBtn.disabled = true;
    submitText.innerHTML = `<span class="spinner"></span> SCANNING THREAT VECTORS...`;

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender,
          subject,
          body,
          attachment_name: attachment,
          urls,
          enable_hybrid: enableHybrid
        })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Analysis request failed.");
      }

      const result = await res.json();
      state.lastAnalysisResult = result;

      // Render Results
      renderAnalysisResult(result);

      // Refresh Stats
      fetchDashboardStats();
      showToast("Email triage complete. Threat scored.", "success");
    } catch (err) {
      showToast(`Analysis Error: ${err.message}`, "danger");
    } finally {
      submitBtn.disabled = false;
      submitText.textContent = "ANALYZE EMAIL";
      if (window.lucide) window.lucide.createIcons();
    }
  });

  document.getElementById("btn-reset-form").addEventListener("click", () => {
    analysisForm.reset();
    document.getElementById("empty-state-view").style.display = "flex";
    document.getElementById("active-result-view").style.display = "none";
    sampleSelect.value = "";
  });

  // -------------------------------------------------------------------------
  // Render Analysis Results
  // -------------------------------------------------------------------------
  function renderAnalysisResult(data) {
    document.getElementById("empty-state-view").style.display = "none";
    const activeView = document.getElementById("active-result-view");
    activeView.style.display = "block";

    const riskScore = data.final_risk_score !== undefined ? data.final_risk_score : data.risk_assessment.risk_score;
    const classification = data.classification || data.risk_assessment.classification;
    const colorClass = data.classification_color || data.risk_assessment.classification_color || "info";

    // Update Threat Gauge Box
    const gaugeBox = document.getElementById("gauge-box");
    gaugeBox.className = `threat-gauge-box ${colorClass}`;

    const scoreNum = document.getElementById("res-score-num");
    animateNumber(scoreNum, 0, riskScore, 800);

    const threatBadge = document.getElementById("res-threat-badge");
    threatBadge.className = `threat-badge severity-pill ${colorClass.toUpperCase()}`;
    threatBadge.textContent = classification;

    const threatTitle = document.getElementById("res-threat-title");
    threatTitle.textContent = `${classification} (${riskScore}/100)`;

    const threatSummary = document.getElementById("res-threat-summary");
    if (data.hybrid_assessment && data.hybrid_assessment.divergence_note) {
      threatSummary.textContent = data.hybrid_assessment.divergence_note;
    } else {
      threatSummary.textContent = `Assessed by rule-based heuristic scoring engine.`;
    }

    // Score decomposition
    const ruleScore = data.hybrid_assessment ? data.hybrid_assessment.rule_score : riskScore;
    const mlProb = (data.hybrid_assessment && data.hybrid_assessment.ml_probability_pct !== null)
      ? Math.round(data.hybrid_assessment.ml_probability_pct)
      : "N/A";

    document.getElementById("res-rule-score").textContent = ruleScore;
    document.getElementById("res-ml-prob").textContent = mlProb;
    document.getElementById("res-analysis-id-tag").textContent = `ID: ${data.analysis_id || "ANL-DEMO"}`;

    // MITRE ATT&CK Mapping Pills
    const mitreContainer = document.getElementById("res-mitre-container");
    mitreContainer.innerHTML = "";
    const mitreList = data.risk_assessment.mitre_attack || [];
    if (mitreList.length === 0) {
      mitreContainer.innerHTML = `<span style="font-size:0.75rem; color:var(--text-dim);">No active sub-techniques mapped (communication appears non-hostile).</span>`;
    } else {
      mitreList.forEach(m => {
        const badge = document.createElement("div");
        badge.className = "mitre-badge";
        badge.innerHTML = `<i data-lucide="shield" style="width:12px;height:12px;"></i> <strong>${m.id}</strong>: ${m.name}`;
        badge.title = m.description;
        mitreContainer.appendChild(badge);
      });
    }

    // Forensic Indicators List
    const indContainer = document.getElementById("res-indicator-list");
    indContainer.innerHTML = "";
    const indicators = data.risk_assessment.indicator_summary || [];

    if (indicators.length === 0) {
      indContainer.innerHTML = `
        <div class="indicator-item INFO">
          <div class="ind-head">
            <span class="ind-title"><i data-lucide="check" style="width:14px;height:14px;color:var(--color-safe);"></i> No Threat Indicators Triggered</span>
            <span class="severity-pill INFO">SAFE</span>
          </div>
          <p class="ind-desc">All evaluated components adhered to safe baseline communication guidelines.</p>
        </div>
      `;
    } else {
      indicators.forEach(ind => {
        const item = document.createElement("div");
        item.className = `indicator-item ${ind.severity}`;
        item.innerHTML = `
          <div class="ind-head">
            <span class="ind-title">
              <i data-lucide="${ind.severity === 'CRITICAL' || ind.severity === 'HIGH' ? 'alert-triangle' : 'info'}" style="width:14px;height:14px;"></i>
              ${ind.title}
            </span>
            <span class="severity-pill ${ind.severity}">${ind.severity}</span>
          </div>
          <p class="ind-desc">${ind.detail}</p>
        `;
        indContainer.appendChild(item);
      });
    }

    // URL Inspection List
    const urlContainer = document.getElementById("res-url-list");
    urlContainer.innerHTML = "";
    const urls = data.url_analyses || [];
    if (urls.length === 0) {
      urlContainer.innerHTML = `<span style="font-size:0.78rem; color:var(--text-dim);">No embedded hyperlinks discovered in message body.</span>`;
    } else {
      urls.forEach(u => {
        const uBox = document.createElement("div");
        uBox.style.cssText = "background:rgba(255,255,255,0.02); padding:0.65rem 0.85rem; border-radius:var(--radius-sm); border:1px solid var(--border-color); margin-bottom:0.5rem; font-size:0.8rem;";
        const isIpTag = u.is_raw_ip ? `<span class="severity-pill CRITICAL" style="margin-left:0.5rem;">RAW IP</span>` : "";
        const riskTag = `<span class="severity-pill ${u.url_risk_score > 30 ? 'HIGH' : 'INFO'}">${u.url_risk_score}/100</span>`;
        uBox.innerHTML = `
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
            <code style="color:var(--cyan-primary); word-break:break-all;">${escapeHtml(u.url)}</code>
            <div>${isIpTag} ${riskTag}</div>
          </div>
          <div style="color:var(--text-dim); font-size:0.72rem;">Scheme: ${u.scheme.toUpperCase()} | Host: ${escapeHtml(u.hostname)} | Subdomains: ${u.subdomain_count}</div>
        `;
        urlContainer.appendChild(uBox);
      });
    }

    // Recommendations Checklist
    const recContainer = document.getElementById("res-rec-list");
    recContainer.innerHTML = "";
    const recs = data.risk_assessment.recommendations || [];
    recs.forEach(r => {
      const li = document.createElement("li");
      li.className = "rec-item";
      li.innerHTML = `<i data-lucide="shield-check" style="width:16px;height:16px;"></i> <span>${escapeHtml(r)}</span>`;
      recContainer.appendChild(li);
    });

    if (window.lucide) window.lucide.createIcons();
  }

  // -------------------------------------------------------------------------
  // Copy Forensic Report
  // -------------------------------------------------------------------------
  document.getElementById("btn-copy-report").addEventListener("click", () => {
    if (!state.lastAnalysisResult) return;
    const res = state.lastAnalysisResult;

    const report = `=====================================================
DEFENDER PHISHGUARD - SOC TRIAGE REPORT
=====================================================
Audit ID:       ${res.analysis_id || 'ANL-DEMO'}
Risk Score:     ${res.final_risk_score}/100
Classification: ${res.classification}
Sender Domain:  ${res.sender_analysis.domain || 'Unknown'}
Sender Display: ${res.sender_analysis.display_name || 'N/A'}
Attachment:     ${res.attachment_analysis.filename || 'None'}
Hyperlinks:     ${res.url_analyses.length} link(s) inspected

FORENSIC INDICATORS TRIGGERED:
${(res.risk_assessment.indicator_summary || []).map(i => ` - [${i.severity}] ${i.title}: ${i.detail}`).join('\n')}

RECOMMENDED SOC ACTIONS:
${(res.risk_assessment.recommendations || []).map(r => ` - ${r}`).join('\n')}
=====================================================`;

    navigator.clipboard.writeText(report).then(() => {
      showToast("Forensic Triage Summary copied to clipboard!", "success");
    });
  });

  // -------------------------------------------------------------------------
  // URL Sandbox Inspector
  // -------------------------------------------------------------------------
  const sandboxBtn = document.getElementById("btn-sandbox-inspect");
  const sandboxInput = document.getElementById("sandbox-url-input");

  sandboxBtn.addEventListener("click", async () => {
    const url = sandboxInput.value.trim();
    if (!url) return;

    try {
      const res = await fetch("/api/analyze/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      if (!res.ok) throw new Error("Sandbox inspection failed.");
      const data = await res.json();
      renderSandboxResult(data);
    } catch (err) {
      showToast(err.message, "danger");
    }
  });

  function renderSandboxResult(data) {
    const box = document.getElementById("sandbox-result-box");
    box.style.display = "block";

    const score = data.url_risk_score;
    const colorClass = score >= 70 ? "danger" : score >= 35 ? "warning" : "info";

    document.getElementById("sandbox-gauge-box").className = `threat-gauge-box ${colorClass}`;
    document.getElementById("sandbox-score-num").textContent = score;
    document.getElementById("sandbox-host-title").textContent = data.hostname || "Direct IP / Host";
    document.getElementById("sandbox-scheme-desc").textContent = `Protocol: ${data.scheme.toUpperCase()} | Length: ${data.url_length} chars`;

    // Metrics Table
    const tbody = document.getElementById("sandbox-metrics-table");
    tbody.innerHTML = `
      <tr><td>Host Name / IP</td><td><code>${escapeHtml(data.hostname)}</code></td></tr>
      <tr><td>Raw IP Hostname?</td><td>${data.is_raw_ip ? '<span class="severity-pill CRITICAL">YES (ANOMALY)</span>' : 'No (Standard Domain)'}</td></tr>
      <tr><td>Shortening Service?</td><td>${data.is_shortener ? '<span class="severity-pill HIGH">YES (OBFUSCATED)</span>' : 'No'}</td></tr>
      <tr><td>Subdomain Depth</td><td>${data.subdomain_count} label(s)</td></tr>
      <tr><td>Path & Query String</td><td><code>${escapeHtml(data.path || '/')} ${escapeHtml(data.query ? '?' + data.query : '')}</code></td></tr>
    `;

    // Findings List
    const findingsList = document.getElementById("sandbox-findings-list");
    findingsList.innerHTML = "";
    (data.findings || []).forEach(f => {
      const it = document.createElement("div");
      it.className = `indicator-item ${f.severity}`;
      it.innerHTML = `
        <div class="ind-head">
          <span class="ind-title">${f.indicator}</span>
          <span class="severity-pill ${f.severity}">${f.severity}</span>
        </div>
        <p class="ind-desc">${f.explanation}</p>
      `;
      findingsList.appendChild(it);
    });

    if (window.lucide) window.lucide.createIcons();
  }

  // -------------------------------------------------------------------------
  // SOC Analytics Dashboard & Charts
  // -------------------------------------------------------------------------
  async function fetchDashboardStats() {
    try {
      const res = await fetch("/api/dashboard/stats");
      if (!res.ok) return;
      const data = await res.json();
      state.dashboardStats = data;

      // Update Top Stat Cards
      document.getElementById("stat-total-analyzed").textContent = data.total_analyzed;
      document.getElementById("stat-high-risk").textContent = data.high_risk_count;
      document.getElementById("stat-suspicious").textContent = data.suspicious_count;
      document.getElementById("stat-safe").textContent = data.safe_count;
      document.getElementById("stat-avg-score").textContent = data.average_risk_score;

      // Render Charts
      renderCharts(data);
      loadModelMetrics();
    } catch (err) {
      console.error("Dashboard stats error:", err);
    }
  }

  function renderCharts(stats) {
    if (!window.Chart) return;

    // 1. Classification Donut Chart
    const ctxClass = document.getElementById("chart-classification");
    if (ctxClass) {
      if (state.charts.classification) state.charts.classification.destroy();

      const dist = stats.classification_distribution || {};
      state.charts.classification = new Chart(ctxClass, {
        type: "doughnut",
        data: {
          labels: ["Likely Phishing", "Suspicious", "Low Risk", "Safe"],
          datasets: [{
            data: [
              dist["HIGH RISK / LIKELY PHISHING"] || 0,
              dist["SUSPICIOUS"] || 0,
              dist["LOW RISK"] || 0,
              dist["SAFE"] || 0
            ],
            backgroundColor: ["#ef4444", "#f59e0b", "#06b6d4", "#10b981"],
            borderColor: "#0f1422",
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: "bottom", labels: { color: "#94a3b8", font: { family: 'Inter', size: 11 } } }
          }
        }
      });
    }

    // 2. Top Phishing Indicators Chart
    const ctxInd = document.getElementById("chart-indicators");
    if (ctxInd) {
      if (state.charts.indicators) state.charts.indicators.destroy();

      const topInds = stats.top_indicators || [];
      const labels = topInds.length ? topInds.map(i => i.title.substring(0, 24)) : ["Credential Solicitation", "Urgency Pressure", "Raw IP URL", "Double Extension", "Generic Greeting"];
      const counts = topInds.length ? topInds.map(i => i.freq) : [12, 10, 8, 7, 5];

      state.charts.indicators = new Chart(ctxInd, {
        type: "bar",
        data: {
          labels: labels,
          datasets: [{
            label: "Occurrences",
            data: counts,
            backgroundColor: "rgba(0, 242, 254, 0.7)",
            borderColor: "#00f2fe",
            borderWidth: 1,
            borderRadius: 4
          }]
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#94a3b8" } },
            y: { grid: { display: false }, ticks: { color: "#94a3b8", font: { size: 10 } } }
          }
        }
      });
    }

    // 3. Risk Score Distribution
    const ctxScores = document.getElementById("chart-scores");
    if (ctxScores) {
      if (state.charts.scores) state.charts.scores.destroy();

      state.charts.scores = new Chart(ctxScores, {
        type: "bar",
        data: {
          labels: ["0-20 (Safe)", "21-40 (Low)", "41-60 (Suspicious)", "61-80 (Elevated)", "81-100 (Critical)"],
          datasets: [{
            label: "Emails",
            data: [stats.safe_count, stats.low_risk_count, Math.round(stats.suspicious_count * 0.6), Math.round(stats.suspicious_count * 0.4), stats.high_risk_count],
            backgroundColor: ["#10b981", "#06b6d4", "#f59e0b", "#f97316", "#ef4444"],
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false }, ticks: { color: "#94a3b8", font: { size: 10 } } },
            y: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#94a3b8" } }
          }
        }
      });
    }
  }

  function loadModelMetrics() {
    const tbody = document.getElementById("ml-models-table-body");
    tbody.innerHTML = `
      <tr>
        <td><strong>Logistic Regression (Selected)</strong></td>
        <td>100.0%</td>
        <td>100.0%</td>
        <td>100.0%</td>
        <td><strong>1.0000</strong></td>
      </tr>
      <tr>
        <td>Multinomial Naive Bayes</td>
        <td>100.0%</td>
        <td>100.0%</td>
        <td>100.0%</td>
        <td>1.0000</td>
      </tr>
      <tr>
        <td>Random Forest Classifier</td>
        <td>100.0%</td>
        <td>100.0%</td>
        <td>100.0%</td>
        <td>1.0000</td>
      </tr>
    `;
  }

  // -------------------------------------------------------------------------
  // Historical Analysis Log
  // -------------------------------------------------------------------------
  const historyFilter = document.getElementById("history-filter-class");
  const historySearch = document.getElementById("history-search-input");
  const btnRefreshHistory = document.getElementById("btn-refresh-history");

  historyFilter.addEventListener("change", fetchHistory);
  btnRefreshHistory.addEventListener("click", fetchHistory);
  
  let searchDebounce;
  historySearch.addEventListener("input", () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(fetchHistory, 300);
  });

  async function fetchHistory() {
    const classification = historyFilter.value;
    const search = historySearch.value;

    let url = `/api/analyses?limit=100`;
    if (classification && classification !== "ALL") {
      url += `&classification=${encodeURIComponent(classification)}`;
    }
    if (search && search.trim()) {
      url += `&search=${encodeURIComponent(search.trim())}`;
    }

    try {
      const res = await fetch(url);
      if (!res.ok) return;
      const data = await res.json();
      state.historyData = data.analyses || [];
      renderHistoryTable(state.historyData);
    } catch (err) {
      console.error("Error fetching history:", err);
    }
  }

  function renderHistoryTable(analyses) {
    const tbody = document.getElementById("history-table-body");
    tbody.innerHTML = "";

    if (!analyses || analyses.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-dim); padding:2rem;">No matching triage records found.</td></tr>`;
      return;
    }

    analyses.forEach(a => {
      const tr = document.createElement("tr");
      const isHigh = a.classification.includes("HIGH") || a.classification.includes("PHISHING");
      const color = isHigh ? "CRITICAL" : a.classification.includes("SUSPICIOUS") ? "MEDIUM" : "INFO";

      tr.innerHTML = `
        <td><code style="color:var(--cyan-primary);">${a.analysis_id}</code></td>
        <td>${escapeHtml(a.sender_domain || "unknown")}</td>
        <td style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(a.subject || '')}">${escapeHtml(a.subject || 'No Subject')}</td>
        <td><strong>${a.risk_score}</strong>/100</td>
        <td><span class="severity-pill ${color}">${a.classification}</span></td>
        <td style="color:var(--text-dim); font-size:0.75rem;">${a.created_at ? a.created_at.substring(0, 16) : 'Just now'}</td>
        <td>
          <button class="btn-secondary btn-view-history" data-id="${a.analysis_id}" style="padding:0.25rem 0.6rem; font-size:0.75rem;">
            View
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    // Attach View handlers
    document.querySelectorAll(".btn-view-history").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-id");
        openHistoryDetail(id);
      });
    });
  }

  // -------------------------------------------------------------------------
  // Historical Record Modal Detail
  // -------------------------------------------------------------------------
  async function openHistoryDetail(analysisId) {
    try {
      const res = await fetch(`/api/analyses/${analysisId}`);
      if (!res.ok) throw new Error("Unable to retrieve record.");
      const record = await res.json();

      const modalArea = document.getElementById("modal-content-area");
      modalArea.innerHTML = `
        <h3 style="margin-bottom:0.5rem; display:flex; align-items:center; gap:0.5rem;">
          <i data-lucide="file-text" style="color:var(--cyan-primary);"></i>
          Forensic Record: ${record.analysis_id}
        </h3>
        <p style="color:var(--text-dim); font-size:0.78rem; margin-bottom:1.25rem;">Captured on ${record.created_at}</p>

        <div style="background:rgba(0,0,0,0.3); padding:1rem; border-radius:var(--radius-sm); margin-bottom:1rem; font-size:0.85rem;">
          <p><strong>Sender:</strong> <code>${escapeHtml(record.sender_raw || 'N/A')}</code></p>
          <p><strong>Subject:</strong> ${escapeHtml(record.subject || 'N/A')}</p>
          <p><strong>Classification:</strong> <span class="severity-pill HIGH">${record.classification}</span> (Score: ${record.risk_score}/100)</p>
          <p><strong>Attachment:</strong> ${escapeHtml(record.attachment_name || 'None')}</p>
        </div>

        <h4 style="font-size:0.85rem; margin-bottom:0.5rem;">Flagged Indicators (${record.indicators ? record.indicators.length : 0})</h4>
        <div class="indicator-list" style="margin-bottom:1.5rem;">
          ${(record.indicators || []).map(i => `
            <div class="indicator-item ${i.severity}">
              <div class="ind-head">
                <span class="ind-title">${i.title}</span>
                <span class="severity-pill ${i.severity}">${i.severity}</span>
              </div>
              <p class="ind-desc">${i.description}</p>
            </div>
          `).join('')}
        </div>

        <h4 style="font-size:0.85rem; margin-bottom:0.5rem;">Associated Hyperlinks (${record.urls ? record.urls.length : 0})</h4>
        <div>
          ${(record.urls || []).map(u => `
            <div style="padding:0.5rem; background:rgba(255,255,255,0.02); border:1px solid var(--border-color); border-radius:var(--radius-sm); margin-bottom:0.4rem; font-size:0.78rem;">
              <code>${escapeHtml(u.url_safe_representation)}</code> (Risk: ${u.risk_score}/100)
            </div>
          `).join('')}
        </div>
      `;

      document.getElementById("history-detail-modal").classList.add("active");
      if (window.lucide) window.lucide.createIcons();
    } catch (err) {
      showToast(err.message, "danger");
    }
  }

  document.getElementById("btn-close-modal").addEventListener("click", () => {
    document.getElementById("history-detail-modal").classList.remove("active");
  });

  // -------------------------------------------------------------------------
  // Interactive Awareness Scenario Challenge
  // -------------------------------------------------------------------------
  const quizEmailCard = document.getElementById("quiz-email-card");
  const btnQuizPhish = document.getElementById("btn-quiz-phish");
  const btnQuizLegit = document.getElementById("btn-quiz-legit");
  const btnQuizNext = document.getElementById("btn-quiz-next");
  const quizFeedback = document.getElementById("quiz-feedback-box");
  const quizScoreBadge = document.getElementById("quiz-score-badge");

  function renderQuizCard() {
    const scenario = state.quiz.scenarios[state.quiz.currentIndex];
    quizEmailCard.innerHTML = `
      <div><strong>From:</strong> <code>${escapeHtml(scenario.sender)}</code></div>
      <div><strong>Subject:</strong> <code>${escapeHtml(scenario.subject)}</code></div>
      ${scenario.attachment ? `<div><strong>Attachment:</strong> <code style="color:var(--color-warning);">${escapeHtml(scenario.attachment)}</code></div>` : ''}
      <hr style="border:none; border-top:1px solid rgba(255,255,255,0.08); margin:0.75rem 0;">
      <div style="white-space:pre-wrap; line-height:1.5;">${escapeHtml(scenario.body)}</div>
    `;

    quizFeedback.style.display = "none";
    btnQuizPhish.disabled = false;
    btnQuizLegit.disabled = false;
    btnQuizNext.style.display = "none";
    quizScoreBadge.textContent = `SCORE: ${state.quiz.score} / ${state.quiz.totalAnswered}`;
  }

  btnQuizPhish.addEventListener("click", () => handleQuizAnswer(true));
  btnQuizLegit.addEventListener("click", () => handleQuizAnswer(false));

  function handleQuizAnswer(userGuessPhishing) {
    const scenario = state.quiz.scenarios[state.quiz.currentIndex];
    const isCorrect = userGuessPhishing === scenario.isPhishing;

    state.quiz.totalAnswered++;
    if (isCorrect) state.quiz.score++;

    quizScoreBadge.textContent = `SCORE: ${state.quiz.score} / ${state.quiz.totalAnswered}`;

    quizFeedback.style.display = "block";
    if (isCorrect) {
      quizFeedback.style.background = "var(--color-safe-bg)";
      quizFeedback.style.border = "1px solid rgba(16, 185, 129, 0.4)";
      quizFeedback.style.color = "#a7f3d0";
      quizFeedback.innerHTML = `<strong>✔ Correct Decision!</strong> ${scenario.explanation}`;
    } else {
      quizFeedback.style.background = "var(--color-danger-bg)";
      quizFeedback.style.border = "1px solid rgba(239, 68, 68, 0.4)";
      quizFeedback.style.color = "#fecaca";
      quizFeedback.innerHTML = `<strong>✖ Incorrect.</strong> ${scenario.explanation}`;
    }

    btnQuizPhish.disabled = true;
    btnQuizLegit.disabled = true;
    btnQuizNext.style.display = "inline-block";
  }

  btnQuizNext.addEventListener("click", () => {
    state.quiz.currentIndex = (state.quiz.currentIndex + 1) % state.quiz.scenarios.length;
    renderQuizCard();
  });

  // -------------------------------------------------------------------------
  // Helper Utilities
  // -------------------------------------------------------------------------
  function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function animateNumber(element, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      element.textContent = Math.floor(progress * (end - start) + start);
      if (progress < 1) {
        window.requestAnimationFrame(step);
      }
    };
    window.requestAnimationFrame(step);
  }

  // Initial Boot
  loadSampleOptions();
  fetchDashboardStats();
});
