/* Detection dashboard — KPIs, pipeline visualization, charts, alerts table,
   log-file upload, alert detail modal, CSV export.
   Stage counters animate so the pipeline reads as a system, not a static diagram. */
(function () {
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
  const CLASS_COLORS = {
    DDoS: "#E97366", DoS: "#DE9255", PortScan: "#EAC26B", BruteForce: "#BF8EDA",
    WebAttack: "#5E9FE8", Bot: "#4FB9C9", Infiltration: "#DF84A8", "unknown-anomaly": "#72BC8F",
  };

  // MITRE technique descriptions for modal (demo mode fallback)
  const TECH_DESC = {
    T1498: "Network Denial of Service — volumetric traffic flood",
    T1499: "Endpoint Denial of Service — resource exhaustion",
    T1046: "Network Service Discovery — port scanning",
    T1595: "Active Scanning — reconnaissance probes",
    T1110: "Brute Force — credential guessing",
    "T1110.001": "Password Guessing — repeated login attempts",
    "T1110.003": "Password Spraying — one password, many accounts",
    T1190: "Exploit Public-Facing Application — web exploit",
    T1059: "Command and Scripting Interpreter — code execution",
    "T1059.007": "JavaScript execution in web context",
    T1071: "Application Layer Protocol — C2 communication",
    "T1071.001": "Web Protocols for C2 traffic",
    T1105: "Ingress Tool Transfer — malware delivery",
    T1041: "Exfiltration Over C2 Channel — data theft",
    T1020: "Automated Exfiltration — scheduled data leak",
    T1048: "Exfiltration Over Alternative Protocol",
    T1203: "Exploitation for Client Execution — zero-day",
    T1068: "Exploitation for Privilege Escalation",
    T1212: "Exploitation for Credential Access",
    "T1499.002": "Service Exhaustion Flood",
  };

  let ALERTS = [];
  let sevFilter = "all";
  let flowsTotal = 0;
  let throughput = 0;

  /* ---------- KPIs ---------- */
  function paintKpis() {
    const threats = ALERTS.filter((a) => a.stage === "classifier").length;
    const zd = ALERTS.filter((a) => a.stage === "autoencoder").length;
    animateNum(document.getElementById("kpi-flows"), flowsTotal);
    animateNum(document.getElementById("kpi-threats"), threats);
    animateNum(document.getElementById("kpi-zeroday"), zd);
    document.getElementById("kpi-throughput").textContent =
      throughput ? CG.util.fmtNum(throughput) : "—";
  }

  function animateNum(el, target) {
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { el.textContent = CG.util.fmtNum(target); return; }
    const t0 = performance.now(), dur = 700;
    (function tick(t) {
      const p = Math.min(1, (t - t0) / dur);
      const eased = 1 - Math.pow(1 - p, 4); // quartic ease-out, transform-free counter
      el.textContent = CG.util.fmtNum(Math.round(target * eased));
      if (p < 1) requestAnimationFrame(tick);
    })(t0);
  }

  /* ---------- pipeline ---------- */
  function paintPipeline(stageCounts, stats) {
    const c = stageCounts || {
      extract: flowsTotal,
      statistical: 0,
      classifier: ALERTS.filter((a) => a.stage === "classifier").length,
      autoencoder: ALERTS.filter((a) => a.stage === "autoencoder").length,
    };
    for (const [stage, n] of Object.entries(c)) {
      const el = document.getElementById("count-" + stage);
      if (el) el.textContent = CG.util.fmtNum(n) + (stage === "extract" ? " flows" : " flagged");
    }
    document.getElementById("pipeline-note").textContent = stats
      ? `measured drop rate ${Number(stats.drop_rate_pct || 0).toFixed(1)}% · mean latency ${Number(stats.mean_latency_ms || 0).toFixed(3)} ms/flow`
      : "upload a log file to measure this pipeline";
  }

  function flashStage(stage, alert) {
    const el = document.querySelector(`.stage[data-stage="${stage}"]`);
    if (!el) return;
    el.classList.remove("is-hot", "is-alert");
    void el.offsetWidth; // restart transition
    el.classList.add(alert ? "is-alert" : "is-hot");
    setTimeout(() => el.classList.remove("is-hot", "is-alert"), 1400);
  }

  /* ---------- charts ---------- */
  function paintCharts(featureImportance) {
    const byType = {};
    ALERTS.forEach((a) => { byType[a.type] = (byType[a.type] || 0) + 1; });
    const dist = Object.entries(byType)
      .map(([label, value]) => ({ label, value, color: CLASS_COLORS[label] }))
      .sort((a, b) => b.value - a.value);
    CG.charts.donut(document.getElementById("chart-distribution"), dist);

    // timeline: bucket last 60 min into 20 slots
    const nowS = Date.now() / 1000, slots = new Array(20).fill(0);
    ALERTS.forEach((a) => {
      const i = Math.floor((nowS - a.created_at) / 180);
      if (i >= 0 && i < 20) slots[19 - i]++;
    });
    CG.charts.area(document.getElementById("chart-timeline"),
      slots.map((v) => ({ value: v })));

    const scores = ALERTS.map((a) => a.anomaly_score).filter((v) => v > 0);
    CG.charts.histogram(document.getElementById("chart-anomaly"),
      scores.length ? scores : [0.05, 0.09, 0.12, 0.2, 0.5, 0.9, 1.4], 0.45);

    const fi = featureImportance || [
      ["packets_per_sec", .21], ["syn_flag_count", .17], ["flow_duration", .13],
      ["bytes_per_sec", .11], ["iat_mean", .09], ["init_win_bytes_fwd", .08],
      ["packet_length_std", .07], ["flow_bytes_ratio", .06],
    ];
    CG.charts.hbars(document.getElementById("chart-importance"), fi);
  }

  /* ---------- alerts table ---------- */
  function paintAlerts() {
    const body = document.getElementById("alerts-body");
    const rows = ALERTS
      .filter((a) => sevFilter === "all" || a.severity === sevFilter)
      .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.created_at - a.created_at)
      .slice(0, 50);
    body.innerHTML = rows.map((a, i) => `
      <tr class="row-in" data-alert-idx="${i}">
        <td class="mono" title="${CG.util.timeAgo(a.created_at)}">${CG.util.fmtTime(a.created_at)}</td>
        <td><span class="sev-badge sev-${a.severity}">${a.severity}</span></td>
        <td><strong>${CG.util.esc(a.type)}</strong></td>
        <td><span class="stage-tag">${a.stage}</span></td>
        <td class="mono">${a.confidence ? (a.confidence * 100).toFixed(1) + "%" : "—"}</td>
        <td class="mono">${a.anomaly_score || "—"}</td>
        <td>${a.mitre_techniques.map((t) => `<span class="tech-tag">${t}</span>`).join("")}</td>
        <td class="mono">${a.latency_ms} ms</td>
      </tr>`).join("");

    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-3);padding:32px">No alerts at this severity — the pipeline is quiet.</td></tr>`;
      return;
    }

    // bind click → modal
    body.querySelectorAll("tr[data-alert-idx]").forEach((tr, i) => {
      tr.addEventListener("click", () => openAlertModal(rows[i]));
    });
  }

  document.querySelectorAll(".sev-filter").forEach((b) =>
    b.addEventListener("click", () => {
      sevFilter = b.dataset.sev;
      document.querySelectorAll(".sev-filter").forEach((x) => x.classList.toggle("is-active", x === b));
      paintAlerts();
    }));

  /* ---------- alert detail modal ---------- */
  const modal = document.getElementById("alert-modal");
  const modalClose = document.getElementById("modal-close");
  let currentAlert = null;

  function openAlertModal(alert) {
    currentAlert = alert;
    // Verdict
    document.getElementById("modal-verdict").innerHTML = `
      <dt>Type</dt><dd><strong>${CG.util.esc(alert.type)}</strong></dd>
      <dt>Severity</dt><dd><span class="sev-badge sev-${alert.severity}">${alert.severity}</span></dd>
      <dt>Stage</dt><dd>${alert.stage}</dd>
      <dt>Time</dt><dd>${CG.util.fmtTime(alert.created_at)}</dd>
      <dt>Confidence</dt><dd>${alert.confidence ? (alert.confidence * 100).toFixed(1) + "%" : "N/A"}</dd>
      <dt>Anomaly Score</dt><dd>${alert.anomaly_score || "N/A"}</dd>
      <dt>Latency</dt><dd>${alert.latency_ms} ms</dd>
      <dt>Source</dt><dd>${CG.util.esc(alert.source_file || "—")}</dd>
    `;

    // Top features
    const featEl = document.getElementById("modal-features");
    const topFeats = alert.top_features || [
      ["packets_per_sec", .83], ["syn_flag_count", .71], ["flow_duration", .64],
      ["bytes_per_sec", .52], ["flow_bytes_ratio", .38],
    ];
    const maxFeat = Math.max(...topFeats.map(f => f[1]), 0.01);
    featEl.innerHTML = topFeats.map(([name, val]) => `
      <div class="modal-feat-bar">
        <span class="feat-name">${name}</span>
        <div class="feat-track"><div class="feat-fill" style="width:${(val/maxFeat*100).toFixed(0)}%"></div></div>
        <span class="feat-val">${val.toFixed(3)}</span>
      </div>`).join("");

    // MITRE mapping
    const mitreEl = document.getElementById("modal-mitre");
    if (alert.mitre_techniques && alert.mitre_techniques.length) {
      mitreEl.innerHTML = alert.mitre_techniques.map(t =>
        `<div style="margin:6px 0"><span class="tech-tag">${t}</span> <span style="color:var(--text-2);font-size:.82rem;margin-left:8px">${TECH_DESC[t] || "MITRE ATT&CK technique"}</span></div>`
      ).join("") + `<p style="margin-top:12px;font-size:.82rem;color:var(--text-3)">View full details in the MITRE ATT&CK browser tab.</p>`;
    } else {
      mitreEl.innerHTML = `<p class="text-muted">No MITRE techniques mapped for this alert type.</p>`;
    }

    // Reset explanation
    document.getElementById("modal-explanation").innerHTML =
      `<p class="text-muted">Click "Explain with AI" to get an AI analysis of this pipeline verdict.</p>`;

    // Show modal
    modal.hidden = false;
    requestAnimationFrame(() => modal.classList.add("is-visible"));
  }

  function closeModal() {
    modal.classList.remove("is-visible");
    setTimeout(() => { modal.hidden = true; }, 350);
  }

  modalClose.addEventListener("click", closeModal);
  modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !modal.hidden) closeModal(); });

  // LLM explain button
  document.getElementById("modal-explain-btn").addEventListener("click", async () => {
    if (!currentAlert) return;
    const expEl = document.getElementById("modal-explanation");
    const btn = document.getElementById("modal-explain-btn");
    btn.disabled = true;
    btn.textContent = "Analyzing…";
    expEl.innerHTML = `<span class="typing"><i></i><i></i><i></i></span>`;

    try {
      if (CG.api.mode === "live" && currentAlert.id) {
        const res = await CG.api.explainAlert(currentAlert.id);
        expEl.innerHTML = CG.util.md(res.explanation);
      } else {
        // Demo mode: generate a context-aware explanation
        await new Promise(r => setTimeout(r, 800 + Math.random() * 600));
        const a = currentAlert;
        const techs = (a.mitre_techniques || []).join(", ");
        const explanation = a.stage === "autoencoder"
          ? `#### Unknown Anomaly Analysis\nThe autoencoder's reconstruction error (**${a.anomaly_score}**) exceeded its held-out benign threshold. This is an anomaly signal, not proof of an exploit or a zero-day.\n\n**Key observations:**\n- The flow deviated from the learned benign distribution\n- The classifier abstained from a high-confidence known label\n- No MITRE technique can be inferred from reconstruction error alone\n\n**Recommended review:**\n1. Correlate with trusted packet capture and endpoint telemetry\n2. Check adjacent flows and asset context\n3. Escalate only when independent evidence supports it`
          : `#### ${a.type} Detection Analysis\nThe XGBoost classifier identified this flow as **${a.type}** with **${(a.confidence*100).toFixed(1)}%** confidence (stage: ${a.stage}).\n\n**Detection path:**\n1. Stage 1 extracted 32 numeric features from the raw flow\n2. Stage 2 Z-score filter flagged statistical anomalies\n3. Stage 3 classifier matched known ${a.type} signatures\n\n**MITRE ATT&CK context:**\nThis maps to techniques: ${techs || "none mapped"}\n\n**Containment guidance:**\n- Block the source at the perimeter firewall\n- Rate-limit similar traffic patterns\n- Monitor for follow-up reconnaissance activity\n- Review correlated alerts in the same time window`;
        expEl.innerHTML = CG.util.md(explanation);
      }
    } catch (err) {
      expEl.innerHTML = `<p style="color:var(--red)">LLM unavailable: ${CG.util.esc(err.message)}. The detection verdict is deterministic — this explanation is optional.</p>`;
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<svg><use href="#i-bolt"/></svg>Explain with AI`;
    }
  });

  /* ---------- export ---------- */
  document.getElementById("btn-export").addEventListener("click", () => {
    if (CG.api.mode === "live") {
      window.open(CG.api.base + "/api/detect/export", "_blank");
      CG.util.toast("Downloading alerts CSV from the pipeline…");
      return;
    }
    // Demo: generate CSV client-side
    const header = "time,severity,type,stage,confidence,anomaly_score,mitre_techniques,latency_ms,source_file";
    const rows = ALERTS.map(a =>
      [CG.util.fmtTime(a.created_at), a.severity, a.type, a.stage,
       a.confidence?.toFixed(3) ?? "", a.anomaly_score?.toFixed(3) ?? "",
       (a.mitre_techniques || []).join(";"), a.latency_ms, a.source_file || ""
      ].join(",")
    );
    const csv = [header, ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: "cyberguard_alerts.csv" });
    a.click();
    URL.revokeObjectURL(url);
    CG.util.toast(`Exported ${ALERTS.length} alerts to CSV.`);
  });

  /* ---------- upload ---------- */
  const input = document.getElementById("upload-input");
  document.getElementById("btn-upload").addEventListener("click", () => input.click());
  input.addEventListener("change", async () => {
    const file = input.files[0];
    input.value = "";
    if (!file) return;
    if (!/\.(csv|json|log|txt|tsv|dat)$/i.test(file.name) && file.name.includes(".")) {
      CG.util.toast("Supported formats: .csv, .json, .log, .txt, .tsv, .dat");
      return;
    }
    const sizeMB = (file.size / 1024 / 1024).toFixed(1);
    const isLarge = file.size > 10 * 1024 * 1024; // >10 MB
    CG.util.toast(
      isLarge
        ? `Uploading ${file.name} (${sizeMB} MB) — large file, this may take a few minutes…`
        : `Analyzing ${file.name} (${sizeMB} MB) through the 4-stage pipeline…`
    );
    // animate stages in sequence while the request runs
    ["extract", "statistical", "classifier", "autoencoder"].forEach((s, i) =>
      setTimeout(() => flashStage(s, false), 250 + i * 350));
    try {
      const res = await CG.api.upload(file);
      flowsTotal += res.flows;
      throughput = res.throughput_rps;
      ALERTS = [...res.alerts, ...ALERTS];
      paintKpis();
      paintPipeline({
        extract: res.flows,
        statistical: res.stage_counts.statistical,
        classifier: res.stage_counts.classifier,
        autoencoder: res.stage_counts.autoencoder,
      }, res.pipeline_stats);
      paintCharts(res.feature_importance);
      paintAlerts();
      flashStage("classifier", true);
      setTimeout(() => flashStage("autoencoder", true), 500);
      const totalAlerts = res.total_alerts || res.alerts.length;
      const cappedNote = res.alerts_capped ? ` (showing ${res.alerts.length} of ${totalAlerts})` : "";
      const elapsed = res.elapsed_seconds ? ` in ${res.elapsed_seconds}s` : "";
      CG.util.toast(
        `${file.name}: ${CG.util.fmtNum(res.flows)} flows → ${CG.util.fmtNum(totalAlerts)} alerts${cappedNote} · ` +
        `${CG.util.fmtNum(res.throughput_rps)} rec/s${elapsed} · ${CG.api.mode === "demo" ? "demo simulation" : "live pipeline"}`);
    } catch (e) {
      CG.util.toast("Analysis failed: " + e.message);
    }
  });

  /* ---------- view lifecycle ---------- */
  CG.onView.dashboard = async function () {
    if (!ALERTS.length) {
      ALERTS = await CG.api.alerts();
      flowsTotal = CG.api.mode === "demo" ? 2840 : 0;
    }
    const health = await CG.api.pipelineHealth();
    const engine = document.getElementById("engine-status");
    const dot = document.getElementById("engine-dot");
    if (CG.api.mode === "live") {
      engine.textContent = health.production_approved
        ? "Production-approved artifacts"
        : health.integrity_verified
          ? "Evaluation-only artifacts"
          : "Pipeline blocked: integrity failure";
      dot.className = health.production_approved ? "dot dot-ok" : "dot dot-warn";
    }
    paintKpis();
    paintPipeline();
    paintCharts();
    paintAlerts();
  };
})();
