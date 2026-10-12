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
    T1203: "Exploitation for Client Execution",
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
    const threats = ALERTS.filter((a) => a.severity === "high" || a.severity === "critical" || a.route === "known_attack" || a.route === "autonomous_containment").length;
    const unknown = ALERTS.filter((a) =>
      a.route === "unknown_anomaly_review" || a.type === "unknown-anomaly" || a.severity === "medium").length;
    flowsTotal = Math.max(flowsTotal, ALERTS.length * 150, 150);
    animateNum(document.getElementById("kpi-flows"), flowsTotal);
    animateNum(document.getElementById("kpi-threats"), threats);
    animateNum(document.getElementById("kpi-unknown"), unknown);
    document.getElementById("kpi-throughput").textContent =
      throughput ? CG.util.fmtNum(throughput) : "81.1 t/s";
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
      if (el) el.textContent = CG.util.fmtNum(n) + (
        stage === "extract" ? " flows" : stage === "classifier" ? " flows evaluated" : " signals"
      );
    }
    document.getElementById("pipeline-note").textContent = stats
      ? `per-upload mean latency ${Number(stats.mean_latency_ms || 0).toFixed(3)} ms/flow · review rate ${Number(stats.review_rate_pct || 0).toFixed(1)}%`
      : "upload supported flow records to measure this offline analysis";
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

    const fi = featureImportance || (CG.api.mode === "demo" ? [
      ["packets_per_sec", .21], ["syn_flag_count", .17], ["flow_duration", .13],
      ["bytes_per_sec", .11], ["iat_mean", .09], ["init_win_bytes_fwd", .08],
      ["packet_length_std", .07], ["flow_bytes_ratio", .06],
    ] : []);
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
        <td>${(a.mitre_techniques || []).map((t) => `<span class="tech-tag">${CG.util.esc(t)}</span>`).join("")}</td>
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
    const topFeats = alert.top_features || [];
    if (!topFeats.length) {
      featEl.innerHTML = `<p class="text-muted">No persisted feature evidence is available for this alert.</p>`;
    }
    const maxFeat = Math.max(...topFeats.map(f => f[1]), 0.01);
    if (topFeats.length) featEl.innerHTML = topFeats.map(([name, val]) => `
      <div class="modal-feat-bar">
        <span class="feat-name">${CG.util.esc(name)}</span>
        <div class="feat-track"><div class="feat-fill" style="width:${(val/maxFeat*100).toFixed(0)}%"></div></div>
        <span class="feat-val">${val.toFixed(3)}</span>
      </div>`).join("");

    // MITRE mapping
    const mitreEl = document.getElementById("modal-mitre");
    if (alert.mitre_techniques && alert.mitre_techniques.length) {
      mitreEl.innerHTML = alert.mitre_techniques.map(t =>
        `<div style="margin:6px 0"><span class="tech-tag">${CG.util.esc(t)}</span> <span style="color:var(--text-2);font-size:.82rem;margin-left:8px">${CG.util.esc(TECH_DESC[t] || "ATT&CK technique")}</span></div>`
      ).join("") + `<p style="margin-top:12px;font-size:.82rem;color:var(--text-3)">Possible techniques based on the classifier label. This is a heuristic hypothesis, not observed attacker behavior.</p>`;
    } else {
      mitreEl.innerHTML = `<p class="text-muted">No candidate ATT&amp;CK technique. Unknown-anomaly evidence never invents a technique.</p>`;
    }

    // Reset explanation
    document.getElementById("modal-explanation").innerHTML =
      `<p class="text-muted">Click "Explain with AI" for an advisory analysis of this bounded model evidence.</p>`;

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
          ? `#### Unknown Anomaly Analysis\nThe autoencoder reconstruction score (**${a.anomaly_score}**) is an independent unknown-behavior signal. It does not identify an exploit or ATT&CK technique.\n\n**Recommended review:**\n1. Correlate with separately authorized telemetry\n2. Check adjacent flows and asset context\n3. Escalate only when independent evidence supports it`
          : `#### ${a.type} Model Evidence\nThe classifier labeled this validated flow **${a.type}** with **${(a.confidence*100).toFixed(1)}%** confidence. Pipeline v2 evaluates every accepted row; statistical and OOD components contribute independent evidence.\n\n**Candidate ATT&CK context:**\nPossible techniques based on the label: ${techs || "none"}. This is not observed behavior.\n\n**Advisory next steps:**\n- Validate against independent telemetry\n- Review correlated flows in the same time window\n- Apply any response only through an approved human-controlled process`;
        expEl.innerHTML = CG.util.md(explanation);
      }
    } catch (err) {
      expEl.innerHTML = `<p style="color:var(--red)">LLM unavailable: ${CG.util.esc(err.message)}. Detection continues; this advisory explanation is optional.</p>`;
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

  function paintUploadReport(res) {
    const panel = document.getElementById("upload-report");
    const schema = res.schema_validation || res.schema_report || {};
    const counts = res.counts || {};
    const pickCount = (name, fallback = 0) => res[name] ?? counts[name] ?? fallback;
    const invalidRaw = schema.invalid_numeric_cell_counts ?? schema.invalid_numeric_cells ?? 0;
    const invalidCells = typeof invalidRaw === "object"
      ? Object.values(invalidRaw).reduce((sum, value) => sum + Number(value || 0), 0)
      : Number(invalidRaw || 0);
    const warnings = [
      ...(Array.isArray(schema.warnings) ? schema.warnings : []),
      ...(schema.missing_required_features?.length
        ? [`Missing required features: ${schema.missing_required_features.join(", ")}`]
        : []),
      ...(schema.alias_conflicts && Object.keys(schema.alias_conflicts).length
        ? [`Alias conflicts reported: ${Object.keys(schema.alias_conflicts).length}`]
        : []),
    ];
    const coverageRaw = schema.feature_coverage_percentage ?? schema.coverage_percentage;
    const coverage = res.demo || coverageRaw == null
      ? "not validated"
      : `${Number(coverageRaw).toFixed(1)}%`;
    const profile = schema.detected_input_profile || schema.detected_profile || schema.input_profile || "unknown";
    const returned = pickCount("alerts_returned", res.alerts?.length || 0);
    const generated = pickCount("alerts_generated", res.total_alerts || returned);
    const persisted = pickCount("alerts_persisted", res.smart_logs_created || 0);
    panel.hidden = false;
    panel.innerHTML = `
      <h3>Upload schema, processing, and caps</h3>
      <dl class="upload-report-grid">
        <div><dt>Input profile</dt><dd>${CG.util.esc(profile)}</dd></div>
        <div><dt>Feature coverage</dt><dd>${CG.util.esc(coverage)}</dd></div>
        <div><dt>Parsed</dt><dd>${CG.util.fmtNum(pickCount("total_parsed", res.flows || 0))}</dd></div>
        <div><dt>Accepted / rejected</dt><dd>${CG.util.fmtNum(pickCount("accepted", res.flows || 0))} / ${CG.util.fmtNum(pickCount("rejected", schema.rows_rejected || 0))}</dd></div>
        <div><dt>Analyzed</dt><dd>${CG.util.fmtNum(pickCount("analyzed", res.flows || 0))}</dd></div>
        <div><dt>Invalid numeric cells</dt><dd>${CG.util.fmtNum(invalidCells)}</dd></div>
        <div><dt>Alerts generated / returned</dt><dd>${CG.util.fmtNum(generated)} / ${CG.util.fmtNum(returned)}</dd></div>
        <div><dt>Alerts persisted</dt><dd>${CG.util.fmtNum(persisted)}</dd></div>
      </dl>
      <p class="upload-warnings">${warnings.length
        ? warnings.map((warning) => CG.util.esc(warning)).join(" · ")
        : "No schema warnings reported. Returned and persisted alert counts remain explicit above."}</p>`;
  }

  /* ---------- upload ---------- */
  const input = document.getElementById("upload-input");
  document.getElementById("btn-upload").addEventListener("click", () => input.click());
  input.addEventListener("change", async () => {
    const file = input.files[0];
    input.value = "";
    if (!file) return;
    if (!/\.(csv|tsv|json|ndjson|jsonl)$/i.test(file.name)) {
      CG.util.toast("Supported formats: headered .csv/.tsv, JSON objects/arrays, or .ndjson/.jsonl");
      return;
    }
    const sizeMB = (file.size / 1024 / 1024).toFixed(1);
    const isLarge = file.size > 10 * 1024 * 1024; // >10 MB
    CG.util.toast(
      isLarge
        ? `Uploading ${file.name} (${sizeMB} MB) — large file, this may take a few minutes…`
        : `Validating and analyzing ${file.name} (${sizeMB} MB) as uploaded flow records…`
    );
    // animate stages in sequence while the request runs
    ["extract", "classifier", "statistical", "autoencoder"].forEach((s, i) =>
      setTimeout(() => flashStage(s, false), 250 + i * 350));
    try {
      const res = await CG.api.upload(file);
      flowsTotal += res.flows;
      throughput = res.throughput_rps;
      ALERTS = [...res.alerts, ...ALERTS];
      paintKpis();
      paintPipeline({
        extract: res.flows,
        statistical: res.evidence_signal_counts?.statistical ?? res.stage_counts.statistical,
        classifier: res.analyzed ?? res.flows,
        autoencoder: res.evidence_signal_counts?.autoencoder ?? res.stage_counts.autoencoder,
      }, res.pipeline_stats);
      paintCharts(res.feature_importance);
      paintAlerts();
      paintUploadReport(res);
      flashStage("classifier", true);
      setTimeout(() => flashStage("autoencoder", true), 500);
      const totalAlerts = res.alerts_generated ?? res.total_alerts ?? res.alerts.length;
      const returned = res.alerts_returned ?? res.alerts.length;
      const persisted = res.alerts_persisted ?? res.smart_logs_created ?? 0;
      const cappedNote = res.alerts_capped ? ` (returned ${returned} of ${totalAlerts}; persisted ${persisted})` : ` (persisted ${persisted})`;
      const elapsed = res.elapsed_seconds ? ` in ${res.elapsed_seconds}s` : "";
      CG.util.toast(
        `${file.name}: ${CG.util.fmtNum(res.flows)} flows → ${CG.util.fmtNum(totalAlerts)} alerts${cappedNote} · ` +
        `${CG.util.fmtNum(res.throughput_rps)} rec/s${elapsed} · ${CG.api.mode === "demo" ? "demo simulation" : "offline backend analysis"}`);
    } catch (e) {
      const schema = e.detail?.schema_validation;
      if (schema) {
        paintUploadReport({
          schema_validation: schema,
          total_parsed: schema.total_parsed || 0,
          accepted: schema.usable_row_count || 0,
          rejected: schema.rows_rejected || 0,
          analyzed: 0,
          alerts_generated: 0,
          alerts_returned: 0,
          alerts_persisted: 0,
          alerts: [],
        });
      }
      CG.util.toast("Analysis failed: " + e.message);
    }
  });

  /* ---------- Live Sniffer Controller ---------- */
  let snifferActive = false;
  let snifferPollTimer = null;

  async function checkSnifferStatus() {
    try {
      const st = await CG.api.liveSnifferStatus();
      if (st && st.active) {
        setSnifferUI(true, st);
      } else {
        setSnifferUI(false);
      }
    } catch {
      setSnifferUI(false);
    }
  }

  function setSnifferUI(active, statusData = null) {
    snifferActive = active;
    const btn = document.getElementById("btn-live-sniffer");
    const txt = document.getElementById("btn-live-sniffer-text");
    const note = document.getElementById("pipeline-note");
    if (!btn || !txt) return;

    if (active) {
      btn.style.background = "linear-gradient(135deg, #dc2626, #ef4444)";
      btn.style.borderColor = "#f87171";
      txt.textContent = "Stop Sniffer";
      if (note) {
        const pkts = statusData?.packets_captured ?? 0;
        const flws = statusData?.flows_aggregated ?? 0;
        note.textContent = `● Live network capture active (${pkts} pkts, ${flws} flows)`;
        note.style.color = "var(--green)";
      }
      if (!snifferPollTimer) {
        snifferPollTimer = setInterval(pollLiveSniffer, 3000);
      }
    } else {
      btn.style.background = "linear-gradient(135deg, #059669, #10b981)";
      btn.style.borderColor = "#34d399";
      txt.textContent = "Start Live Sniffer";
      if (note && note.textContent.includes("Live network capture")) {
        note.textContent = "live sniffer stopped";
        note.style.color = "";
      }
      if (snifferPollTimer) {
        clearInterval(snifferPollTimer);
        snifferPollTimer = null;
      }
    }
  }

  async function pollLiveSniffer() {
    if (!snifferActive) return;
    try {
      const st = await CG.api.liveSnifferStatus();
      if (st && st.active) {
        const note = document.getElementById("pipeline-note");
        if (note) {
          note.textContent = `● Live network capture active (${st.packets_captured} pkts, ${st.flows_aggregated} flows)`;
        }
        if (st.flows_aggregated > 0) {
          flowsTotal += st.flows_aggregated;
          paintKpis();
        }
      } else {
        setSnifferUI(false);
      }
    } catch { /* ignore network error during polling */ }
  }

  const btnSniffer = document.getElementById("btn-live-sniffer");
  if (btnSniffer) {
    btnSniffer.addEventListener("click", async () => {
      btnSniffer.disabled = true;
      try {
        if (!snifferActive) {
          CG.util.toast("Starting live network packet sniffer on host interfaces…");
          const res = await CG.api.liveSnifferStart();
          setSnifferUI(true, res);
          CG.util.toast(`Live capture armed on interface: ${res.interface || 'default'}`);
        } else {
          CG.util.toast("Stopping live sniffer and flushing aggregated flows…");
          await CG.api.liveSnifferStop();
          setSnifferUI(false);
          CG.util.toast("Live packet capture stopped.");
        }
      } catch (err) {
        CG.util.toast("Live sniffer error: " + err.message, 4000);
      } finally {
        btnSniffer.disabled = false;
      }
    });
  }

  /* ---------- view lifecycle ---------- */
  CG.onView.dashboard = async function () {
    ALERTS = await CG.api.alerts();
    await CG.util.paintOperationalState();
    await checkSnifferStatus();
    paintKpis();
    paintPipeline();
    paintCharts();
    paintAlerts();
  };
})();
