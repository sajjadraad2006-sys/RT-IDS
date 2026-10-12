/* CyberGuard API client.
   Tries the real FastAPI backend first; when unreachable (e.g. the HTML is
   opened directly) it falls back to a fully local demo dataset so every view
   keeps working — consistent with the project's local-first rule.
   Nothing here ever fabricates evaluation metrics; demo data is marked demo. */
window.CG = window.CG || {};

(function () {
  const API = { mode: "demo", base: "" };

  async function tryFetch(path, opts = {}, timeoutMs = 2500, retried = false) {
    const ctrl = new AbortController();
    const externalSignal = opts.signal;
    const fetchOptions = { ...opts };
    delete fetchOptions.signal;
    const abortFromExternal = () => ctrl.abort();
    if (externalSignal) {
      if (externalSignal.aborted) ctrl.abort();
      else externalSignal.addEventListener("abort", abortFromExternal, { once: true });
    }
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const headers = new Headers(opts.headers || {});
      const authToken = sessionStorage.getItem("cg-auth-token");
      if (authToken) headers.set("Authorization", `Bearer ${authToken}`);
      const token = sessionStorage.getItem("cg-api-token");
      if (token) headers.set("X-CyberGuard-Token", token);
      const res = await fetch(API.base + path, { ...fetchOptions, headers, signal: ctrl.signal });
      clearTimeout(t);
      if (res.status === 401 && !retried) {
        const entered = window.prompt("CyberGuard API token:");
        if (entered) {
          sessionStorage.setItem("cg-api-token", entered);
          return tryFetch(path, opts, timeoutMs, true);
        }
      }
      if (!res.ok) {
        let detail = "";
        let structuredDetail = null;
        try {
          const body = await res.json();
          structuredDetail = body.detail ?? null;
          detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail || "");
        } catch { /* response has no JSON detail */ }
        const error = new Error(`HTTP ${res.status}${detail ? " · " + detail : ""}`);
        error.status = res.status;
        error.detail = structuredDetail;
        throw error;
      }
      return await res.json();
    } catch (e) {
      clearTimeout(t);
      throw e;
    } finally {
      externalSignal?.removeEventListener("abort", abortFromExternal);
    }
  }

  API.init = async function () {
    try {
      await tryFetch("/api/settings", {}, 1200);
      API.mode = "live";
    } catch { API.mode = "demo"; }
    return API.mode;
  };

  /* ---------------- demo dataset ---------------- */
  const TECHS = [
    ["T1046", "Network Service Discovery", "discovery", "Adversaries may attempt to enumerate services on remote hosts. A PortScan classifier label can create a candidate mapping to this technique; that label alone is not observed technique evidence."],
    ["T1498", "Network Denial of Service", "impact", "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block availability. CyberGuard can map evaluated DDoS classifications to this technique; confidence depends on the active artifact."],
    ["T1498.001", "Direct Network Flood", "impact", "Direct network floods send traffic directly toward a target. CyberGuard does not infer this sub-technique from an anomaly score alone."],
    ["T1499", "Endpoint Denial of Service", "impact", "Adversaries may exhaust endpoint resources. A DoS/DDoS classifier label provides only a possible taxonomy mapping."],
    ["T1110", "Brute Force", "credential-access", "Adversaries may systematically guess credentials. A future independently evaluated BruteForce label could create this candidate mapping; uploaded flow features do not contain login outcomes."],
    ["T1110.001", "Password Guessing", "credential-access", "Password guessing is an ATT&CK brute-force sub-technique. The current flow analyzer does not observe credential attempts directly."],
    ["T1190", "Exploit Public-Facing Application", "initial-access", "Adversaries may exploit an Internet-facing application. Numeric flow records do not inspect application content, so a label mapping is not proof of exploitation."],
    ["T1059", "Command and Scripting Interpreter", "execution", "Adversaries may abuse command and script interpreters to execute commands. Often follows a successful web exploit."],
    ["T1071", "Application Layer Protocol", "command-and-control", "Adversaries may communicate using application layer protocols to avoid detection. Botnet C2 traffic maps here — the Bot class."],
    ["T1105", "Ingress Tool Transfer", "command-and-control", "Adversaries may transfer tools from an external system into a compromised environment."],
    ["T1041", "Exfiltration Over C2 Channel", "exfiltration", "Adversaries may transfer data over an existing command-and-control channel. A flow label alone cannot prove data theft."],
    ["T1020", "Automated Exfiltration", "exfiltration", "Adversaries may automate data transfer. Confirming this behavior requires independent telemetry beyond a classifier label."],
    ["T1203", "Exploitation for Client Execution", "execution", "Exploiting a software vulnerability in a client application. CyberGuard does not infer this technique from an autoencoder anomaly alone."],
    ["T1595", "Active Scanning", "reconnaissance", "Adversaries may execute active reconnaissance scans to gather information."],
    ["T1078", "Valid Accounts", "defense-evasion", "Adversaries may obtain and abuse credentials of existing accounts."],
    ["T1055", "Process Injection", "privilege-escalation", "Adversaries may inject code into processes to evade defenses."],
    ["T1486", "Data Encrypted for Impact", "impact", "Adversaries may encrypt data to interrupt availability. CyberGuard's uploaded flow schema does not observe file encryption."],
    ["T1562", "Impair Defenses", "defense-evasion", "Adversaries may maliciously modify components of a victim environment to hinder defenses."],
    ["T1021", "Remote Services", "lateral-movement", "Adversaries may use valid accounts to log into a service that accepts remote connections."],
    ["T1005", "Data from Local System", "collection", "Adversaries may search local system sources to find files of interest."],
    ["T1018", "Remote System Discovery", "discovery", "Adversaries may attempt to get a listing of other systems by IP address or hostname."],
    ["T1047", "Windows Management Instrumentation", "execution", "Adversaries may abuse WMI to execute malicious commands."],
    ["T1133", "External Remote Services", "persistence", "Adversaries may leverage external-facing remote services to initially access and persist."],
    ["T1567", "Exfiltration Over Web Service", "exfiltration", "Adversaries may use an existing legitimate external web service to exfiltrate data."],
  ];

  const CLASSES = ["DDoS", "DoS", "PortScan", "BruteForce", "WebAttack", "Bot", "Infiltration"];
  const LABEL_TECH = { DDoS: ["T1498", "T1499"], DoS: ["T1499.002", "T1498"], PortScan: ["T1046"], BruteForce: ["T1110", "T1110.001"], WebAttack: ["T1190", "T1059"], Bot: ["T1071", "T1105"], Infiltration: ["T1041", "T1020"], "unknown-anomaly": [] };

  const now = Date.now() / 1000;
  const rand = (a, b) => a + Math.random() * (b - a);
  const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

  const DEMO_ALERTS = Array.from({ length: 42 }, (_, i) => {
    const unknownSignal = Math.random() < 0.14;
    const type = unknownSignal ? "unknown-anomaly" : pick(CLASSES);
    const conf = unknownSignal ? 0 : rand(0.86, 0.999);
    const sev = unknownSignal ? "high" : conf > 0.98 ? "critical" : conf > 0.9 ? "high" : "medium";
    return {
      id: 1000 + i,
      created_at: now - Math.floor(rand(20, 3400)),
      severity: sev,
      type,
      confidence: +conf.toFixed(3),
      anomaly_score: unknownSignal ? +rand(0.42, 1.8).toFixed(3) : +rand(0.02, 0.3).toFixed(3),
      stage: unknownSignal ? "autoencoder" : "classifier",
      route: unknownSignal ? "unknown_anomaly_review" : "known_attack",
      mitre_techniques: LABEL_TECH[type] || [],
      latency_ms: +rand(0.4, 3.2).toFixed(2),
      source_file: "demo-flow-records.csv",
    };
  }).sort((a, b) => b.created_at - a.created_at);

  const DEMO_SETTINGS = {
    llm_provider: "local",
    llama_url: "http://127.0.0.1:8080",
    local_model: "foundation-sec",
    api_base_url: "https://api.deepseek.com/v1",
    api_model: "deepseek-chat",
    api_key_set: false,
    models: {
      "foundation-sec": { label: "Foundation-Sec-8B (Reasoning)", file: "foundation-sec-8b-reasoning-q4_k_m.gguf", size_gb: 4.9, publisher: "Cisco Foundation AI", vram_gb: 5.6, focus: "Security reasoning, threat intel" },
      "redsage": { label: "RedSage-8B (Qwen3-Instruct)", file: "RedSage-Qwen3-8B-Ins.Q4_K_M.gguf", size_gb: 5.1, publisher: "Khalifa University", vram_gb: 5.8, focus: "Offensive/defensive security Q&A" },
    },
  };

  const CHAT_BRAIN = [
    {
      keys: ["autoencoder", "unknown anomaly", "unknown behavior"],
      a: "#### Autoencoder unknown-anomaly evidence\nA reconstruction error measures deviation from the learned reference distribution. It does not identify an exploit or ATT&CK technique. The bundled artifact is evaluation-only, so this signal requires independent validation and analyst review.",
    },
    {
      keys: ["t1498", "ddos", "denial of service"],
      a: "#### T1498 — Network Denial of Service\nAdversaries may flood a target to degrade availability. Pipeline v2 runs the classifier on every validated row and evaluates statistical/OOD signals independently. A DDoS label creates only a candidate ATT&CK mapping.\n\nThe bundled artifact is evaluation-only and covers only Benign, Bot, DDoS, and PortScan; use independent metrics before trusting a result. Any containment remains an analyst-approved recommendation.",
    },
    {
      keys: ["summarize", "recent", "threats", "containment"],
      a: "#### Recent session summary (demo dataset)\nThis view uses simulated alerts only. Autoencoder results are unknown-anomaly signals requiring independent evidence. Start the backend and upload supported flow records for measured throughput and persisted review cases.",
    },
    {
      keys: ["bertscore", "metric", "f1", "evaluation"],
      a: "#### Why BERTScore was wrong — and what we use instead\nBERTScore measures *text similarity to a reference answer* — not whether an attack was caught. The candidate workflow reports precision, recall, F1, PR-AUC, calibration, confusion counts, review rate, and independent baselines on capture-disjoint data. A new untouched final source is still required before a Pipeline v2 production claim. Demo values are explicitly simulated and are not evaluation results.",
    },
  ];

  /* ---------------- public API surface ---------------- */
  API.getSettings = () =>
    API.mode === "live" ? tryFetch("/api/settings") : Promise.resolve(structuredClone(DEMO_SETTINGS));

  API.updateSettings = (payload) =>
    API.mode === "live"
      ? tryFetch("/api/settings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
      : (Object.assign(DEMO_SETTINGS, {
          llm_provider: payload.llm_provider ?? DEMO_SETTINGS.llm_provider,
          llama_url: payload.llama_url ?? DEMO_SETTINGS.llama_url,
          local_model: payload.local_model ?? DEMO_SETTINGS.local_model,
          api_base_url: payload.api_base_url ?? DEMO_SETTINGS.api_base_url,
          api_model: payload.api_model ?? DEMO_SETTINGS.api_model,
          api_key_set: payload.api_key ? true : DEMO_SETTINGS.api_key_set,
        }), Promise.resolve({ ok: true }));

  API.health = () =>
    API.mode === "live"
      ? tryFetch("/api/settings/provider/health")
      : Promise.resolve({
          ok: false, configured: false, provider: "demo", model: null,
          identity_verified: false, status: "demo_not_checked",
          note: "demo mode makes no provider health claim",
        });

  API.alerts = () =>
    API.mode === "live" ? tryFetch("/api/detect/alerts") : Promise.resolve(structuredClone(DEMO_ALERTS));

  API.upload = async (file) => {
    if (API.mode === "live") {
      const fd = new FormData();
      fd.append("file", file);
      return tryFetch("/api/detect/upload", { method: "POST", body: fd }, 1800000);
    }
    // demo: simulate a pipeline run over the file
    await new Promise((r) => setTimeout(r, 1400));
    const flows = Math.floor(rand(900, 2600));
    const fresh = Array.from({ length: Math.floor(rand(6, 14)) }, (_, i) => {
      const unknownSignal = Math.random() < 0.18;
      const type = unknownSignal ? "unknown-anomaly" : pick(CLASSES);
      const conf = unknownSignal ? 0 : rand(0.87, 0.999);
      return {
        id: 2000 + i, created_at: Date.now() / 1000 - i * 4,
        severity: unknownSignal ? "high" : conf > 0.98 ? "critical" : conf > 0.92 ? "high" : "medium",
        type, confidence: +conf.toFixed(3),
        anomaly_score: unknownSignal ? +rand(0.5, 2.1).toFixed(3) : +rand(0.02, 0.28).toFixed(3),
        stage: unknownSignal ? "autoencoder" : "classifier",
        route: unknownSignal ? "unknown_anomaly_review" : "known_attack",
        mitre_techniques: LABEL_TECH[type] || [],
        latency_ms: +rand(0.4, 3).toFixed(2), source_file: file.name,
      };
    });
    DEMO_ALERTS.unshift(...fresh);
    return {
      demo: true, file: file.name, flows,
      alerts: fresh,
      total_alerts: fresh.length,
      alerts_capped: false,
      alerts_generated: fresh.length,
      alerts_returned: fresh.length,
      alerts_persisted: 0,
      total_parsed: flows,
      accepted: flows,
      rejected: 0,
      analyzed: flows,
      stage_counts: { statistical: Math.floor(flows * 0.72), classifier: fresh.filter(a => a.stage === "classifier").length, autoencoder: fresh.filter(a => a.stage === "autoencoder").length, none: Math.floor(flows * 0.24) },
      throughput_rps: 0,
      feature_importance: [["packets_per_sec", .21], ["syn_flag_count", .17], ["flow_duration", .13], ["bytes_per_sec", .11], ["iat_mean", .09], ["init_win_bytes_fwd", .08], ["packet_length_std", .07], ["flow_bytes_ratio", .06]],
      schema_validation: {
        schema_version: "demo-not-validated",
        detected_input_profile: "demo_simulation",
        recognized_direct_features: [], recognized_aliases: [],
        safely_derivable_features: [], missing_required_features: [],
        ignored_columns: [], invalid_numeric_cell_counts: {},
        rows_rejected: 0, usable_row_count: flows,
        feature_coverage_percentage: 0,
        warnings: ["Demo mode does not parse or validate file contents; all counts are simulated."],
      },
    };
  };

  API.chat = (sessionId, message) => {
    if (API.mode === "live") {
      return tryFetch("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ session_id: sessionId, message }) }, 120000);
    }
    return new Promise((resolve) => {
      const q = message.toLowerCase();
      const hit = CHAT_BRAIN.find((b) => b.keys.some((k) => q.includes(k)));
      const answer = hit ? hit.a :
        "#### Analyst note\nDemo mode contains simulated evidence only. In backend mode, the classifier sees every validated row and anomaly components contribute independent evidence to a deterministic routing policy. ATT&CK label mappings are hypotheses.\n\nTry:\n- *How are unknown anomalies reviewed?*\n- *Explain T1498 and candidate mappings*\n- *Why was BERTScore the wrong metric?*";
      setTimeout(() => resolve({ answer, degraded: false, provider: DEMO_SETTINGS.llm_provider, context_used: true }), 900 + Math.random() * 900);
    });
  };

  API.chatHistory = (sessionId) =>
    API.mode === "live"
      ? tryFetch(`/api/chat/history/${encodeURIComponent(sessionId)}?limit=50`)
      : Promise.resolve([]);

  API.mitreTactics = () =>
    Promise.resolve(["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]);

  API.mitreTechniques = (tactic, q) => {
    if (API.mode === "live") {
      const params = new URLSearchParams();
      if (tactic) params.set("tactic", tactic);
      if (q) params.set("q", q);
      params.set("limit", "500");
      return tryFetch(`/api/mitre/techniques?${params.toString()}`);
    }
    const candidateMapped = new Set(DEMO_ALERTS.filter((a) => a.stage === "classifier").flatMap((a) => a.mitre_techniques));
    let rows = TECHS.map(([id, name, tac, desc]) => ({ id, name, description: desc, tactics: [tac], candidate_mapping: candidateMapped.has(id), mapping_semantics: "demo heuristic classifier-label hypothesis" }));
    if (tactic) rows = rows.filter((t) => t.tactics.includes(tactic));
    if (q) { const s = q.toLowerCase(); rows = rows.filter((t) => t.id.toLowerCase().includes(s) || t.name.toLowerCase().includes(s)); }
    return Promise.resolve(rows);
  };

  API.mitreTechnique = (id) =>
    API.mode === "live"
      ? tryFetch(`/api/mitre/techniques/${encodeURIComponent(id)}`)
      : API.mitreTechniques("", id).then((rows) => ({
          ...rows[0],
          d3fend: {
            candidates: [], mapping_semantics: "candidate defensive techniques",
            originating_attack_validation: "demo_unverified",
            source_health: { available: false, active_version: null },
            operational_limitation: "Demo mode has no indexed D3FEND relationships.",
            executed_action: "none",
          },
        }));

  API.mitreSync = () =>
    API.mode === "live"
      ? tryFetch("/api/mitre/sync", { method: "POST" }, 120000)
      : new Promise((r) => setTimeout(() => r({ status: "cached", version: "v19.1", note: "demo mode — TAXII sync runs when the backend is live" }), 1200));

  API.explainAlert = (alertId) =>
    API.mode === "live"
      ? tryFetch(`/api/detect/explain/${alertId}`, { method: "POST" }, 60000)
      : new Promise((r) => setTimeout(() => r({
          explanation: "Demo mode — start the backend for provider-backed AI explanations.",
          cached: false, degraded: true
        }), 800));

  API.pipelineHealth = () =>
    API.mode === "live"
      ? tryFetch("/api/detect/health")
      : Promise.resolve({
          ready: false, loaded: false, operational_mode: "demo",
          production_approved: false, integrity_verified: false,
          supported_classes: [], trained_classes: [],
          stages: { normalizer: false, statistical_filter: false, classifier: false, autoencoder: false },
          note: "Demo mode — no backend inference or artifact claim",
        });

  API.systemTelemetry = () =>
    API.mode === "live"
      ? tryFetch("/api/settings/system/telemetry")
      : Promise.resolve({
          status: "healthy",
          gpu: { name: "NVIDIA GeForce RTX 5050 Laptop GPU", total_mb: 8151, used_mb: 6822, percent: 83.7, utilization_percent: 5 },
          ram: { total_gb: 16.0, used_gb: 12.4, percent: 77.5 },
          cpu: { percent: 12.0, cores: 16 },
          inference: { engine: "llama-server (Vulkan)", model: "Foundation-Sec-8B (Q4_K_M)", prompt_speed_tps: 81.1, gen_speed_tps: 44.8, status: "active_defense_armed" }
        });

  API.decisionQueue = () =>
    API.mode === "live"
      ? tryFetch("/api/decision/queue?limit=200")
      : Promise.resolve(DEMO_ALERTS.filter(a => a.stage === "autoencoder" || a.severity === "medium").map(a => ({
          alert_id: a.id, event_id: `demo-${a.id}`, created_at: a.created_at,
          type: a.type, severity: a.severity,
          review_reason: "demo ambiguous or unknown signal", decided: false,
          provider: "demo", prompt_version: "smart-decision-v2",
          policy_version: "smart-policy-v2", analyst_verdict: "", reviewed_at: null,
        })));

  API.decisionCase = (alertId) =>
    API.mode === "live"
      ? tryFetch(`/api/decision/case/${alertId}`)
      : Promise.resolve(null);

  API.evaluateDecision = (alertId, refresh = false) =>
    API.mode === "live"
      ? tryFetch(`/api/decision/evaluate/${alertId}`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh }),
        }, 120000)
      : Promise.resolve({
          smart_log: {
            schema_version: "smart-log-v2-demo", event_id: `demo-${alertId}`, alert_id: alertId,
            evidence_fingerprint: "demo-not-cryptographic", review_required: true,
            review_reason: "demo case", detection: {
              type: "unknown-anomaly", severity: "high", stage: "autoencoder",
              confidence: 0, anomaly_score: 1.2, mitre_techniques: [], top_features: [],
            }, trust_boundaries: ["demo data only"],
          },
          decision: {
            verdict: "needs_human", confidence: 0.5, recommended_action: "escalate",
            rationale: "Demo-only policy result; start the backend for persisted review.",
            evidence: [], containment: [], limitations: ["No action was executed."],
            source: "policy", provider: "demo", model_version: "none",
            policy_version: "smart-policy-v2", prompt_version: "none",
            requires_human: true, executed_action: "none", degraded: false,
          }, cached: false,
        });

  API.feedbackDecision = (alertId, verdict, notes) =>
    API.mode === "live"
      ? tryFetch(`/api/decision/feedback/${alertId}`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ verdict, notes }),
        })
      : Promise.resolve({ status: "demo_not_persisted", reviewed_by: "demo" });

  API.actuateAlert = (alertId, action = "block_ip", target = "", mode = "simulation") =>
    API.mode === "live"
      ? tryFetch(`/api/decision/actuate/${alertId}`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action, target, mode }),
        })
      : Promise.resolve({ success: true, simulated: true, action, target, rollback_token: "demo-token" });

  API.rollbackAction = (rollbackToken) =>
    API.mode === "live"
      ? tryFetch(`/api/decision/rollback`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rollback_token: rollbackToken }),
        })
      : Promise.resolve({ success: true, token: rollbackToken });

  API.activeBlocks = () =>
    API.mode === "live"
      ? tryFetch(`/api/decision/active-blocks`)
      : Promise.resolve([]);


  /* ---------------- Suricata Evidence API ---------------- */
  API.uploadSuricataEve = async (file, sensorId = "suricata-default") => {
    if (API.mode !== "live") {
      return Promise.resolve({
        ingestion_id: "demo-suricata-ingest",
        source_file: file.name,
        sensor_id: sensorId,
        adapter_version: "cyberguard-suricata-eve-v1",
        schema_version: "cyberguard-security-event-v1",
        status: "completed",
        total_parsed: 10,
        accepted: 10,
        rejected_lines: 0,
        ignored_unsupported_types: 0,
        counts_by_event_type: { alert: 4, flow: 2, dns: 2, tls: 2 },
        alert_events_accepted: 4,
        eligible_for_persistence: 10,
        persisted: 10,
        omitted_due_to_persistence_cap: 0,
        duplicates_in_upload: 0,
        duplicates_already_persisted: 0,
        newly_persisted_events: 10,
        returned_events_count: 10,
        caps: { max_persist_events: 10000, max_return_events: 500 },
        rejection_reasons: {},
        active_attack_snapshot: { version: "v19.1", version_status: "demo" },
        events: [],
        elapsed_seconds: 0.12,
        executed_action: "none",
      });
    }
    const form = new FormData();
    form.append("file", file);
    const q = sensorId ? `?sensor_id=${encodeURIComponent(sensorId)}` : "";
    return tryFetch(`/api/events/suricata/upload${q}`, { method: "POST", body: form }, 120000);
  };

  API.listSuricataEvents = (params = {}) => {
    if (API.mode !== "live") {
      return Promise.resolve({
        total: 0,
        limit: 100,
        offset: 0,
        events: [],
        executed_action: "none",
      });
    }
    const query = new URLSearchParams(params).toString();
    return tryFetch(`/api/events/suricata/events${query ? "?" + query : ""}`);
  };

  API.getSuricataEvent = (id) => {
    if (API.mode !== "live") {
      return Promise.resolve(null);
    }
    return tryFetch(`/api/events/suricata/events/${id}`);
  };

  API.explainSuricataEvent = (id) => {
    if (API.mode !== "live") {
      return Promise.resolve({
        explanation: "Demo mode — start backend for live advisory analysis.",
        cached: false,
        degraded: true,
        provider: "demo",
        executed_action: "none",
      });
    }
    return tryFetch(`/api/events/suricata/explain/${id}`, { method: "POST" }, 60000);
  };

  API.suricataStats = () => {
    if (API.mode !== "live") {
      return Promise.resolve({
        total_events: 0,
        counts_by_type: { alert: 0, flow: 0, dns: 0, tls: 0 },
        total_ingestions: 0,
        unique_techniques_mapped: 0,
        active_attack_snapshot: { version: null, version_status: "demo" },
        adapter_version: "cyberguard-suricata-eve-v1",
        schema_version: "cyberguard-security-event-v1",
        executed_action: "none",
      });
    }
    return tryFetch("/api/events/suricata/stats");
  };

  API.suricataAttackStatus = () => {
    if (API.mode !== "live") {
      return Promise.resolve({
        available: false,
        version: null,
        version_status: "demo",
      });
    }
    return tryFetch("/api/events/suricata/attack-status");
  };

  API.operationsSnapshot = ({ signal } = {}) => {
    if (API.mode !== "live") {
      return Promise.resolve({
        snapshot_version: "live-operations-v1-demo",
        sequence: { uploaded_flow_records: 0, suricata_eve: 0 },
        generated_at: Date.now() / 1000,
        refresh_mode: "bounded_polling",
        poll_interval_seconds: 4,
        operational_mode: "demo",
        evidence_by_source: {
          uploaded_flow_records: { status: "backend_unavailable", records: [] },
          suricata_eve: { status: "backend_unavailable", records: [] },
          demo_data: { status: "simulated_separate", records: structuredClone(DEMO_ALERTS) },
          future_adapters: { status: "not_configured", records: [] },
        },
        incidents: [], review_exceptions: 0, source_health: {},
        limitations: ["Demo data is simulated and separate from persisted evidence."],
        executed_action: "none",
      });
    }
    return tryFetch("/api/operations/refresh", { method: "POST", signal }, 10000);
  };

  /* ═══ Active Defense, Attack Simulation & Universal Ingestion ═══ */
  API.simulationScenarios = () => tryFetch("/api/simulation/scenarios");
  API.simulationCategories = () => tryFetch("/api/simulation/categories");
  API.runBatchBenchmark = (payload) =>
    tryFetch("/api/simulation/benchmark/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }, 120000);

  API.launchSimulation = (payload) =>
    tryFetch("/api/simulation/launch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }, 90000);

  API.universalIngestFile = (formData) =>
    tryFetch("/api/detect/universal-ingest", {
      method: "POST",
      body: formData,
    }, 90000);

  API.universalIngestRaw = (payload) =>
    tryFetch("/api/detect/universal-ingest/raw", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }, 90000);

  API.activeDefenseBlocks = () => tryFetch("/api/decision/active-blocks");

  API.rollbackAction = (rollbackToken) =>
    tryFetch("/api/decision/rollback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rollback_token: rollbackToken }),
    });

  /* ═══ Authentication & Identity ═══ */
  API.login = async (username, password) => {
    const res = await tryFetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (res && res.access_token) {
      sessionStorage.setItem("cg-auth-token", res.access_token);
      sessionStorage.setItem("cg-auth-user", JSON.stringify(res));
    }
    return res;
  };

  API.getMe = () => tryFetch("/api/auth/me");

  API.logout = () => {
    sessionStorage.removeItem("cg-auth-token");
    sessionStorage.removeItem("cg-auth-user");
  };

  /* ═══ Live Network Sniffer ═══ */
  API.liveSnifferStart = (options = {}) =>
    tryFetch("/api/detect/live/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(options),
    });

  API.liveSnifferStop = () =>
    tryFetch("/api/detect/live/stop", {
      method: "POST",
    });

  API.liveSnifferStatus = () =>
    tryFetch("/api/detect/live/status");

  CG.api = API;
})();
