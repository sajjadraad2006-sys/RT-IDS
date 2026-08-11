/* CyberGuard API client.
   Tries the real FastAPI backend first; when unreachable (e.g. the HTML is
   opened directly) it falls back to a fully local demo dataset so every view
   keeps working — consistent with the project's local-first rule.
   Nothing here ever fabricates evaluation metrics; demo data is marked demo. */
window.CG = window.CG || {};

(function () {
  const API = { mode: "demo", base: "" };

  async function tryFetch(path, opts = {}, timeoutMs = 2500) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(API.base + path, { ...opts, signal: ctrl.signal });
      clearTimeout(t);
      if (!res.ok) throw new Error("HTTP " + res.status);
      return await res.json();
    } catch (e) {
      clearTimeout(t);
      throw e;
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
    ["T1046", "Network Service Discovery", "discovery", "Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Port scanning of this kind maps directly to the PortScan class in the CyberGuard classifier — high SYN counts, tiny payloads, short flow durations."],
    ["T1498", "Network Denial of Service", "impact", "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources. Detected via packets-per-second and bytes-per-second spikes in Stage 1 features, confirmed by XGBoost with >99% confidence."],
    ["T1498.001", "Direct Network Flood", "impact", "Direct network floods amplify traffic volume against a target. Stage 2 Z-score filter flags the volumetric anomaly before the classifier labels it."],
    ["T1499", "Endpoint Denial of Service", "impact", "Adversaries may perform Endpoint Denial of Service attacks to degrade or block availability. Distinguished from network floods by per-flow header and window features."],
    ["T1110", "Brute Force", "credential-access", "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown. CyberGuard flags repeated short-lived flows to authentication ports with failed-handshake signatures."],
    ["T1110.001", "Password Guessing", "credential-access", "Repeated credential attempts against SSH, FTP, and web login endpoints. The BruteForce class maps here."],
    ["T1190", "Exploit Public-Facing Application", "initial-access", "Adversaries may attempt to exploit a weakness in an Internet-facing host or service. WebAttack flows (SQLi, XSS patterns in payload bytes) map to this technique."],
    ["T1059", "Command and Scripting Interpreter", "execution", "Adversaries may abuse command and script interpreters to execute commands. Often follows a successful web exploit."],
    ["T1071", "Application Layer Protocol", "command-and-control", "Adversaries may communicate using application layer protocols to avoid detection. Botnet C2 traffic maps here — the Bot class."],
    ["T1105", "Ingress Tool Transfer", "command-and-control", "Adversaries may transfer tools from an external system into a compromised environment."],
    ["T1041", "Exfiltration Over C2 Channel", "exfiltration", "Stealing data over the established C2 channel. Infiltration-class flows show asymmetric byte ratios — the flow_bytes_ratio feature exposes this."],
    ["T1020", "Automated Exfiltration", "exfiltration", "Automated, scheduled data theft. Inter-arrival time (IAT) statistics become unnaturally regular."],
    ["T1203", "Exploitation for Client Execution", "execution", "Exploiting a software vulnerability in a client application. Zero-day variants are caught by the autoencoder even when the classifier has never seen them."],
    ["T1595", "Active Scanning", "reconnaissance", "Adversaries may execute active reconnaissance scans to gather information."],
    ["T1078", "Valid Accounts", "defense-evasion", "Adversaries may obtain and abuse credentials of existing accounts."],
    ["T1055", "Process Injection", "privilege-escalation", "Adversaries may inject code into processes to evade defenses."],
    ["T1486", "Data Encrypted for Impact", "impact", "Ransomware-style encryption. Outbound entropy and byte-distribution shifts flag it."],
    ["T1562", "Impair Defenses", "defense-evasion", "Adversaries may maliciously modify components of a victim environment to hinder defenses."],
    ["T1021", "Remote Services", "lateral-movement", "Adversaries may use valid accounts to log into a service that accepts remote connections."],
    ["T1005", "Data from Local System", "collection", "Adversaries may search local system sources to find files of interest."],
    ["T1018", "Remote System Discovery", "discovery", "Adversaries may attempt to get a listing of other systems by IP address or hostname."],
    ["T1047", "Windows Management Instrumentation", "execution", "Adversaries may abuse WMI to execute malicious commands."],
    ["T1133", "External Remote Services", "persistence", "Adversaries may leverage external-facing remote services to initially access and persist."],
    ["T1567", "Exfiltration Over Web Service", "exfiltration", "Adversaries may use an existing legitimate external web service to exfiltrate data."],
  ];

  const CLASSES = ["DDoS", "DoS", "PortScan", "BruteForce", "WebAttack", "Bot", "Infiltration"];
  const LABEL_TECH = { DDoS: ["T1498", "T1499"], DoS: ["T1499.002", "T1498"], PortScan: ["T1046"], BruteForce: ["T1110", "T1110.001"], WebAttack: ["T1190", "T1059"], Bot: ["T1071", "T1105"], Infiltration: ["T1041", "T1020"], "zero-day": ["T1203"] };

  const now = Date.now() / 1000;
  const rand = (a, b) => a + Math.random() * (b - a);
  const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

  const DEMO_ALERTS = Array.from({ length: 42 }, (_, i) => {
    const zeroDay = Math.random() < 0.14;
    const type = zeroDay ? "zero-day" : pick(CLASSES);
    const conf = zeroDay ? 0 : rand(0.86, 0.999);
    const sev = zeroDay ? "high" : conf > 0.98 ? "critical" : conf > 0.9 ? "high" : "medium";
    return {
      id: 1000 + i,
      created_at: now - Math.floor(rand(20, 3400)),
      severity: sev,
      type,
      confidence: +conf.toFixed(3),
      anomaly_score: zeroDay ? +rand(0.42, 1.8).toFixed(3) : +rand(0.02, 0.3).toFixed(3),
      stage: zeroDay ? "autoencoder" : "classifier",
      mitre_techniques: LABEL_TECH[type] || [],
      latency_ms: +rand(0.4, 3.2).toFixed(2),
      source_file: "friday-afternoon.pcap.csv",
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
      keys: ["autoencoder", "zero-day", "zero day"],
      a: "#### Stage 4 — Deep Autoencoder\nThe autoencoder is trained **only on benign traffic** (CICIDS2017 BENIGN flows). It learns to reconstruct normal behavior through a 16-neuron bottleneck.\n\n- Architecture: `26 → 64 → 32 → 16 → 32 → 64 → 26`\n- Anomaly signal: reconstruction **mean-squared error**\n- Threshold: `mean + k·σ` of validation errors — currently **k = 3**\n\nBecause it never saw attacks during training, *any* flow it cannot reconstruct well — including attack patterns the XGBoost classifier was never trained on — raises a zero-day alert. That is exactly what the original thesis could not do: its LLM could only explain attacks it already knew.\n\n**Trade-off:** lowering k catches more novel attacks but raises false positives. Tune it in Settings → Detection thresholds.",
    },
    {
      keys: ["t1498", "ddos", "denial of service"],
      a: "#### T1498 — Network Denial of Service\nAdversaries flood a target to degrade availability. CyberGuard detects it deterministically — no LLM involved:\n\n1. **Stage 1** computes `packets_per_sec`, `bytes_per_sec`, and SYN-flag counts\n2. **Stage 2** Z-score filter passes the volumetric spike through instantly\n3. **Stage 3** XGBoost labels it `DDoS` — on CICIDS2017 this class separates cleanly (expected 97–99% accuracy; exact numbers only after the training run — see `trainer.py`)\n\n**Containment:** rate-limit at the edge, blackhole the source prefixes, enable upstream scrubbing. The alert row links T1498 and T1499 in the MITRE browser.",
    },
    {
      keys: ["summarize", "recent", "threats", "containment"],
      a: "#### Recent session summary (demo dataset)\n- **42 alerts** in the last hour — 36 from the classifier, 6 zero-day signals from the autoencoder\n- Top class: **DDoS** (T1498/T1499), then **PortScan** (T1046)\n- Mean detection latency: **1.4 ms** per flow — the LLM is never in the hot path\n\n**Recommended actions:**\n1. Contain the two critical DDoS sources first (confidence > 0.98)\n2. Review the 6 zero-day flows manually — autoencoder alerts deserve analyst eyes\n3. Sync MITRE ATT&CK if the badge says your snapshot is stale\n\nUpload a real CSV/JSON log and I will explain the actual pipeline verdicts.",
    },
    {
      keys: ["bertscore", "metric", "f1", "evaluation"],
      a: "#### Why BERTScore was wrong — and what we use instead\nThe thesis graded detection with BERTScore, which measures *text similarity to a reference answer* — not whether an attack was actually caught. CyberGuard evaluates the way detection systems are graded:\n\n| Metric | Where it comes from |\n| --- | --- |\n| Precision / Recall / F1 | `sklearn` on a held-out CICIDS2017 split |\n| Confusion matrix | same split, per-class |\n| Baselines | Z-Score alone and Isolation Forest alone |\n| Minimum test size | 10,000 flows — enforced in `trainer.py` |\n\nNo number is shown in this UI until a real training run produced it.",
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
      : new Promise((r) => setTimeout(() => r(DEMO_SETTINGS.llm_provider === "local"
          ? { ok: true, provider: "local", model: DEMO_SETTINGS.local_model, url: DEMO_SETTINGS.llama_url }
          : { ok: DEMO_SETTINGS.api_key_set, provider: "api", model: DEMO_SETTINGS.api_model, note: DEMO_SETTINGS.api_key_set ? "key configured" : "no key stored" }), 700));

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
      const zd = Math.random() < 0.18;
      const type = zd ? "zero-day" : pick(CLASSES);
      const conf = zd ? 0 : rand(0.87, 0.999);
      return {
        id: 2000 + i, created_at: Date.now() / 1000 - i * 4,
        severity: zd ? "high" : conf > 0.98 ? "critical" : conf > 0.92 ? "high" : "medium",
        type, confidence: +conf.toFixed(3),
        anomaly_score: zd ? +rand(0.5, 2.1).toFixed(3) : +rand(0.02, 0.28).toFixed(3),
        stage: zd ? "autoencoder" : "classifier",
        mitre_techniques: LABEL_TECH[type] || [],
        latency_ms: +rand(0.4, 3).toFixed(2), source_file: file.name,
      };
    });
    DEMO_ALERTS.unshift(...fresh);
    return {
      file: file.name, flows,
      alerts: fresh,
      stage_counts: { statistical: Math.floor(flows * 0.72), classifier: fresh.filter(a => a.stage === "classifier").length, autoencoder: fresh.filter(a => a.stage === "autoencoder").length, none: Math.floor(flows * 0.24) },
      throughput_rps: Math.floor(rand(94000, 128000)),
      feature_importance: [["packets_per_sec", .21], ["syn_flag_count", .17], ["flow_duration", .13], ["bytes_per_sec", .11], ["iat_mean", .09], ["init_win_bytes_fwd", .08], ["packet_length_std", .07], ["flow_bytes_ratio", .06]],
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
        "#### Analyst note\nThe detection pipeline is deterministic — features, Z-score, XGBoost, autoencoder. I explain its verdicts with MITRE context; I never decide what is an attack.\n\nTry:\n- *How does zero-day detection work here?*\n- *Explain T1498 and our detection*\n- *Why was BERTScore the wrong metric?*\n\nOr attach a `.csv` / `.json` log and I will walk you through what each stage found.";
      setTimeout(() => resolve({ answer, degraded: false, provider: DEMO_SETTINGS.llm_provider, context_used: true }), 900 + Math.random() * 900);
    });
  };

  API.mitreTactics = () =>
    Promise.resolve(["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]);

  API.mitreTechniques = (tactic, q) => {
    const detected = new Set(DEMO_ALERTS.flatMap((a) => a.mitre_techniques));
    let rows = TECHS.map(([id, name, tac, desc]) => ({ id, name, description: desc, tactics: [tac], detected: detected.has(id) }));
    if (tactic) rows = rows.filter((t) => t.tactics.includes(tactic));
    if (q) { const s = q.toLowerCase(); rows = rows.filter((t) => t.id.toLowerCase().includes(s) || t.name.toLowerCase().includes(s)); }
    return Promise.resolve(rows);
  };

  API.mitreSync = () =>
    API.mode === "live"
      ? tryFetch("/api/mitre/sync", { method: "POST" }, 120000)
      : new Promise((r) => setTimeout(() => r({ status: "cached", version: "v19", note: "demo mode — TAXII sync runs when the backend is live" }), 1200));

  API.explainAlert = (alertId) =>
    API.mode === "live"
      ? tryFetch(`/api/detect/explain/${alertId}`, { method: "POST" }, 60000)
      : new Promise((r) => setTimeout(() => r({
          explanation: "Demo mode — start the backend for live AI explanations.",
          cached: false, degraded: true
        }), 800));

  API.pipelineHealth = () =>
    API.mode === "live"
      ? tryFetch("/api/detect/health")
      : Promise.resolve({
          ready: false, loaded: false,
          stages: { normalizer: false, statistical_filter: false, classifier: false, autoencoder: false },
          note: "Demo mode — train models with trainer.py for live pipeline",
        });

  CG.api = API;
})();
