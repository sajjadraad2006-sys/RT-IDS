/* Analyst chat — ChatGPT-style interface.
   Markdown-lite rendering, log-file attachment with inline analysis cards,
   provider-aware. Model evidence is always presented with its limitations. */
(function () {
  const messages = document.getElementById("chat-messages");
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const upload = document.getElementById("chat-upload");
  const session = "session-" + (localStorage.getItem("cg-session") ||
    (() => {
      const id = crypto.randomUUID ? crypto.randomUUID() :
        crypto.getRandomValues(new Uint32Array(4)).join("-");
      localStorage.setItem("cg-session", id);
      return id;
    })());
  let historyLoaded = false;

  const avatarAI = `<div class="msg-avatar"><svg><use href="#i-shield"/></svg></div>`;
  const avatarUser = `<div class="msg-avatar"><svg><use href="#i-doc"/></svg></div>`;

  function scrollBottom() {
    messages.scrollTo({ top: messages.scrollHeight, behavior:
      matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
  }

  function addUser(text) {
    const el = document.createElement("div");
    el.className = "msg msg-user reveal is-in";
    el.innerHTML = `${avatarUser}<div class="msg-body"><p>${CG.util.esc(text)}</p></div>`;
    messages.appendChild(el);
    scrollBottom();
  }

  function addAI(markdown, meta) {
    const el = document.createElement("div");
    el.className = "msg msg-ai reveal is-in";
    el.innerHTML = `${avatarAI}<div class="msg-body">${CG.util.md(markdown)}` +
      (meta ? `<div class="msg-meta">${CG.util.esc(meta)}</div>` : "") + `</div>`;
    messages.appendChild(el);
    scrollBottom();
  }

  function addTyping() {
    const el = document.createElement("div");
    el.className = "msg msg-ai";
    el.id = "typing-row";
    el.innerHTML = `${avatarAI}<div class="msg-body"><span class="typing"><i></i><i></i><i></i></span></div>`;
    messages.appendChild(el);
    scrollBottom();
  }

  function removeTyping() {
    document.getElementById("typing-row")?.remove();
  }

  /* inline analysis card after a log upload */
  function addAnalysisCard(file, res) {
    const byStage = res.stage_counts || {};
    const schema = res.schema_validation || res.schema_report || {};
    const top = res.alerts.slice(0, 4);
    const returned = res.alerts_returned ?? res.alerts.length;
    const generated = res.alerts_generated ?? res.total_alerts ?? returned;
    const persisted = res.alerts_persisted ?? res.smart_logs_created ?? 0;
    const coverage = res.demo
      ? "not validated (demo)"
      : schema.feature_coverage_percentage == null
        ? "not reported"
        : `${Number(schema.feature_coverage_percentage).toFixed(1)}%`;
    const el = document.createElement("div");
    el.className = "msg msg-ai reveal is-in";
    el.innerHTML = `${avatarAI}<div class="msg-body">
      <h4>${res.demo ? "Demo simulation" : "Offline flow analysis"} — ${CG.util.esc(file)}</h4>
      <div class="analysis-card">
        <header><span>${CG.util.fmtNum(res.flows)} flows processed</span>
          <span class="mono">${CG.util.fmtNum(res.throughput_rps)} rec/s</span></header>
        <div class="ac-body">
          <div class="ac-row"><span>Schema profile / coverage</span><span class="mono">${CG.util.esc(schema.detected_input_profile || schema.detected_profile || "unknown")} · ${CG.util.esc(coverage)}</span></div>
          <div class="ac-row"><span>Classifier alerts</span><span class="mono">${byStage.classifier ?? 0}</span></div>
          <div class="ac-row"><span>Statistical evidence signals</span><span class="mono">${CG.util.fmtNum(byStage.statistical || 0)}</span></div>
          <div class="ac-row"><span>Unknown-anomaly signals</span><span class="mono">${byStage.autoencoder ?? 0}</span></div>
          <div class="ac-row"><span>Alerts generated / returned / persisted</span><span class="mono">${generated} / ${returned} / ${persisted}</span></div>
        </div>
      </div>
      ${top.length ? `<p>Top alerts:</p><ul>${top.map((a) =>
        `<li><strong>${CG.util.esc(a.type)}</strong> — ${a.severity}${a.confidence ? ` · ${(a.confidence * 100).toFixed(1)}%` : ""} · route evidence <code>${CG.util.esc(a.stage)}</code>${(a.mitre_techniques || []).length ? ` · candidate mapping ${a.mitre_techniques.map(CG.util.esc).join(", ")}` : ""}</li>`).join("")}</ul>` : ""}
      <p>Full breakdown is on the <strong>Dashboard</strong>.</p>
    </div>`;
    messages.appendChild(el);
    scrollBottom();
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    addUser(text);
    addTyping();
    try {
      const res = await CG.api.chat(session, text);
      removeTyping();
      addAI(res.answer,
        `${res.provider === "api" ? "API provider" : "local model"} · ${res.context_used ? "relevant ATT&CK context attached" : "no relevant ATT&CK context"} · ${res.operational_mode || CG.api.mode}${res.degraded ? " · degraded" : ""}`);
    } catch (err) {
      removeTyping();
      addAI("LLM provider unavailable. Detection pipeline and MITRE browser still work — check **Settings → AI provider**.", "error");
    }
  });

  /* suggestion chips */
  document.querySelectorAll("#chat-suggestions [data-q]").forEach((b) =>
    b.addEventListener("click", () => {
      input.value = b.dataset.q;
      form.requestSubmit();
    }));

  /* log attachment */
  document.getElementById("btn-chat-upload").addEventListener("click", () => upload.click());
  upload.addEventListener("change", async () => {
    const file = upload.files[0];
    upload.value = "";
    if (!file) return;
    if (!/\.(csv|tsv|json|ndjson|jsonl)$/i.test(file.name)) {
      addAI("Supported input is headered `.csv`/`.tsv`, JSON objects/arrays, or `.ndjson`/`.jsonl`. Raw/headerless text is rejected.", "attachment rejected");
      return;
    }
    addUser(`Analyze attached log: ${file.name}`);
    addTyping();
    try {
      const res = await CG.api.upload(file);
      removeTyping();
      addAnalysisCard(file.name, res);
      CG.onView.dashboard && (CG.util.toast("Dashboard updated with new alerts — switch views to inspect."));
    } catch (err) {
      removeTyping();
      const schema = err.detail?.schema_validation;
      const schemaNote = schema
        ? `\n\nSchema profile: **${schema.detected_input_profile || "unsupported"}**; coverage: **${Number(schema.feature_coverage_percentage || 0).toFixed(1)}%**; rejected rows: **${schema.rows_rejected || 0}**.`
        : "";
      addAI("Analysis failed: " + err.message + schemaNote, "error");
    }
  });

  CG.onView.chat = async () => {
    if (!historyLoaded) {
      historyLoaded = true;
      try {
        const history = await CG.api.chatHistory(session);
        if (history.length) {
          messages.innerHTML = "";
          history.forEach((item) => item.role === "user"
            ? addUser(item.content)
            : addAI(item.content, "restored from this session"));
        }
      } catch {
        addAI("Stored chat history is unavailable; this does not affect detection.", "history unavailable");
      }
    }
    scrollBottom();
  };
})();
