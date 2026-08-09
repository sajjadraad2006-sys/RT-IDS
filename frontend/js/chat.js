/* Analyst chat — ChatGPT-style interface.
   Markdown-lite rendering, log-file attachment with inline analysis cards,
   provider-aware. The pipeline verdict is always presented as ground truth. */
(function () {
  const messages = document.getElementById("chat-messages");
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const upload = document.getElementById("chat-upload");
  const session = "session-" + (localStorage.getItem("cg-session") ||
    (() => { const id = Math.random().toString(36).slice(2); localStorage.setItem("cg-session", id); return id; })());

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
    const top = res.alerts.slice(0, 4);
    const el = document.createElement("div");
    el.className = "msg msg-ai reveal is-in";
    el.innerHTML = `${avatarAI}<div class="msg-body">
      <h4>Pipeline analysis — ${CG.util.esc(file)}</h4>
      <div class="analysis-card">
        <header><span>${CG.util.fmtNum(res.flows)} flows processed</span>
          <span class="mono">${CG.util.fmtNum(res.throughput_rps)} rec/s</span></header>
        <div class="ac-body">
          <div class="ac-row"><span>Stage 2 · Z-score flagged</span><span class="mono">${CG.util.fmtNum(byStage.statistical || 0)}</span></div>
          <div class="ac-row"><span>Stage 3 · classifier alerts</span><span class="mono">${byStage.classifier ?? 0}</span></div>
          <div class="ac-row"><span>Stage 4 · zero-day signals</span><span class="mono">${byStage.autoencoder ?? 0}</span></div>
        </div>
      </div>
      ${top.length ? `<p>Top alerts:</p><ul>${top.map((a) =>
        `<li><strong>${CG.util.esc(a.type)}</strong> — ${a.severity}${a.confidence ? ` · ${(a.confidence * 100).toFixed(1)}%` : ""} · caught by <code>${a.stage}</code>${a.mitre_techniques.length ? ` · ${a.mitre_techniques.join(", ")}` : ""}</li>`).join("")}</ul>` : ""}
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
        `${res.provider === "api" ? "API provider" : "local model"} · ${res.context_used ? "MITRE context attached" : "no context"}${res.degraded ? " · degraded" : ""}`);
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
    if (!/\.(csv|json)$/i.test(file.name)) {
      addAI("Only `.csv` or `.json` log files are supported.", "attachment rejected");
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
      addAI("Analysis failed: " + CG.util.esc(err.message), "error");
    }
  });

  CG.onView.chat = () => scrollBottom();
})();
