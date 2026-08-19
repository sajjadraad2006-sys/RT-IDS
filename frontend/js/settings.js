/* Settings + Models views.
   Provider switch (local llama.cpp / external API), encrypted-key note,
   detection thresholds, connection test, and the model management cards. */
(function () {
  const segLocal = document.getElementById("seg-local");
  const segApi = document.getElementById("seg-api");
  const paneLocal = document.getElementById("pane-local");
  const paneApi = document.getElementById("pane-api");
  const form = document.getElementById("settings-form");
  const status = document.getElementById("settings-status");

  let current = null;

  function setProviderUI(provider) {
    segLocal.classList.toggle("is-active", provider === "local");
    segApi.classList.toggle("is-active", provider === "api");
    paneLocal.hidden = provider !== "local";
    paneApi.hidden = provider !== "api";
  }

  segLocal.addEventListener("click", () => setProviderUI("local"));
  segApi.addEventListener("click", () => setProviderUI("api"));

  /* sliders */
  const conf = document.getElementById("set-threshold-conf");
  const k = document.getElementById("set-threshold-k");
  conf.addEventListener("input", () => document.getElementById("conf-val").textContent = (+conf.value).toFixed(2));
  k.addEventListener("input", () => document.getElementById("k-val").textContent = (+k.value).toFixed(1));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const provider = segApi.classList.contains("is-active") ? "api" : "local";
    const payload = {
      llm_provider: provider,
      llama_url: document.getElementById("set-llama-url").value.trim(),
      local_model: document.getElementById("set-local-model").value,
      api_base_url: document.getElementById("set-api-base").value.trim(),
      api_model: document.getElementById("set-api-model").value.trim(),
    };
    const key = document.getElementById("set-api-key").value.trim();
    if (key) payload.api_key = key;
    await CG.api.updateSettings(payload);
    current = await CG.api.getSettings();
    await CG.util.paintProvider();
    paintModels();
    status.classList.remove("err");
    status.textContent = "saved · provider = " + provider + (key ? " · key stored encrypted" : "");
    document.getElementById("set-api-key").value = "";
    CG.util.toast("Settings saved.");
  });

  document.getElementById("btn-health-check").addEventListener("click", async () => {
    status.classList.remove("err");
    status.textContent = "testing connection…";
    const h = await CG.api.health();
    if (h.ok) {
      status.textContent = `connected · ${h.provider} · ${h.model || ""}`;
    } else {
      status.classList.add("err");
      status.textContent = `unreachable · ${h.note || h.error || "check server URL / API key"}`;
    }
  });

  /* ---------- models view ---------- */
  function paintModels() {
    if (!current) return;
    const grid = document.getElementById("model-cards");
    const active = current.local_model;
    grid.innerHTML = Object.entries(current.models).map(([keyId, m]) => {
      const isLoaded = current.llm_provider === "local" && keyId === active;
      return `
      <article class="model-card ${isLoaded ? "is-loaded" : ""}">
        ${isLoaded ? `<span class="mc-loaded-tag"><span class="dot dot-ok"></span>loaded</span>` : ""}
        <div class="mc-top">
          <span class="mc-icon"><svg><use href="#i-chip"/></svg></span>
          <div><h3>${m.label}</h3><span class="mc-pub">${m.publisher}</span></div>
        </div>
        <dl class="mc-specs">
          <dt>File</dt><dd>${m.file}</dd>
          <dt>Disk size</dt><dd>${m.size_gb} GB</dd>
          <dt>Est. VRAM</dt><dd>${m.vram_gb} GB</dd>
          <dt>Focus</dt><dd>${m.focus}</dd>
        </dl>
        <div class="mc-actions">
          ${isLoaded
            ? `<button class="btn" disabled>Active in chat</button>`
            : `<button class="btn btn-primary" data-load="${keyId}"><svg><use href="#i-bolt"/></svg>Load this model</button>`}
        </div>
      </article>`;
    }).join("");
    grid.querySelectorAll("[data-load]").forEach((b) =>
      b.addEventListener("click", async () => {
        await CG.api.updateSettings({ llm_provider: "local", local_model: b.dataset.load });
        current = await CG.api.getSettings();
        await CG.util.paintProvider();
        paintModels();
        CG.util.toast("Model switched — chat now uses " + current.models[b.dataset.load].label);
        // nudge VRAM meter to the newly loaded model
        const m = current.models[b.dataset.load];
        const pct = Math.min(100, Math.round((m.vram_gb / 8) * 100));
        document.getElementById("meter-vram").style.width = pct + "%";
        document.getElementById("meter-vram-val").textContent = `${m.vram_gb} / 8.0 GB`;
      }));
    CG.util.watchReveals(grid);
  }

  CG.onView.settings = async () => {
    const [settingsData, health] = await Promise.all([
      CG.api.getSettings(), CG.api.pipelineHealth(),
    ]);
    current = settingsData;
    setProviderUI(current.llm_provider);
    document.getElementById("set-llama-url").value = current.llama_url;
    document.getElementById("set-local-model").value = current.local_model;
    document.getElementById("set-api-base").value = current.api_base_url;
    document.getElementById("set-api-model").value = current.api_model;
    if (health.classifier_abstention_threshold != null) {
      conf.value = health.classifier_abstention_threshold;
      document.getElementById("conf-val").textContent = Number(conf.value).toFixed(2);
    }
    if (health.autoencoder_k != null) {
      k.value = health.autoencoder_k;
      document.getElementById("k-val").textContent = Number(k.value).toFixed(1);
    }
    status.textContent = "";
  };

  CG.onView.models = async () => {
    current = await CG.api.getSettings();
    paintModels();
  };
})();
