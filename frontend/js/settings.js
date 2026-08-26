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
  let currentHealth = null;

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
    currentHealth = await CG.api.health().catch(() => ({ ok: false }));
    await CG.util.paintProvider();
    paintModels(currentHealth);
    status.classList.remove("err");
    status.textContent = "saved · provider = " + provider + (key ? " · key stored encrypted" : "");
    document.getElementById("set-api-key").value = "";
    CG.util.toast("Settings saved.");
  });

  document.getElementById("btn-health-check").addEventListener("click", async () => {
    status.classList.remove("err");
    status.textContent = "testing connection…";
    const h = await CG.api.health();
    currentHealth = h;
    if (h.ok) {
      status.textContent = h.identity_verified
        ? `reachable · ${h.provider} · actual model ${h.model}`
        : `reachable · ${h.provider} · actual model identity unavailable`;
    } else if (h.configured) {
      status.classList.add("err");
      status.textContent = `configured but not connectivity-tested · ${h.model || "model unknown"}`;
    } else {
      status.classList.add("err");
      status.textContent = `unreachable · ${h.note || h.error || "check server URL / API key"}`;
    }
  });

  /* ---------- models view ---------- */
  function modelIdentityMatches(keyId, model, health) {
    if (!health?.ok || !health.identity_verified || !health.model) return false;
    const actual = String(health.model).toLowerCase().replace(/[^a-z0-9]/g, "");
    const key = keyId.toLowerCase().replace(/[^a-z0-9]/g, "");
    const file = String(model.file).toLowerCase().replace(/[^a-z0-9]/g, "");
    return actual.includes(key) || actual.includes(file.replace(/gguf$/, ""));
  }

  function paintModels(health = currentHealth) {
    if (!current) return;
    const grid = document.getElementById("model-cards");
    const selected = current.local_model;
    grid.innerHTML = Object.entries(current.models).map(([keyId, m]) => {
      const isSelected = current.llm_provider === "local" && keyId === selected;
      const isServed = isSelected && modelIdentityMatches(keyId, m, health);
      return `
      <article class="model-card ${isServed ? "is-loaded" : ""}">
        ${isServed
          ? `<span class="mc-loaded-tag"><span class="dot dot-ok"></span>served</span>`
          : isSelected ? `<span class="mc-loaded-tag"><span class="dot dot-warn"></span>selected only</span>` : ""}
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
          ${isSelected
            ? `<button class="btn" disabled>${isServed ? "Confirmed by provider" : "Configuration selected"}</button>`
            : `<button class="btn btn-primary" data-load="${keyId}"><svg><use href="#i-bolt"/></svg>Select configuration</button>`}
        </div>
      </article>`;
    }).join("");
    grid.querySelectorAll("[data-load]").forEach((b) =>
      b.addEventListener("click", async () => {
        await CG.api.updateSettings({ llm_provider: "local", local_model: b.dataset.load });
        current = await CG.api.getSettings();
        currentHealth = await CG.api.health().catch(() => ({ ok: false }));
        await CG.util.paintProvider();
        paintModels(currentHealth);
        CG.util.toast("Model configuration selected. Provider health must confirm what is actually served.");
        const m = current.models[b.dataset.load];
        document.getElementById("meter-vram").style.width = "0%";
        document.getElementById("meter-vram-val").textContent = `${m.vram_gb} GB catalog estimate`;
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
    [current, currentHealth] = await Promise.all([
      CG.api.getSettings(), CG.api.health().catch(() => ({ ok: false })),
    ]);
    paintModels(currentHealth);
    const selected = current.models[current.local_model];
    document.getElementById("meter-vram").style.width = "0%";
    document.getElementById("meter-vram-val").textContent = selected
      ? `${selected.vram_gb} GB catalog estimate`
      : "No catalog estimate";
  };
})();
