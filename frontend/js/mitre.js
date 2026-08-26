/* ATT&CK browser — technique reference plus explicitly heuristic classifier
   label mappings, detail panel, and snapshot/RAG synchronization status. */
(function () {
  const list = document.getElementById("mitre-list");
  const detail = document.getElementById("mitre-detail");
  const search = document.getElementById("mitre-search");
  const tacticSel = document.getElementById("mitre-tactic-filter");
  const syncBtn = document.getElementById("mitre-sync-btn");
  const syncStatus = document.getElementById("mitre-sync-status");

  let techniques = [];
  let loaded = false;

  const titleCase = (t) => t.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

  async function load() {
    if (loaded) return;
    loaded = true;
    const tactics = await CG.api.mitreTactics();
    tacticSel.innerHTML = `<option value="">All tactics</option>` +
      tactics.map((t) => `<option value="${t}">${titleCase(t)}</option>`).join("");
    await refresh();
  }

  async function refresh() {
    techniques = await CG.api.mitreTechniques(tacticSel.value, search.value.trim());
    paint();
  }

  function paint() {
    if (!techniques.length) {
      list.innerHTML = `<div class="mitre-detail-empty"><svg class="empty-icon"><use href="#i-search"/></svg><p>No techniques match. Try a different ID or name.</p></div>`;
      return;
    }
    list.innerHTML = techniques.map((t) => `
      <button class="tech-item" data-id="${CG.util.esc(t.id)}" role="listitem">
        <span class="tid">${CG.util.esc(t.id)}</span>
        <span class="tname">${CG.util.esc(t.name)}</span>
        ${t.candidate_mapping ? `<span class="tdetected">candidate map</span>` : ""}
      </button>`).join("");
    list.querySelectorAll(".tech-item").forEach((b) =>
      b.addEventListener("click", () => select(b.dataset.id)));
  }

  function select(id) {
    list.querySelectorAll(".tech-item").forEach((b) =>
      b.classList.toggle("is-active", b.dataset.id === id));
    const t = techniques.find((x) => x.id === id);
    if (!t) return;
    detail.innerHTML = `
      <span class="detail-id">${CG.util.esc(t.id)}</span>
      <h3 class="detail-name">${CG.util.esc(t.name)}</h3>
      <p class="detail-desc">${CG.util.esc(t.description)}</p>
      <div class="detail-tactics">${t.tactics.map((x) => `<span class="chip">${CG.util.esc(titleCase(x))}</span>`).join("")}</div>
      <div class="detail-meta">
        <span>Source: MITRE ATT&amp;CK Enterprise v19.1 (TAXII 2.1)</span>
        ${t.candidate_mapping
          ? `<span style="color:var(--amber)">Possible technique based on a persisted classifier label (${Number(t.candidate_mapping_count || 1)} mapping records). This is not observed behavior.</span>`
          : `<span>No persisted classifier-label hypothesis points to this technique.</span>`}
        <span>Mapping semantics: heuristic hypothesis; unknown-anomaly evidence creates no mapping.</span>
        <span>attack.mitre.org/techniques/${CG.util.esc(t.id.replace(".", "/"))}</span>
      </div>`;
  }

  let debounce = 0;
  search.addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(refresh, 220);
  });
  tacticSel.addEventListener("change", refresh);

  syncBtn.addEventListener("click", async () => {
    syncBtn.disabled = true;
    syncStatus.textContent = "syncing from attack-taxii.mitre.org…";
    try {
      const res = await CG.api.mitreSync();
      syncStatus.textContent = res.status === "synced"
        ? `ATT&CK ${res.version} · ${res.indexed ?? ""} techniques · RAG ${res.rag_synchronized ? "synchronized" : "not synchronized"}`
        : `ATT&CK ${res.version || "v19.1"} · ${res.note || res.status}`;
      CG.util.toast(res.status === "synced" ? "ATT&CK snapshot updated." : "Sync skipped — using cached snapshot.");
    } catch {
      syncStatus.textContent = "sync failed — cached data active";
      CG.util.toast("TAXII sync failed; local snapshot remains available offline.");
    } finally {
      syncBtn.disabled = false;
    }
  });

  CG.onView.mitre = load;
})();
