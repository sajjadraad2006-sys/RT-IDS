/* CyberGuard Suricata Evidence Bridge UI.
   Renders imported Suricata EVE IDS evidence and candidate ATT&CK mappings.
   Strictly uses safe DOM APIs (textContent, createElement) without innerHTML. */
window.CG = window.CG || {};

(function () {
  const S = {
    events: [],
    currentTypeFilter: "all",
    selectedEvent: null,
  };

  function el(tag, cls = "", text = "") {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text) node.textContent = text;
    return node;
  }

  /* ---------------- Initialize view ---------------- */
  async function initSuricataView() {
    await Promise.all([loadStats(), loadAttackStatus(), loadEvents()]);
  }

  async function loadAttackStatus() {
    const statusEl = document.getElementById("suricata-attack-status");
    if (!statusEl) return;
    try {
      const data = await CG.api.suricataAttackStatus();
      if (data && data.available && data.version) {
        if (data.official_release_verified) {
          statusEl.textContent = `${data.version} (official release verified · ${data.technique_count || 0} techniques)`;
          statusEl.style.color = "var(--green)";
        } else {
          statusEl.textContent = `${data.version} (Locally hashed; official release not verified · ${data.technique_count || 0} techniques)`;
          statusEl.style.color = "var(--text-muted)";
        }
      } else {
        statusEl.textContent = `Snapshot Unavailable (${data.version_status || "offline"})`;
        statusEl.style.color = "var(--amber)";
      }
    } catch {
      statusEl.textContent = "Snapshot Unavailable (offline)";
      statusEl.style.color = "var(--amber)";
    }
  }

  async function loadStats() {
    try {
      const stats = await CG.api.suricataStats();
      const totalEl = document.getElementById("kpi-suricata-total");
      const alertsEl = document.getElementById("kpi-suricata-alerts");
      const telemEl = document.getElementById("kpi-suricata-telemetry");
      const techEl = document.getElementById("kpi-suricata-techniques");

      if (totalEl) totalEl.textContent = String(stats.total_events || 0);
      if (alertsEl) alertsEl.textContent = String(stats.counts_by_type?.alert || 0);
      const telemetryCount = (stats.counts_by_type?.flow || 0) + (stats.counts_by_type?.dns || 0) + (stats.counts_by_type?.tls || 0);
      if (telemEl) telemEl.textContent = String(telemetryCount);
      if (techEl) techEl.textContent = String(stats.unique_techniques_mapped || 0);
    } catch (e) {
      console.warn("Failed to load Suricata stats:", e);
    }
  }

  async function loadEvents() {
    const tbody = document.getElementById("suricata-table-body");
    if (!tbody) return;

    tbody.textContent = "";
    const loadingRow = el("tr");
    const loadingCell = el("td", "text-muted", "Loading imported Suricata events…");
    loadingCell.setAttribute("colspan", "8");
    loadingRow.appendChild(loadingCell);
    tbody.appendChild(loadingRow);

    try {
      const params = { limit: 150 };
      if (S.currentTypeFilter !== "all") {
        params.event_type = S.currentTypeFilter;
      }
      const data = await CG.api.listSuricataEvents(params);
      S.events = data.events || [];
      renderTable(S.events);
    } catch (err) {
      tbody.textContent = "";
      const errRow = el("tr");
      const errCell = el("td", "text-muted", `Error loading events: ${err.message}`);
      errCell.setAttribute("colspan", "8");
      errRow.appendChild(errCell);
      tbody.appendChild(errRow);
    }
  }

  function renderTable(events) {
    const tbody = document.getElementById("suricata-table-body");
    if (!tbody) return;
    tbody.textContent = "";

    if (!events.length) {
      const emptyRow = el("tr");
      const emptyCell = el("td", "text-muted", "No Suricata events found. Upload an EVE JSON/NDJSON file above to import.");
      emptyCell.setAttribute("colspan", "8");
      emptyRow.appendChild(emptyCell);
      tbody.appendChild(emptyRow);
      return;
    }

    events.forEach((ev) => {
      const tr = el("tr");

      // Time
      const timeCell = el("td", "mono text-muted", ev.timestamp_iso ? ev.timestamp_iso.replace("T", " ").slice(0, 19) : "—");
      tr.appendChild(timeCell);

      // Type Badge
      const typeCell = el("td");
      const typeBadge = el("span", `chip chip-sm type-${ev.source_event_type || "unknown"}`, (ev.source_event_type || "").toUpperCase());
      typeCell.appendChild(typeBadge);
      tr.appendChild(typeCell);

      // Signature / Details
      const sigCell = el("td");
      if (ev.source_event_type === "alert") {
        const sigTitle = el("div", "strong", ev.alert_signature || "Unknown Alert");
        sigCell.appendChild(sigTitle);
        if (ev.alert_signature_id) {
          const sidNote = el("div", "text-muted mono", `SID: ${ev.alert_signature_id}${ev.alert_category ? " · " + ev.alert_category : ""}`);
          sigCell.appendChild(sidNote);
        }
      } else if (ev.source_event_type === "dns") {
        const dnsInfo = ev.evidence?.rrname || "DNS Query";
        sigCell.appendChild(el("div", "mono", dnsInfo));
        if (ev.evidence?.rcode) {
          sigCell.appendChild(el("div", "text-muted", `RCODE: ${ev.evidence.rcode}`));
        }
      } else if (ev.source_event_type === "tls") {
        const sni = ev.evidence?.sni || ev.evidence?.subject || "TLS Session";
        sigCell.appendChild(el("div", "mono", sni));
        if (ev.evidence?.version) {
          sigCell.appendChild(el("div", "text-muted", `TLS Version: ${ev.evidence.version}`));
        }
      } else if (ev.source_event_type === "flow") {
        const flowSummary = `Bytes: ${ev.evidence?.bytes_toserver || 0} ↑ / ${ev.evidence?.bytes_toclient || 0} ↓`;
        sigCell.appendChild(el("div", "mono", flowSummary));
      } else {
        sigCell.appendChild(el("div", "text-muted", "Telemetry event"));
      }
      tr.appendChild(sigCell);

      // Severity (CG-SUR-007: Handle missing/unknown severity without converting to "low")
      const sevCell = el("td");
      const sev = ev.alert_severity ? ev.alert_severity.toLowerCase() : "n/a";
      const sevBadge = el("span", `chip chip-sm sev-${sev}`, sev.toUpperCase());
      sevCell.appendChild(sevBadge);
      tr.appendChild(sevCell);

      // Network 5-tuple
      const netCell = el("td", "mono");
      const src = ev.src_ip ? `${ev.src_ip}:${ev.src_port || ""}` : "—";
      const dst = ev.dest_ip ? `${ev.dest_ip}:${ev.dest_port || ""}` : "—";
      netCell.appendChild(el("div", "", `${src} → ${dst}`));
      if (ev.proto) {
        netCell.appendChild(el("div", "text-muted", `${ev.proto}${ev.app_proto ? "/" + ev.app_proto : ""}`));
      }
      tr.appendChild(netCell);

      // Candidate ATT&CK Badges
      const mitreCell = el("td");
      const techs = ev.mitre_techniques || [];
      if (techs.length > 0) {
        techs.forEach((m) => {
          const badge = el("span", "chip chip-sm chip-mitre", m.technique_id);
          badge.title = `Validation: ${m.validation_status} (rule match observed, technique not confirmed)`;
          badge.style.marginRight = "4px";
          mitreCell.appendChild(badge);
        });
      } else {
        mitreCell.appendChild(el("span", "text-muted", "—"));
      }
      tr.appendChild(mitreCell);

      // Actions Column
      const actionCell = el("td");
      const viewBtn = el("button", "btn btn-outline btn-sm", "Details");
      viewBtn.addEventListener("click", () => openEventModal(ev));
      actionCell.appendChild(viewBtn);
      tr.appendChild(actionCell);

      tbody.appendChild(tr);
    });
  }

  /* ---------------- Modal detail ---------------- */
  function openEventModal(ev) {
    S.selectedEvent = ev;
    const modal = document.getElementById("suricata-detail-modal");
    if (!modal) return;

    const title = document.getElementById("suricata-modal-title");
    if (title) {
      title.textContent = `Event #${ev.id || "—"} · ${ev.source_event_type?.toUpperCase()} · ${ev.alert_signature || ev.proto || "Telemetry"}`;
    }

    const provDiv = document.getElementById("suricata-modal-provenance");
    const evidDiv = document.getElementById("suricata-modal-evidence");
    const mitreDiv = document.getElementById("suricata-modal-mitre");
    const advisoryDiv = document.getElementById("suricata-modal-advisory");

    // 1. Provenance
    if (provDiv) {
      provDiv.textContent = "";
      const grid = el("div", "modal-meta-grid");

      const addField = (lbl, val) => {
        const item = el("div", "meta-item");
        item.appendChild(el("span", "meta-label", lbl));
        item.appendChild(el("span", "meta-value mono", String(val ?? "—")));
        grid.appendChild(item);
      };

      addField("Database ID", ev.id);
      addField("Deterministic Event Ref", ev.event_ref);
      addField("Ingestion ID", ev.ingestion_id);
      addField("Sensor ID", ev.sensor_id);
      addField("Source Line", ev.source_line_number);
      addField("Timestamp (UTC)", ev.timestamp_iso);
      addField("Event Type", ev.source_event_type);
      addField("Schema Version", ev.schema_version);
      addField("Adapter Version", ev.adapter_version);
      addField("Source Sensor Action", ev.source_sensor_action || "Unknown / Not specified");
      addField("CyberGuard Executed Action", ev.executed_action || "Autonomous Containment Armed");

      provDiv.appendChild(grid);
    }

    // 2. Canonical Security Evidence
    if (evidDiv) {
      evidDiv.textContent = "";
      const box = el("div", "panel", "");
      box.style.background = "var(--surface)";
      box.style.padding = "var(--s3)";
      box.style.borderRadius = "var(--radius)";

      const netLine = el("div", "mono", `Network 5-Tuple: ${ev.src_ip || "—"}:${ev.src_port || ""} → ${ev.dest_ip || "—"}:${ev.dest_port || ""} (${ev.proto || "IP"}${ev.app_proto ? "/" + ev.app_proto : ""})`);
      netLine.style.marginBottom = "var(--s2)";
      box.appendChild(netLine);

      if (ev.flow_id || ev.community_id) {
        const flowLine = el("div", "mono text-muted", `Flow ID: ${ev.flow_id || "—"} | Community ID: ${ev.community_id || "—"}`);
        flowLine.style.marginBottom = "var(--s2)";
        box.appendChild(flowLine);
      }

      const pre = el("pre", "mono", JSON.stringify(ev.evidence || {}, null, 2));
      pre.style.background = "var(--surface-2)";
      pre.style.padding = "var(--s2)";
      pre.style.borderRadius = "var(--radius)";
      pre.style.maxHeight = "160px";
      pre.style.overflowY = "auto";
      box.appendChild(pre);

      evidDiv.appendChild(box);
    }

    // 3. Candidate ATT&CK Mappings
    if (mitreDiv) {
      mitreDiv.textContent = "";
      const notice = el("p", "text-muted", "Semantics: Evidence-supported candidate ATT&CK mapping. A rule match is observed evidence of the rule firing; it is not conclusive proof that the full technique occurred.");
      notice.style.fontSize = "var(--step--1)";
      notice.style.marginBottom = "var(--s2)";
      mitreDiv.appendChild(notice);

      const techs = ev.mitre_techniques || [];
      if (!techs.length) {
        mitreDiv.appendChild(el("p", "text-muted", "No ATT&CK technique metadata extracted for this event."));
      } else {
        const list = el("div", "tech-cards-list");
        techs.forEach((m) => {
          const card = el("div", "panel");
          card.style.background = "var(--surface)";
          card.style.padding = "var(--s3)";
          card.style.marginBottom = "var(--s2)";
          card.style.borderRadius = "var(--radius)";

          const header = el("div", "strong", `Technique: ${m.technique_id} ${m.tactic_id ? "(" + m.tactic_id + ")" : ""}`);
          card.appendChild(header);

          const statusLine = el("div", "text-muted mono", `Validation Status: ${m.validation_status} | Extraction Fidelity: ${m.metadata_extraction_confidence ?? 1.0} | Technique Occurrence: Unconfirmed (Candidate Mapping)`);
          statusLine.style.fontSize = "var(--step--1)";
          card.appendChild(statusLine);

          const semLine = el("div", "text-muted", `Semantics: ${m.mapping_semantics} (rule_match_observed: ${m.rule_match_observed}, technique_observed: ${m.technique_observed})`);
          semLine.style.fontSize = "var(--step--1)";
          card.appendChild(semLine);

          if (m.snapshot_version) {
            const snapLine = el("div", "text-muted", `Validated against ATT&CK Snapshot: ${m.snapshot_version}`);
            snapLine.style.fontSize = "var(--step--1)";
            card.appendChild(snapLine);
          }

          list.appendChild(card);
        });
        mitreDiv.appendChild(list);
      }
    }

    // 4. Advisory Panel
    if (advisoryDiv) {
      advisoryDiv.textContent = "";
      if (ev.explanation) {
        renderAdvisoryCard(advisoryDiv, ev.explanation, "cached");
      } else {
        const promptNote = el("p", "text-muted", "No advisory summary generated yet. Click 'Generate LLM Advisory' below to run analysis with deterministic fallback.");
        advisoryDiv.appendChild(promptNote);
      }
    }

    modal.hidden = false;
    modal.classList.add("is-open");
  }

  function closeEventModal() {
    const modal = document.getElementById("suricata-detail-modal");
    if (modal) {
      modal.hidden = true;
      modal.classList.remove("is-open");
    }
    S.selectedEvent = null;
  }

  async function explainSelectedEvent() {
    if (!S.selectedEvent) return;
    const advisoryDiv = document.getElementById("suricata-modal-advisory");
    const explainBtn = document.getElementById("btn-suricata-explain");

    if (explainBtn) explainBtn.disabled = true;
    if (advisoryDiv) {
      advisoryDiv.textContent = "Requesting advisory analysis from CyberGuard…";
    }

    try {
      const res = await CG.api.explainSuricataEvent(S.selectedEvent.id);
      S.selectedEvent.explanation = res.explanation;
      if (advisoryDiv) {
        advisoryDiv.textContent = "";
        renderAdvisoryCard(advisoryDiv, res.explanation, res.provider, res.degraded);
      }
    } catch (err) {
      if (advisoryDiv) {
        advisoryDiv.textContent = "";
        const errP = el("p", "text-muted", `Advisory generation failed: ${err.message}`);
        advisoryDiv.appendChild(errP);
      }
    } finally {
      if (explainBtn) explainBtn.disabled = false;
    }
  }

  function renderAdvisoryCard(container, explanationText, provider = "unknown", isDegraded = false) {
    const card = el("div", "panel");
    card.style.background = "var(--surface)";
    card.style.padding = "var(--s3)";
    card.style.borderRadius = "var(--radius)";

    const badgeLine = el("div", "flex items-center gap-2", "");
    badgeLine.style.marginBottom = "var(--s2)";

    const provBadge = el("span", "chip chip-sm", `Provider: ${provider}`);
    badgeLine.appendChild(provBadge);

    if (isDegraded || provider === "deterministic_fallback") {
      const fbBadge = el("span", "chip chip-sm chip-amber", "Deterministic Fallback");
      badgeLine.appendChild(fbBadge);
    }
    card.appendChild(badgeLine);

    const body = el("pre", "mono", explanationText);
    body.style.whiteSpace = "pre-wrap";
    body.style.wordBreak = "break-word";
    body.style.fontSize = "var(--step-0)";
    card.appendChild(body);

    container.appendChild(card);
  }

  /* ---------------- Upload & Report ---------------- */
  async function handleFileUpload(file) {
    const reportPanel = document.getElementById("suricata-upload-report");
    if (!file) return;

    if (reportPanel) {
      reportPanel.hidden = false;
      reportPanel.textContent = `Uploading and parsing ${file.name}…`;
    }

    try {
      const res = await CG.api.uploadSuricataEve(file);
      renderUploadReport(res);
      await Promise.all([loadStats(), loadEvents()]);
      CG.toast?.(`Ingested ${res.accepted} events from ${file.name}`);
    } catch (err) {
      if (reportPanel) {
        reportPanel.hidden = false;
        reportPanel.textContent = "";
        const errHead = el("h3", "text-red", "Suricata Ingestion Failed");
        const errMsg = el("p", "text-muted", err.message || "Upload rejected");
        reportPanel.appendChild(errHead);
        reportPanel.appendChild(errMsg);
      }
    }
  }

  function renderUploadReport(rep) {
    const panel = document.getElementById("suricata-upload-report");
    if (!panel) return;
    panel.hidden = false;
    panel.textContent = "";

    const head = el("h3", "strong", `Suricata Ingestion Report: ${rep.source_file}`);
    panel.appendChild(head);

    const metaGrid = el("div", "modal-meta-grid");
    metaGrid.style.marginTop = "var(--s2)";
    metaGrid.style.marginBottom = "var(--s2)";

    const addStat = (lbl, val) => {
      const d = el("div", "meta-item");
      d.appendChild(el("span", "meta-label", lbl));
      d.appendChild(el("span", "meta-value mono", String(val)));
      metaGrid.appendChild(d);
    };

    addStat("Total Parsed", rep.total_parsed);
    addStat("Accepted", rep.accepted);
    addStat("Newly Persisted", rep.newly_persisted_events);
    addStat("Alert Events Accepted", rep.alert_events_accepted);
    addStat("Duplicates in File", rep.duplicates_in_upload);
    addStat("Duplicates Already in DB", rep.duplicates_already_persisted);
    addStat("Omitted by Cap", rep.omitted_due_to_persistence_cap);
    addStat("Returned in Response", rep.returned_events_count ?? rep.events?.length ?? 0);
    addStat("Persistence Cap", rep.caps?.max_persist_events ?? 10000);
    addStat("Return Cap", rep.caps?.max_return_events ?? 500);
    addStat("Ignored Unsupported", rep.ignored_unsupported_types);
    addStat("Rejected Lines", rep.rejected_lines);
    addStat("Elapsed Time", `${rep.elapsed_seconds}s`);

    panel.appendChild(metaGrid);

    if (rep.rejection_reasons && Object.keys(rep.rejection_reasons).length > 0) {
      const reasHead = el("div", "text-amber strong", "Recoverable Rejection Reasons:");
      panel.appendChild(reasHead);
      const reasList = el("ul", "mono text-muted");
      for (const [r, cnt] of Object.entries(rep.rejection_reasons)) {
        reasList.appendChild(el("li", "", `${r}: ${cnt} line(s)`));
      }
      panel.appendChild(reasList);
    }
  }

  /* ---------------- Event Listeners ---------------- */
  document.addEventListener("DOMContentLoaded", () => {
    // Upload triggers
    const fileInput = document.getElementById("suricata-upload-input");
    const uploadBtn = document.getElementById("btn-suricata-upload");
    const refreshBtn = document.getElementById("btn-suricata-refresh");
    const modalClose = document.getElementById("suricata-modal-close");
    const explainBtn = document.getElementById("btn-suricata-explain");

    if (uploadBtn && fileInput) {
      uploadBtn.addEventListener("click", () => fileInput.click());
      fileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files[0]) {
          handleFileUpload(e.target.files[0]);
          fileInput.value = "";
        }
      });
    }

    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => {
        loadStats();
        loadEvents();
      });
    }

    if (modalClose) {
      modalClose.addEventListener("click", closeEventModal);
    }

    if (explainBtn) {
      explainBtn.addEventListener("click", explainSelectedEvent);
    }

    // Filter buttons
    document.querySelectorAll(".suricata-type-filter").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".suricata-type-filter").forEach((b) => b.classList.remove("is-active"));
        btn.classList.add("is-active");
        S.currentTypeFilter = btn.dataset.type || "all";
        loadEvents();
      });
    });
  });

  CG.onView = CG.onView || {};
  CG.onView.suricata = initSuricataView;
})();
