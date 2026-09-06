/* Bounded polling controller and Live Operations view. */
window.CG = window.CG || {};

(function (root) {
  "use strict";

  const SOURCE_KEYS = [
    "uploaded_flow_records", "suricata_eve", "demo_data", "future_adapters",
  ];

  function normalizeOperationsEvidence(snapshot) {
    const grouped = {};
    const sources = snapshot?.evidence_by_source || {};
    SOURCE_KEYS.forEach((source) => {
      const seen = new Set();
      grouped[source] = (sources[source]?.records || [])
        .filter((record) => {
          const key = String(record.event_ref ?? `${record.id}:${record.timestamp}`);
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        })
        .slice(0, 500)
        .sort((a, b) => Number(b.timestamp || 0) - Number(a.timestamp || 0)
          || String(a.event_ref || "").localeCompare(String(b.event_ref || "")));
    });
    return grouped;
  }

  class LiveOperationsPoller {
    constructor({
      fetchSnapshot,
      applySnapshot,
      onState = () => {},
      documentRef = document,
      intervalMs = 4000,
      setIntervalFn = setInterval,
      clearIntervalFn = clearInterval,
    }) {
      this.fetchSnapshot = fetchSnapshot;
      this.applySnapshot = applySnapshot;
      this.onState = onState;
      this.documentRef = documentRef;
      this.intervalMs = Math.max(3000, Math.min(Number(intervalMs) || 4000, 5000));
      this.setIntervalFn = setIntervalFn;
      this.clearIntervalFn = clearIntervalFn;
      this.inFlight = null;
      this.controller = null;
      this.requestSequence = 0;
      this.timer = null;
      this.paused = false;
      this.lastSuccess = null;
      this.lastError = null;
      this.visibilityHandler = () => {
        if (this.documentRef.hidden) {
          if (this.controller) this.controller.abort();
          this.onState({ status: "paused_hidden", lastSuccess: this.lastSuccess, lastError: this.lastError });
        } else if (!this.paused) {
          this.refresh({ supersede: true });
        }
      };
      this.documentRef.addEventListener("visibilitychange", this.visibilityHandler);
    }

    refresh({ supersede = false } = {}) {
      if (this.documentRef.hidden || this.paused) {
        this.onState({
          status: this.documentRef.hidden ? "paused_hidden" : "paused_manual",
          lastSuccess: this.lastSuccess,
          lastError: this.lastError,
        });
        return Promise.resolve(null);
      }
      if (this.inFlight && !supersede) return this.inFlight;
      if (this.inFlight && this.controller) this.controller.abort();

      const requestId = ++this.requestSequence;
      const controller = new AbortController();
      this.controller = controller;
      this.onState({ status: "connecting", lastSuccess: this.lastSuccess, lastError: this.lastError });
      let request;
      try {
        request = this.fetchSnapshot({ signal: controller.signal });
      } catch (error) {
        request = Promise.reject(error);
      }
      const promise = Promise.resolve(request)
        .then((snapshot) => {
          if (requestId !== this.requestSequence || controller.signal.aborted) return null;
          this.lastSuccess = Date.now() / 1000;
          this.lastError = null;
          this.applySnapshot(snapshot);
          this.onState({ status: "connected", lastSuccess: this.lastSuccess, lastError: null });
          return snapshot;
        })
        .catch((error) => {
          if (requestId !== this.requestSequence || error?.name === "AbortError") return null;
          this.lastError = String(error?.message || error);
          this.onState({
            status: this.lastSuccess ? "degraded" : "disconnected",
            lastSuccess: this.lastSuccess,
            lastError: this.lastError,
          });
          return null;
        })
        .finally(() => {
          if (requestId === this.requestSequence) {
            this.inFlight = null;
            this.controller = null;
          }
        });
      this.inFlight = promise;
      return promise;
    }

    tick() {
      return this.refresh({ supersede: false });
    }

    start() {
      if (!this.timer) this.timer = this.setIntervalFn(() => this.tick(), this.intervalMs);
      return this.refresh({ supersede: false });
    }

    setPaused(paused) {
      this.paused = Boolean(paused);
      if (this.paused && this.inFlight) {
        if (this.controller) this.controller.abort();
        this.requestSequence += 1;
        this.inFlight = null;
        this.controller = null;
      }
      this.onState({
        status: this.paused ? "paused_manual" : "resuming",
        lastSuccess: this.lastSuccess,
        lastError: this.lastError,
      });
      if (!this.paused) this.refresh({ supersede: true });
    }

    stop() {
      this.suspend();
      this.documentRef.removeEventListener("visibilitychange", this.visibilityHandler);
    }

    suspend() {
      if (this.timer) this.clearIntervalFn(this.timer);
      this.timer = null;
      if (this.controller) this.controller.abort();
      this.requestSequence += 1;
      this.inFlight = null;
    }
  }

  root.normalizeOperationsEvidence = normalizeOperationsEvidence;
  root.LiveOperationsPoller = LiveOperationsPoller;

  if (typeof document === "undefined") return;
  const view = document.getElementById("view-operations");
  if (!view) return;
  const esc = (value) => root.util.esc(value);
  const statusEl = document.getElementById("operations-connection-state");
  const lastSuccessEl = document.getElementById("operations-last-success");
  const lastErrorEl = document.getElementById("operations-last-error");
  const pauseButton = document.getElementById("operations-pause");
  let paused = false;

  function paintState(state) {
    statusEl.textContent = state.status.replaceAll("_", " ");
    statusEl.dataset.status = state.status;
    lastSuccessEl.textContent = state.lastSuccess
      ? new Date(state.lastSuccess * 1000).toLocaleTimeString() : "never";
    lastErrorEl.textContent = state.lastError || "none";
  }

  function rows(records, source) {
    if (!records.length) return `<tr><td colspan="5" class="text-muted">No ${esc(source)} records persisted.</td></tr>`;
    return records.slice(0, 50).map((item) => `<tr>
      <td class="mono">${esc(root.util.fmtTime(item.timestamp))}</td>
      <td>${esc(source)}</td>
      <td>${esc(item.type || item.source_event_type || item.signature || "evidence")}</td>
      <td><span class="sev-badge sev-${esc(item.severity || "info")}">${esc(item.severity || "info")}</span></td>
      <td>${esc(item.triage?.state || item.mapping_semantics || "evidence only")}</td>
    </tr>`).join("");
  }

  function paint(snapshot) {
    const grouped = normalizeOperationsEvidence(snapshot);
    document.getElementById("operations-mode").textContent = snapshot.operational_mode;
    document.getElementById("operations-limitations").textContent = snapshot.limitations.join(" · ");
    document.getElementById("operations-uploaded-count").textContent = grouped.uploaded_flow_records.length;
    document.getElementById("operations-suricata-count").textContent = grouped.suricata_eve.length;
    document.getElementById("operations-incident-count").textContent = snapshot.incidents.length;
    document.getElementById("operations-review-count").textContent = snapshot.review_exceptions;
    document.getElementById("operations-uploaded-body").innerHTML = rows(grouped.uploaded_flow_records, "uploaded flow");
    document.getElementById("operations-suricata-body").innerHTML = rows(grouped.suricata_eve, "Suricata EVE");
    document.getElementById("operations-incidents-body").innerHTML = snapshot.incidents.length
      ? snapshot.incidents.map((incident) => {
          const risk = incident.risk || {};
          const components = Object.entries(risk.components || {}).map(([name, item]) =>
            `<li><strong>${esc(name)}</strong>: ${Number(item.contribution || 0).toFixed(1)} · ${esc(item.evidence || "missing")}${item.warning ? ` · <span class="text-amber">${esc(item.warning)}</span>` : ""}</li>`
          ).join("");
          return `<tr><td class="mono">${esc(incident.incident_id)}</td><td>${esc(incident.severity)}</td><td>${Number(incident.evidence_count)}</td><td>${Number(incident.duplicate_count)}</td><td><details><summary>${Number(risk.score || 0).toFixed(1)} · ${esc(risk.formula_version || "unversioned")}</summary><ul class="rule-list">${components}</ul><small>${esc((risk.limitations || []).join(" · "))}</small></details></td><td>${esc(incident.triage_state)}</td></tr>`;
        }).join("")
      : `<tr><td colspan="6" class="text-muted">No correlated incidents.</td></tr>`;
    const health = snapshot.source_health || {};
    document.getElementById("operations-health-body").innerHTML = Object.entries(health)
      .map(([name, value]) => {
        const status = value.stale === true ? "stale" : value.freshness_status
          || value.status || value.version_status || (value.available ? "available" : "unavailable");
        const reference = value.source_date || value.active_version || value.version
          || value.freshest_event_at || value.indexed_at || "—";
        return `<tr><td>${esc(name)}</td><td>${esc(status)}</td><td>${esc(reference)}</td></tr>`;
      }).join("");
  }

  const poller = new LiveOperationsPoller({
    fetchSnapshot: ({ signal }) => root.api.operationsSnapshot({ signal }),
    applySnapshot: paint,
    onState: paintState,
  });
  document.getElementById("operations-refresh").addEventListener("click", () => poller.refresh({ supersede: true }));
  pauseButton.addEventListener("click", () => {
    paused = !paused;
    poller.setPaused(paused);
    pauseButton.textContent = paused ? "Resume" : "Pause";
    pauseButton.setAttribute("aria-pressed", String(paused));
  });
  root.onView.operations = () => poller.start();
  root.onLeave.operations = () => poller.suspend();
})(window.CG);
