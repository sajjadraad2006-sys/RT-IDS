/* Analyst review queue: minimal Smart Log evidence, guarded decision, feedback. */
(function () {
  let queue = [];
  let selectedId = null;

  const esc = (value) => CG.util.esc(value ?? "");
  const list = (items) => (items || []).map(item => `<li>${esc(item)}</li>`).join("");

  function paintQueue() {
    const body = document.getElementById("review-queue-body");
    document.getElementById("review-count").textContent = `${queue.length} cases`;
    if (!queue.length) {
      body.innerHTML = `<tr><td colspan="4" class="text-muted" style="text-align:center;padding:32px">No ambiguous or unknown cases are waiting.</td></tr>`;
      return;
    }
    body.innerHTML = queue.map(item => `
      <tr data-case-id="${Number(item.alert_id)}" class="${item.alert_id === selectedId ? "is-selected" : ""}">
        <td class="mono">${esc(CG.util.fmtTime(item.created_at))}</td>
        <td><span class="sev-badge sev-${esc(item.severity)}">${esc(item.severity)}</span></td>
        <td><strong>${esc(item.type)}</strong><br><small class="text-muted">${esc(item.review_reason)}</small></td>
        <td>${item.reviewed_at ? `<span class="text-green">reviewed</span>` : item.decided ? "decision ready" : "pending"}</td>
      </tr>`).join("");
    body.querySelectorAll("[data-case-id]").forEach(row => row.addEventListener("click", () => {
      openCase(Number(row.dataset.caseId));
    }));
  }

  function decisionHtml(decision) {
    if (!decision) return `<p class="text-muted">No decision support has been requested yet.</p>`;
    const isMitigated = decision.executed_action && decision.executed_action !== "none";
    const rollbackBtn = decision.rollback_token
      ? `<button class="btn btn-sm btn-warn" id="btn-rollback-action" data-token="${esc(decision.rollback_token)}" style="margin-top:8px">Rollback Mitigation (${esc(decision.rollback_token)})</button>`
      : "";
    return `
      <dl class="modal-meta">
        <dt>Verdict</dt><dd>${esc(decision.verdict)}</dd>
        <dt>Recommendation</dt><dd>${esc(decision.recommended_action)}</dd>
        <dt>Source</dt><dd>${esc(decision.source)}</dd>
        <dt>Provider / model</dt><dd>${esc(decision.provider)} / ${esc(decision.model_version)}</dd>
        <dt>Policy / prompt</dt><dd>${esc(decision.policy_version)} / ${esc(decision.prompt_version)}</dd>
        <dt>Executed action</dt><dd><strong>${esc(decision.executed_action)}</strong> ${isMitigated ? `<span class="badge text-cyan">ACTIVE DEFENSE</span>` : ""}</dd>
      </dl>
      ${rollbackBtn}
      <p class="review-rationale">${esc(decision.rationale)}</p>
      <h4>Evidence</h4><ul class="rule-list">${list(decision.evidence)}</ul>
      <h4>Limitations</h4><ul class="rule-list">${list(decision.limitations)}</ul>`;
  }


  async function openCase(alertId) {
    selectedId = alertId;
    paintQueue();
    const detail = document.getElementById("review-detail");
    detail.innerHTML = `<p class="text-muted">Loading case ${alertId}…</p>`;
    try {
      let data = await CG.api.decisionCase(alertId);
      if (!data) {
        const evaluated = await CG.api.evaluateDecision(alertId);
        data = {};
        data.smart_log = evaluated.smart_log;
        data.decision = evaluated.decision;
        data.feedback = data.feedback || {};
        data.audit = data.audit || [];
      }
      const smart = data.smart_log;
      const detection = smart.detection;
      detail.innerHTML = `
        <div class="panel-head"><h2 class="panel-title">Case #${Number(alertId)}</h2><span class="mono text-muted">${esc(smart.schema_version)}</span></div>
        <section class="review-section"><h3>Smart Log evidence</h3>
          <dl class="modal-meta">
            <dt>Event</dt><dd>${esc(smart.event_id)}</dd>
            <dt>Fingerprint</dt><dd class="fingerprint">${esc(smart.evidence_fingerprint)}</dd>
            <dt>Detection</dt><dd>${esc(detection.type)} · ${esc(detection.stage)}</dd>
            <dt>Confidence</dt><dd>${Number(detection.confidence || 0).toFixed(3)}</dd>
            <dt>Anomaly score</dt><dd>${Number(detection.anomaly_score || 0).toFixed(3)}</dd>
            <dt>MITRE</dt><dd>${esc((detection.mitre_techniques || []).join(", ") || "none")}</dd>
          </dl>
          <p class="review-reason">${esc(smart.review_reason)}</p>
        </section>
        <section class="review-section">
          <div class="panel-head">
            <h3>Guarded decision</h3>
            <div style="display:flex;gap:6px">
              <button class="btn btn-primary" id="review-actuate">Execute Mitigation</button>
              <button class="btn" id="review-evaluate">${data.decision ? "Re-evaluate" : "Evaluate decision"}</button>
            </div>
          </div>
          <div id="review-decision">${decisionHtml(data.decision)}</div>
        </section>
        <section class="review-section"><h3>Analyst feedback</h3>
          <form id="review-feedback-form" class="settings-form">
            <div class="field"><label class="field-label" for="review-verdict">Verdict</label><select class="select" id="review-verdict"><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="benign">Benign</option><option value="needs_human">Needs another analyst</option></select></div>
            <div class="field"><label class="field-label" for="review-notes">Evidence notes (max 2,000 chars)</label><textarea id="review-notes" maxlength="2000" rows="4"></textarea></div>
            <button class="btn btn-primary" type="submit">Record reviewed verdict</button>
            <small class="field-hint">Identity is assigned by the authenticated server; feedback never retrains the active model.</small>
          </form>
        </section>
        <section class="review-section"><h3>Audit events</h3><ul class="audit-list">${(data.audit || []).map(event => `<li><span>${esc(event.action)}</span><code>${esc(event.event_hash).slice(0, 16)}…</code></li>`).join("") || "<li>No events returned yet.</li>"}</ul></section>`;

      if (data.feedback?.verdict) document.getElementById("review-verdict").value = data.feedback.verdict;
      if (data.feedback?.notes) document.getElementById("review-notes").value = data.feedback.notes;

      function bindRollbackBtn() {
        const rbBtn = document.getElementById("btn-rollback-action");
        if (rbBtn) {
          rbBtn.addEventListener("click", async () => {
            const token = rbBtn.dataset.token;
            rbBtn.disabled = true;
            rbBtn.textContent = "Rolling back…";
            try {
              const res = await CG.api.rollbackAction(token);
              if (res.success) {
                CG.util.toast("Mitigation rolled back successfully!");
                await openCase(alertId);
              } else {
                CG.util.toast("Failed to rollback mitigation");
              }
            } catch (err) {
              CG.util.toast("Rollback error: " + err.message);
            }
          });
        }
      }
      bindRollbackBtn();

      document.getElementById("review-actuate").addEventListener("click", async () => {
        const btn = document.getElementById("review-actuate");
        btn.disabled = true;
        btn.textContent = "Actuating…";
        try {
          const res = await CG.api.actuateAlert(alertId, "block_ip", "", "simulation");
          if (res.success) {
            CG.util.toast(`Mitigation executed (${res.simulated ? "Simulated" : "Live"}): ${res.command_executed}`);
            await openCase(alertId);
          } else {
            CG.util.toast("Actuation blocked: " + (res.error || "Guardrail violation"));
          }
        } catch (err) {
          CG.util.toast("Actuation failed: " + err.message);
        } finally {
          btn.disabled = false;
          btn.textContent = "Execute Mitigation";
        }
      });

      document.getElementById("review-evaluate").addEventListener("click", async () => {
        const button = document.getElementById("review-evaluate");
        button.disabled = true;
        button.textContent = "Evaluating…";
        try {
          const result = await CG.api.evaluateDecision(alertId, true);
          document.getElementById("review-decision").innerHTML = decisionHtml(result.decision);
          bindRollbackBtn();
          CG.util.toast("Guarded decision refreshed.");
        } catch (error) { CG.util.toast("Decision failed: " + error.message); }
        finally { button.disabled = false; button.textContent = "Re-evaluate"; }
      });

      document.getElementById("review-feedback-form").addEventListener("submit", async event => {
        event.preventDefault();
        const verdict = document.getElementById("review-verdict").value;
        const notes = document.getElementById("review-notes").value;
        try {
          const result = await CG.api.feedbackDecision(alertId, verdict, notes);
          CG.util.toast(`Feedback recorded as ${verdict} by ${result.reviewed_by}.`);
          await refreshQueue(false);
        } catch (error) { CG.util.toast("Feedback failed: " + error.message); }
      });
    } catch (error) {
      detail.innerHTML = `<p style="color:var(--red)">Unable to load case: ${esc(error.message)}</p>`;
    }
  }

  async function refreshQueue(clearSelection = true) {
    if (clearSelection) selectedId = null;
    try { queue = await CG.api.decisionQueue(); }
    catch (error) { queue = []; CG.util.toast("Review queue unavailable: " + error.message); }
    paintQueue();
  }

  document.getElementById("review-refresh").addEventListener("click", () => refreshQueue());
  CG.onView.review = () => refreshQueue(false);
})();
