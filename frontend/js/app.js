/* CyberGuard app shell — hash router, reveal motion, shared utils, particles.
   Motion rules (from the design system): transform+opacity only,
   expo-out easing, whole stagger sequences finish under ~0.8s. */
window.CG = window.CG || {};

(function () {
  /* ---------------- utils ---------------- */
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const fmtNum = (n) => n >= 1e6 ? (n / 1e6).toFixed(1) + "M"
    : n >= 1e3 ? (n / 1e3).toFixed(1) + "k" : String(n);

  const fmtTime = (ts) => {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  const timeAgo = (ts) => {
    const s = Math.max(1, Math.floor(Date.now() / 1000 - ts));
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    return Math.floor(s / 3600) + "h ago";
  };

  let toastTimer = 0;
  function toast(msg, ms = 3400) {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.classList.add("is-visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove("is-visible"), ms);
  }

  /* ---------------- markdown-lite (safe: escapes first, then formats) ---------------- */
  function md(src) {
    let html = esc(src);
    // fenced code
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) =>
      `<pre><code>${code.replace(/\n$/, "")}</code></pre>`);
    // tables
    html = html.replace(/(?:^|\n)((?:\|[^\n]+\|\n?)+)/g, (m, block) => {
      const rows = block.trim().split("\n").filter((r) => !/^\|[\s\-:|]+\|$/.test(r.trim()));
      if (!rows.length) return m;
      const cells = (r) => r.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
      const head = cells(rows[0]);
      const body = rows.slice(1).map(cells);
      return "\n<table><thead><tr>" + head.map((c) => `<th>${c}</th>`).join("") +
        "</tr></thead><tbody>" + body.map((r) => "<tr>" + r.map((c) => `<td>${c}</td>`).join("") + "</tr>").join("") +
        "</tbody></table>";
    });
    // headings ####
    html = html.replace(/^####\s+(.+)$/gm, "<h4>$1</h4>");
    // bold / italic / inline code
    html = html.replace(/`([^`\n]+)`/g, "<code>$1</code>");
    html = html.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
    html = html.replace(/(^|[\s(])\*([^*\n]+)\*/g, "$1<em>$2</em>");
    // lists
    html = html.replace(/(?:^|\n)((?:\d+\.\s[^\n]+\n?)+)/g, (m, b) =>
      "\n<ol>" + b.trim().split("\n").map((l) => `<li>${l.replace(/^\d+\.\s*/, "")}</li>`).join("") + "</ol>");
    html = html.replace(/(?:^|\n)((?:-\s[^\n]+\n?)+)/g, (m, b) =>
      "\n<ul>" + b.trim().split("\n").map((l) => `<li>${l.replace(/^-\s*/, "")}</li>`).join("") + "</ul>");
    // paragraphs
    html = html.split(/\n{2,}/).map((p) =>
      /^\s*<(h4|pre|table|ul|ol)/.test(p) ? p : `<p>${p.replace(/\n/g, "<br>")}</p>`).join("");
    return html;
  }

  /* ---------------- reveal on scroll ---------------- */
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add("is-in"); io.unobserve(e.target); }
    });
  }, { threshold: 0.08 });
  function watchReveals(root = document) {
    root.querySelectorAll(".reveal:not(.is-in)").forEach((el) => io.observe(el));
  }

  /* ---------------- router ---------------- */
  const views = ["dashboard", "review", "chat", "mitre", "models", "settings"];
  function route(view) {
    if (!views.includes(view)) view = "dashboard";
    document.querySelectorAll(".nav-item").forEach((b) =>
      b.classList.toggle("is-active", b.dataset.view === view));
    document.querySelectorAll(".view").forEach((v) =>
      v.classList.toggle("is-active", v.id === "view-" + view));
    if (location.hash !== "#" + view) history.replaceState(null, "", "#" + view);
    CG.onView?.[view]?.();
    watchReveals(document.getElementById("view-" + view));
    window.scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });
  }

  document.querySelectorAll(".nav-item").forEach((b) =>
    b.addEventListener("click", () => route(b.dataset.view)));
  window.addEventListener("hashchange", () => route(location.hash.slice(1)));

  /* ---------------- particle background ---------------- */
  function initParticles() {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const canvas = document.createElement("canvas");
    canvas.id = "particle-canvas";
    document.body.insertBefore(canvas, document.body.firstChild);
    const ctx = canvas.getContext("2d");
    let W, H, particles = [];

    function resize() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener("resize", resize);

    const N = Math.min(40, Math.floor(window.innerWidth / 30));
    for (let i = 0; i < N; i++) {
      particles.push({
        x: Math.random() * W,
        y: Math.random() * H,
        r: 1 + Math.random() * 1.5,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        alpha: 0.15 + Math.random() * 0.25,
      });
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);
      for (const p of particles) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x = W;
        if (p.x > W) p.x = 0;
        if (p.y < 0) p.y = H;
        if (p.y > H) p.y = 0;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(94,159,232,${p.alpha})`;
        ctx.fill();
      }
      // draw faint connections between nearby particles
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 140) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(94,159,232,${0.08 * (1 - dist / 140)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }
      requestAnimationFrame(draw);
    }
    draw();
  }

  /* ---------------- provider badge + boot ---------------- */
  async function paintProvider() {
    const [s, health] = await Promise.all([
      CG.api.getSettings(),
      CG.api.health().catch(() => ({ ok: false, status: "unreachable" })),
    ]);
    const label = document.getElementById("provider-label");
    const dot = document.getElementById("provider-dot");
    const tag = document.getElementById("chat-provider-tag");
    if (CG.api.mode === "demo") {
      label.textContent = "Demo · provider simulated";
      tag.textContent = "demo · no provider call";
      dot.className = "dot dot-warn";
      return;
    }
    if (s.llm_provider === "local") {
      const configured = s.local_model === "redsage" ? "RedSage-8B" : "Foundation-Sec-8B";
      const actual = health.identity_verified && health.model ? health.model : null;
      label.textContent = health.ok
        ? actual ? "Local ready · " + actual : "Local reachable · identity unknown"
        : "Local unavailable · selected " + configured;
      tag.textContent = health.ok
        ? actual ? "local · " + actual : "local · identity unverified"
        : "local unavailable";
      dot.className = health.ok ? "dot dot-ok" : "dot dot-err";
    } else {
      label.textContent = health.configured
        ? "API configured · reachability unverified"
        : "API not configured";
      tag.textContent = "api · " + (s.api_model || "model unset") + " · unverified";
      dot.className = "dot dot-warn";
    }
  }

  async function paintOperationalState(prefetched) {
    const banner = document.getElementById("operational-banner");
    const engine = document.getElementById("engine-status");
    const dot = document.getElementById("engine-dot");
    if (CG.api.mode === "demo") {
      banner.className = "operational-banner mode-demo";
      banner.textContent = "Demo — all alerts and upload results are simulated and kept separate from backend records.";
      engine.textContent = "Demo · no backend inference";
      dot.className = "dot dot-warn";
      return;
    }
    try {
      const health = prefetched || await CG.api.pipelineHealth();
      const classes = health.supported_classes || health.trained_classes || [];
      const scope = classes.length ? classes.join(", ") : "no independently supported class scope reported";
      if (!health.ready || !health.integrity_verified) {
        banner.className = "operational-banner mode-unavailable";
        banner.textContent = "Unavailable — artifact integrity/readiness failed; inference is blocked closed.";
        engine.textContent = "Pipeline unavailable";
        dot.className = "dot dot-err";
      } else if (health.production_approved) {
        banner.className = "operational-banner mode-production";
        banner.textContent = `Production-approved for explicit scope only: ${scope}. Uploaded flow analysis; no live ingestion.`;
        engine.textContent = "Production-approved · scoped";
        dot.className = "dot dot-ok";
      } else {
        banner.className = "operational-banner";
        banner.textContent = `Evaluation-only — active artifact is not production approved. Trained scope: ${scope}. Results require validation.`;
        engine.textContent = "Evaluation-only artifacts";
        dot.className = "dot dot-warn";
      }
    } catch {
      banner.className = "operational-banner mode-unavailable";
      banner.textContent = "Unavailable — backend health could not be read; no readiness claim is made.";
      engine.textContent = "Health unavailable";
      dot.className = "dot dot-err";
    }
  }

  document.getElementById("provider-badge").addEventListener("click", () => route("settings"));

  CG.util = { esc, fmtNum, fmtTime, timeAgo, toast, md, watchReveals, paintProvider, paintOperationalState, route };
  CG.onView = {};

  document.addEventListener("DOMContentLoaded", async () => {
    initParticles();
    const mode = await CG.api.init();
    await Promise.all([paintProvider(), paintOperationalState()]);
    route(location.hash.slice(1) || "dashboard");
    watchReveals();
    // dismiss loading screen
    const ls = document.getElementById("loading-screen");
    if (ls) { ls.classList.add("is-gone"); setTimeout(() => ls.remove(), 600); }
  });

  /* keyboard shortcuts: Ctrl+1-6 switch views */
  document.addEventListener("keydown", (e) => {
    if (!e.ctrlKey || e.shiftKey || e.altKey) return;
    const idx = parseInt(e.key) - 1;
    if (idx >= 0 && idx < views.length) { e.preventDefault(); route(views[idx]); }
  });
})();
