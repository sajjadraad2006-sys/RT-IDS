import puppeteer from 'puppeteer-core';

const fig1Svg = `<div id="fig1-container" style="width: 100%; max-width: 760px; margin: 16px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<svg viewBox="0 0 760 380" width="100%" height="auto" xmlns="http://www.w3.org/2000/svg" style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
  <defs>
    <linearGradient id="headerGrad1" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#1e3a8a" />
    </linearGradient>
    <marker id="arr1Blue" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#2563eb" />
    </marker>
    <marker id="arr1Green" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#16a34a" />
    </marker>
  </defs>

  <!-- Banner Header -->
  <rect x="0" y="0" width="760" height="34" rx="8" fill="url(#headerGrad1)" />
  <rect x="0" y="24" width="760" height="10" fill="url(#headerGrad1)" />
  <text x="380" y="22" text-anchor="middle" font-size="12" font-weight="700" fill="#ffffff" letter-spacing="0.5">
    CONCEPTUAL OVERVIEW: MODERN HYBRID RT-IDS IN CONTEMPORARY SOC OPERATIONS
  </text>

  <!-- Col 1: Ingestion -->
  <rect x="15" y="46" width="215" height="320" rx="6" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
  <text x="122" y="66" text-anchor="middle" font-size="10" font-weight="700" fill="#1e293b">1. ENTERPRISE INGESTION</text>

  <g transform="translate(25, 78)">
    <rect width="195" height="50" rx="4" fill="#ffffff" stroke="#64748b" stroke-width="1.2" />
    <text x="97" y="18" text-anchor="middle" font-size="9.5" font-weight="700" fill="#0f172a">Raw Network Traffic</text>
    <text x="97" y="32" text-anchor="middle" font-size="8" fill="#475569">Physical NIC / Promiscuous</text>
    <text x="97" y="44" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#0284c7">AF_PACKET Raw Sockets</text>
  </g>

  <g transform="translate(25, 138)">
    <rect width="195" height="50" rx="4" fill="#ffffff" stroke="#64748b" stroke-width="1.2" />
    <text x="97" y="18" text-anchor="middle" font-size="9.5" font-weight="700" fill="#0f172a">Suricata EVE Streams</text>
    <text x="97" y="32" text-anchor="middle" font-size="8" fill="#475569">NIDS alert log bridge</text>
    <text x="97" y="44" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#0284c7">/var/log/suricata/eve.json</text>
  </g>

  <path d="M122, 188 L122, 206" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr1Blue)" />

  <g transform="translate(25, 208)">
    <rect width="195" height="56" rx="4" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5" />
    <text x="97" y="18" text-anchor="middle" font-size="9.5" font-weight="700" fill="#1e3a8a">Flow Assembler</text>
    <text x="97" y="32" text-anchor="middle" font-size="8" fill="#1e40af">Stateful 5-tuple tracking</text>
    <text x="97" y="46" text-anchor="middle" font-size="8" font-weight="600" fill="#2563eb">32 Canonical Flow Features</text>
  </g>

  <g transform="translate(25, 276)">
    <rect width="195" height="42" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
    <text x="97" y="18" text-anchor="middle" font-size="8.5" font-weight="600" fill="#475569">Bounded Ring Buffer</text>
    <text x="97" y="32" text-anchor="middle" font-size="7.5" fill="#64748b">Drops oldest on high-load saturation</text>
  </g>

  <!-- Arrow Col 1 -> Col 2 -->
  <path d="M220, 236 L243, 236" stroke="#2563eb" stroke-width="2" marker-end="url(#arr1Blue)" />

  <!-- Col 2: RT-IDS Core Pipeline -->
  <rect x="245" y="46" width="270" height="320" rx="6" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
  <text x="380" y="66" text-anchor="middle" font-size="10" font-weight="700" fill="#1e293b">2. RT-IDS CORE FUSION &amp; DECISION</text>

  <!-- Multi-Model Triad -->
  <g transform="translate(255, 76)">
    <rect width="250" height="74" rx="4" fill="#ffffff" stroke="#0284c7" stroke-width="1.2" />
    <text x="125" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#0369a1">Triple-Engine Detection Triad</text>
    
    <rect x="8" y="24" width="74" height="42" rx="3" fill="#f0fdf4" stroke="#86efac" stroke-width="1" />
    <text x="45" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#166534">XGBoost</text>
    <text x="45" y="50" text-anchor="middle" font-size="7" fill="#15803d">Known Attack</text>
    <text x="45" y="60" text-anchor="middle" font-size="6.5" fill="#475569">4-Class</text>

    <rect x="88" y="24" width="74" height="42" rx="3" fill="#f0f9ff" stroke="#7dd3fc" stroke-width="1" />
    <text x="125" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#0369a1">Z-Score</text>
    <text x="125" y="50" text-anchor="middle" font-size="7" fill="#0284c7">Statistical</text>
    <text x="125" y="60" text-anchor="middle" font-size="6.5" fill="#475569">Welford</text>

    <rect x="168" y="24" width="74" height="42" rx="3" fill="#faf5ff" stroke="#d8b4fe" stroke-width="1" />
    <text x="205" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#6b21a8">Autoencoder</text>
    <text x="205" y="50" text-anchor="middle" font-size="7" fill="#7c3aed">PyTorch OOD</text>
    <text x="205" y="60" text-anchor="middle" font-size="6.5" fill="#475569">MSE Loss</text>
  </g>

  <path d="M380, 150 L380, 166" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr1Blue)" />

  <!-- Canonical Router -->
  <g transform="translate(255, 168)">
    <polygon points="125,0 250,22 125,44 0,22" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5" />
    <text x="125" y="18" text-anchor="middle" font-size="9" font-weight="700" fill="#1e3a8a">Canonical Risk Router</text>
    <text x="125" y="32" text-anchor="middle" font-size="7.5" fill="#2563eb">Deterministic Precedence Table</text>
  </g>

  <path d="M380, 212 L380, 226" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr1Blue)" />

  <!-- Decision Engine & Formal Gate -->
  <g transform="translate(255, 228)">
    <rect width="250" height="60" rx="4" fill="#ffffff" stroke="#64748b" stroke-width="1.2" />
    <text x="125" y="18" text-anchor="middle" font-size="9.5" font-weight="700" fill="#0f172a">Decision Engine &amp; Advisory LLM</text>
    <text x="125" y="32" text-anchor="middle" font-size="8" fill="#475569">Llama-3 containment proposal &amp; RAG</text>
    <text x="125" y="46" text-anchor="middle" font-size="8" font-family="monospace" fill="#0284c7">ContradictionGuard Intercept</text>
  </g>

  <path d="M380, 288 L380, 302" stroke="#16a34a" stroke-width="1.5" marker-end="url(#arr1Green)" />

  <g transform="translate(255, 304)">
    <rect width="250" height="52" rx="4" fill="#f0fdf4" stroke="#16a34a" stroke-width="1.5" />
    <text x="125" y="18" text-anchor="middle" font-size="9.5" font-weight="700" fill="#14532d">Formal Safety Invariant Gate</text>
    <text x="125" y="32" text-anchor="middle" font-size="8" fill="#166534">SymPy First-Order Logic verification</text>
    <text x="125" y="44" text-anchor="middle" font-size="7.5" font-weight="600" fill="#15803d">Pre-execution invariant check (I1 - I4)</text>
  </g>

  <!-- Arrow Col 2 -> Col 3 -->
  <path d="M505, 330 L528, 330" stroke="#16a34a" stroke-width="2" marker-end="url(#arr1Green)" />

  <!-- Col 3: Autonomous Containment -->
  <rect x="530" y="46" width="215" height="320" rx="6" fill="#f0fdf4" stroke="#86efac" stroke-width="1" />
  <text x="637" y="66" text-anchor="middle" font-size="10" font-weight="700" fill="#14532d">3. AUTONOMOUS CONTAINMENT</text>

  <!-- Dual-Authorization Box -->
  <g transform="translate(540, 78)">
    <rect width="195" height="60" rx="4" fill="#ffffff" stroke="#16a34a" stroke-width="1.5" />
    <text x="97" y="20" text-anchor="middle" font-size="9.5" font-weight="700" fill="#14532d">Two-Person Authorization</text>
    <text x="97" y="34" text-anchor="middle" font-size="8" fill="#475569">Disruption score &gt; 0.50</text>
    <text x="97" y="48" text-anchor="middle" font-size="7.5" font-weight="600" fill="#15803d">Mandates 2nd analyst sign-off</text>
  </g>

  <!-- Actuators Group -->
  <g transform="translate(540, 150)">
    <rect width="195" height="152" rx="4" fill="#ffffff" stroke="#16a34a" stroke-width="1.2" />
    <text x="97" y="18" text-anchor="middle" font-size="9" font-weight="700" fill="#166534">Subsystem Actuators</text>

    <!-- Actuator 1 -->
    <rect x="10" y="26" width="175" height="34" rx="3" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1" />
    <text x="97" y="40" text-anchor="middle" font-size="8.5" font-weight="700" fill="#0f172a">Host Firewall (Netsh/iptables)</text>
    <text x="97" y="52" text-anchor="middle" font-size="7" fill="#64748b">Automated IP block rule insertion</text>

    <!-- Actuator 2 -->
    <rect x="10" y="66" width="175" height="34" rx="3" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1" />
    <text x="97" y="80" text-anchor="middle" font-size="8.5" font-weight="700" fill="#0f172a">Process Isolation (SIGSTOP)</text>
    <text x="97" y="92" text-anchor="middle" font-size="7" fill="#64748b">Freezes malicious processes</text>

    <!-- Actuator 3 -->
    <rect x="10" y="106" width="175" height="34" rx="3" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1" />
    <text x="97" y="120" text-anchor="middle" font-size="8.5" font-weight="700" fill="#0f172a">HMAC-SHA256 Rollback</text>
    <text x="97" y="132" text-anchor="middle" font-size="7" fill="#15803d">Cryptographic atomic undo receipt</text>
  </g>

  <!-- Audit Ledger -->
  <g transform="translate(540, 312)">
    <rect width="195" height="44" rx="4" fill="#dcfce7" stroke="#16a34a" stroke-width="1.2" />
    <text x="97" y="18" text-anchor="middle" font-size="9" font-weight="700" fill="#14532d">Immutable Audit Ledger</text>
    <text x="97" y="32" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#15803d">SHA-256 forward-secure log</text>
  </g>
</svg>
</div>`;

const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fff; padding: 20px; width: 850px; }
  </style>
</head>
<body>
  ${fig1Svg}
</body>
</html>`;

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
await page.setContent(html, { waitUntil: 'networkidle0' });
await (await page.$('#fig1-container')).screenshot({ path: 'report/scratch/test_fig1_svg.png' });
await browser.close();
console.log('Saved test_fig1_svg.png successfully.');
