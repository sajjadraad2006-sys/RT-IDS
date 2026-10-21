import puppeteer from 'puppeteer-core';

const fig14Svg = `<div id="fig14-container" style="width: 100%; max-width: 760px; margin: 16px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<svg viewBox="0 0 760 380" width="100%" height="auto" xmlns="http://www.w3.org/2000/svg" style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
  <defs>
    <linearGradient id="headerGrad14" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#334155" />
    </linearGradient>
    <marker id="arr14Blue" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#0284c7" />
    </marker>
    <marker id="arr14Red" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#ef4444" />
    </marker>
    <marker id="arr14Amber" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#d97706" />
    </marker>
  </defs>

  <!-- Banner Header -->
  <rect x="0" y="0" width="760" height="34" rx="8" fill="url(#headerGrad14)" />
  <rect x="0" y="24" width="760" height="10" fill="url(#headerGrad14)" />
  <text x="380" y="22" text-anchor="middle" font-size="12" font-weight="700" fill="#ffffff" letter-spacing="0.5">
    MULTI-ZONE TRUST ARCHITECTURE &amp; DATAFLOW PIPELINE (Z0 -> Z1 -> Z2)
  </text>

  <!-- Zone 0: Untrusted -->
  <rect x="15" y="46" width="200" height="320" rx="6" fill="#fef2f2" stroke="#ef4444" stroke-width="1.5" />
  <rect x="25" y="54" width="180" height="20" rx="3" fill="#fee2e2" />
  <text x="115" y="68" text-anchor="middle" font-size="9.5" font-weight="700" fill="#991b1b">UNTRUSTED ZONE (Z0)</text>

  <g transform="translate(25, 82)">
    <rect width="180" height="60" rx="4" fill="#ffffff" stroke="#ef4444" stroke-width="1" />
    <text x="90" y="20" text-anchor="middle" font-size="9.5" font-weight="700" fill="#991b1b">Raw Network Traffic</text>
    <text x="90" y="34" text-anchor="middle" font-size="8" fill="#475569">Physical NIC / Promiscuous</text>
    <text x="90" y="46" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#dc2626">Untrusted packet stream</text>
  </g>

  <g transform="translate(25, 154)">
    <rect width="180" height="60" rx="4" fill="#ffffff" stroke="#ef4444" stroke-width="1" />
    <text x="90" y="20" text-anchor="middle" font-size="9.5" font-weight="700" fill="#991b1b">External Adversary</text>
    <text x="90" y="34" text-anchor="middle" font-size="8" fill="#475569">Volumetric DDoS / Scans</text>
    <text x="90" y="46" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#dc2626">SYN flood / Malicious payload</text>
  </g>

  <g transform="translate(25, 230)">
    <rect width="180" height="70" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
    <text x="90" y="18" text-anchor="middle" font-size="8.5" font-weight="700" fill="#475569">Security Assumption:</text>
    <text x="90" y="32" text-anchor="middle" font-size="7.5" fill="#64748b">All payloads &amp; headers</text>
    <text x="90" y="44" text-anchor="middle" font-size="7.5" fill="#64748b">are strictly untrusted and</text>
    <text x="90" y="56" text-anchor="middle" font-size="7.5" fill="#64748b">potentially adversarial.</text>
  </g>

  <!-- Connection Z0 -> Z2 Sniffer -->
  <path d="M205, 112 L225, 112 L225, 112 L435, 112" fill="none" stroke="#ef4444" stroke-width="1.8" stroke-dasharray="3,3" marker-end="url(#arr14Red)" />
  <rect x="208" y="102" width="22" height="18" rx="2" fill="#ffffff" stroke="#ef4444" stroke-width="1" />
  <text x="219" y="114" text-anchor="middle" font-size="7" font-weight="700" fill="#dc2626">Raw</text>

  <!-- Zone 1: Semi-Trusted -->
  <rect x="230" y="46" width="195" height="320" rx="6" fill="#fffbeb" stroke="#f59e0b" stroke-width="1.5" />
  <rect x="240" y="54" width="175" height="20" rx="3" fill="#fef3c7" />
  <text x="327" y="68" text-anchor="middle" font-size="9.5" font-weight="700" fill="#92400e">SEMI-TRUSTED ZONE (Z1)</text>

  <g transform="translate(240, 82)">
    <rect width="175" height="60" rx="4" fill="#ffffff" stroke="#f59e0b" stroke-width="1" />
    <text x="87" y="20" text-anchor="middle" font-size="9.5" font-weight="700" fill="#92400e">Suricata EVE-JSON</text>
    <text x="87" y="34" text-anchor="middle" font-size="8" font-family="monospace" fill="#b45309">/var/log/suricata/eve.json</text>
    <text x="87" y="46" text-anchor="middle" font-size="7.5" fill="#475569">External daemon stream</text>
  </g>

  <g transform="translate(240, 154)">
    <rect width="175" height="60" rx="4" fill="#ffffff" stroke="#f59e0b" stroke-width="1" />
    <text x="87" y="20" text-anchor="middle" font-size="9.5" font-weight="700" fill="#92400e">Web Client &amp; API</text>
    <text x="87" y="34" text-anchor="middle" font-size="8" fill="#475569">Operator browser / REST</text>
    <text x="87" y="46" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#b45309">HTTP Bearer JWT</text>
  </g>

  <g transform="translate(240, 230)">
    <rect width="175" height="70" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
    <text x="87" y="18" text-anchor="middle" font-size="8.5" font-weight="700" fill="#475569">Security Boundary:</text>
    <text x="87" y="32" text-anchor="middle" font-size="7.5" fill="#64748b">Traversing Z1 -> Z2 requires</text>
    <text x="87" y="44" text-anchor="middle" font-size="7.5" fill="#64748b">JWT auth &amp; strict Pydantic</text>
    <text x="87" y="56" text-anchor="middle" font-size="7.5" fill="#64748b">InputContract validation.</text>
  </g>

  <!-- Connection Z1 -> Z2 Ingestion -->
  <path d="M415, 112 L435, 112" fill="none" stroke="#d97706" stroke-width="1.8" marker-end="url(#arr14Amber)" />
  <path d="M415, 184 L435, 184" fill="none" stroke="#d97706" stroke-width="1.8" marker-end="url(#arr14Amber)" />

  <!-- Zone 2: Trusted Execution Core -->
  <rect x="440" y="46" width="305" height="320" rx="6" fill="#f0f9ff" stroke="#0284c7" stroke-width="1.5" />
  <rect x="450" y="54" width="285" height="20" rx="3" fill="#e0f2fe" />
  <text x="592" y="68" text-anchor="middle" font-size="9.5" font-weight="700" fill="#0369a1">TRUSTED CORE EXECUTION ZONE (Z2)</text>

  <!-- Block 1: Ingestion & Contracts -->
  <g transform="translate(450, 80)">
    <rect width="285" height="70" rx="4" fill="#ffffff" stroke="#0284c7" stroke-width="1.2" />
    <text x="142" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#0369a1">Ingestion &amp; Normalization Layer</text>
    
    <rect x="8" y="24" width="85" height="38" rx="3" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
    <text x="50" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#0f172a">LiveFlowSniffer</text>
    <text x="50" y="50" text-anchor="middle" font-size="6.5" font-family="monospace" fill="#0284c7">Raw 5-tuple</text>

    <rect x="100" y="24" width="85" height="38" rx="3" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
    <text x="142" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#0f172a">SuricataTailer</text>
    <text x="142" y="50" text-anchor="middle" font-size="6.5" font-family="monospace" fill="#0284c7">EVE Adapter</text>

    <rect x="192" y="24" width="85" height="38" rx="3" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
    <text x="234" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#0f172a">InputContract</text>
    <text x="234" y="50" text-anchor="middle" font-size="6.5" font-family="monospace" fill="#0284c7">Pydantic Gate</text>
  </g>

  <path d="M592, 150 L592, 164" stroke="#0284c7" stroke-width="1.5" marker-end="url(#arr14Blue)" />

  <!-- Block 2: Detection Triad -->
  <g transform="translate(450, 166)">
    <rect width="285" height="74" rx="4" fill="#ffffff" stroke="#0284c7" stroke-width="1.2" />
    <text x="142" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#0369a1">Multi-Stage Detection Engine (Pipeline v2)</text>
    
    <rect x="8" y="24" width="85" height="42" rx="3" fill="#eff6ff" stroke="#3b82f6" stroke-width="1" />
    <text x="50" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#1e3a8a">XGBoost (32-F)</text>
    <text x="50" y="50" text-anchor="middle" font-size="7" fill="#2563eb">Known-attack clf</text>
    <text x="50" y="60" text-anchor="middle" font-size="6.5" fill="#475569">[CE-08]</text>

    <rect x="100" y="24" width="85" height="42" rx="3" fill="#eff6ff" stroke="#3b82f6" stroke-width="1" />
    <text x="142" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#1e3a8a">Autoencoder</text>
    <text x="142" y="50" text-anchor="middle" font-size="7" fill="#2563eb">PyTorch MSE Loss</text>
    <text x="142" y="60" text-anchor="middle" font-size="6.5" fill="#475569">[CE-10]</text>

    <rect x="192" y="24" width="85" height="42" rx="3" fill="#eff6ff" stroke="#3b82f6" stroke-width="1" />
    <text x="234" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#1e3a8a">Risk Router</text>
    <text x="234" y="50" text-anchor="middle" font-size="7" fill="#2563eb">Deterministic</text>
    <text x="234" y="60" text-anchor="middle" font-size="6.5" fill="#475569">[CE-11]</text>
  </g>

  <path d="M592, 240 L592, 254" stroke="#0284c7" stroke-width="1.5" marker-end="url(#arr14Blue)" />

  <!-- Block 3: Safety Interlocks -->
  <g transform="translate(450, 256)">
    <rect width="285" height="98" rx="4" fill="#ffffff" stroke="#16a34a" stroke-width="1.5" />
    <text x="142" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#14532d">Safety Interlocks &amp; Autonomous Actuation</text>
    
    <rect x="8" y="24" width="130" height="66" rx="3" fill="#f0fdf4" stroke="#86efac" stroke-width="1" />
    <text x="73" y="38" text-anchor="middle" font-size="8" font-weight="700" fill="#166534">Formal Safety Verifier</text>
    <text x="73" y="50" text-anchor="middle" font-size="7" fill="#475569">SymPy Invariants I1 - I4</text>
    <text x="73" y="62" text-anchor="middle" font-size="7" fill="#475569">Advisory LLM SmartDecision</text>
    <text x="73" y="74" text-anchor="middle" font-size="7" font-weight="600" fill="#15803d">[CE-18] Gatekeeper</text>

    <rect x="146" y="24" width="131" height="66" rx="3" fill="#f0fdf4" stroke="#86efac" stroke-width="1" />
    <text x="211" y="38" text-anchor="middle" font-size="8" font-weight="700" fill="#166534">System Actuators</text>
    <text x="211" y="50" text-anchor="middle" font-size="7" fill="#475569">Host Firewall (Netsh/iptables)</text>
    <text x="211" y="62" text-anchor="middle" font-size="7" fill="#475569">SIGSTOP Process Freeze</text>
    <text x="211" y="74" text-anchor="middle" font-size="7" font-weight="600" fill="#15803d">[CE-48] Two-Person Rule</text>
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
  ${fig14Svg}
</body>
</html>`;

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
await page.setContent(html, { waitUntil: 'networkidle0' });
await (await page.$('#fig14-container')).screenshot({ path: 'report/scratch/test_fig14_svg.png' });
await browser.close();
console.log('Saved test_fig14_svg.png successfully.');
