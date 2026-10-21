import puppeteer from 'puppeteer-core';
import fs from 'fs';

async function test() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1000, height: 800, deviceScaleFactor: 2 });

  const svgContent = `
  <svg viewBox="0 0 760 480" width="100%" height="auto" style="max-width: 760px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; display: block; margin: 0 auto;" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="p1Grad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#f8fafc" />
        <stop offset="100%" stop-color="#f1f5f9" />
      </linearGradient>
      <linearGradient id="p2Grad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#f8fafc" />
        <stop offset="100%" stop-color="#f1f5f9" />
      </linearGradient>
      <linearGradient id="boxGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#ffffff" />
        <stop offset="100%" stop-color="#f8fafc" />
      </linearGradient>
      <linearGradient id="headerGrad1" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#1e3a8a" />
        <stop offset="100%" stop-color="#2563eb" />
      </linearGradient>
      <linearGradient id="headerGrad2" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#4c1d95" />
        <stop offset="100%" stop-color="#7c3aed" />
      </linearGradient>
      <filter id="shadow" x="-5%" y="-5%" width="110%" height="115%" filterUnits="userSpaceOnUse">
        <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.07" flood-color="#0f172a" />
      </filter>
      <marker id="arrowBlue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#2563eb" />
      </marker>
      <marker id="arrowRed" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#dc2626" />
      </marker>
      <marker id="arrowPurple" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#7c3aed" />
      </marker>
      <marker id="arrowSlate" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#475569" />
      </marker>
    </defs>

    <!-- Background Canvas -->
    <rect width="760" height="480" fill="#ffffff" rx="8" />

    <!-- ==================== PHASE I CONTAINER ==================== -->
    <g transform="translate(10, 8)">
      <rect width="740" height="206" rx="8" fill="url(#p1Grad)" stroke="#cbd5e1" stroke-width="1.2" filter="url(#shadow)" />
      
      <!-- Phase I Header Badge -->
      <path d="M 0 8 Q 0 0 8 0 L 390 0 L 372 26 L 0 26 Z" fill="url(#headerGrad1)" />
      <text x="14" y="17.5" font-size="10.5" font-weight="700" fill="#ffffff" letter-spacing="0.5">PHASE I: REAL-TIME DETECTION PIPELINE (LINE-SPEED)</text>

      <!-- Layer 1 Box -->
      <g transform="translate(14, 34)">
        <rect width="215" height="160" rx="6" fill="url(#boxGrad)" stroke="#94a3b8" stroke-width="1" />
        <rect width="215" height="26" rx="6" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1" />
        <text x="107" y="17" font-size="11" font-weight="700" fill="#0f172a" text-anchor="middle">Layer 1: Ingestion &amp; Telemetry</text>
        
        <!-- Subcomponents -->
        <g transform="translate(10, 34)">
          <rect width="195" height="34" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="12" y="15" font-size="9.5" font-weight="600" fill="#1e293b">Raw Socket Sniffer [CE-04]</text>
          <text x="12" y="27" font-size="8" fill="#64748b">AF_PACKET / Raw IP flow assembler</text>
        </g>
        <g transform="translate(10, 74)">
          <rect width="195" height="34" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="12" y="15" font-size="9.5" font-weight="600" fill="#1e293b">Suricata EVE Tailer [CE-05]</text>
          <text x="12" y="27" font-size="8" fill="#64748b">eve.json stream &amp; alert mapper</text>
        </g>
        <g transform="translate(10, 114)">
          <rect width="195" height="34" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="12" y="15" font-size="9.5" font-weight="600" fill="#1e293b">Universal Ingestion Engine [CE-06]</text>
          <text x="12" y="27" font-size="8" fill="#64748b">CSV / JSON / NDJSON batch parser</text>
        </g>
      </g>

      <!-- Arrow L1 -> L2 -->
      <line x1="230" y1="114" x2="260" y2="114" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />

      <!-- Layer 2 Box -->
      <g transform="translate(262, 34)">
        <rect width="205" height="160" rx="6" fill="url(#boxGrad)" stroke="#94a3b8" stroke-width="1" />
        <rect width="205" height="26" rx="6" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1" />
        <text x="102" y="17" font-size="11" font-weight="700" fill="#0f172a" text-anchor="middle">Layer 2: Feature Engineering</text>
        
        <!-- Subcomponents -->
        <g transform="translate(10, 36)">
          <rect width="185" height="48" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="12" y="17" font-size="9.5" font-weight="600" fill="#1e293b">32-Feature Extraction [CE-07]</text>
          <text x="12" y="30" font-size="8" fill="#64748b">Duration, packet rates, byte ratios,</text>
          <text x="12" y="42" font-size="8" fill="#64748b">TCP flags, inter-arrival times (IAT)</text>
        </g>
        <!-- Mini arrow -->
        <line x1="102" y1="85" x2="102" y2="99" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arrowBlue)" />
        <g transform="translate(10, 100)">
          <rect width="185" height="48" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="12" y="17" font-size="9.5" font-weight="600" fill="#1e293b">Robust Normalizer [CE-08]</text>
          <text x="12" y="30" font-size="8" fill="#64748b">log1p transformation + RobustScaler</text>
          <text x="12" y="42" font-size="8" fill="#64748b">Mitigates heavy-tailed flow outliers</text>
        </g>
      </g>

      <!-- Arrow L2 -> L3 -->
      <line x1="468" y1="114" x2="496" y2="114" stroke="#2563eb" stroke-width="2" marker-end="url(#arrowBlue)" />

      <!-- Layer 3 Box -->
      <g transform="translate(498, 34)">
        <rect width="228" height="160" rx="6" fill="url(#boxGrad)" stroke="#94a3b8" stroke-width="1" />
        <rect width="228" height="26" rx="6" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1" />
        <text x="114" y="17" font-size="11" font-weight="700" fill="#0f172a" text-anchor="middle">Layer 3: Pipeline v2 Inference</text>
        
        <!-- Inference Models -->
        <g transform="translate(8, 32)">
          <rect width="66" height="60" rx="4" fill="#eff6ff" stroke="#bfdbfe" stroke-width="1" />
          <text x="33" y="15" font-size="8.5" font-weight="700" fill="#1e40af" text-anchor="middle">XGBoost</text>
          <text x="33" y="27" font-size="8" fill="#1d4ed8" text-anchor="middle">Classifier</text>
          <text x="33" y="44" font-size="7.5" fill="#475569" text-anchor="middle">Supervised</text>
          <text x="33" y="54" font-size="7.5" fill="#475569" text-anchor="middle">Known Attack</text>
        </g>
        <g transform="translate(79, 32)">
          <rect width="66" height="60" rx="4" fill="#fef2f2" stroke="#fecaca" stroke-width="1" />
          <text x="33" y="15" font-size="8.5" font-weight="700" fill="#991b1b" text-anchor="middle">Z-Score</text>
          <text x="33" y="27" font-size="8" fill="#b91c1c" text-anchor="middle">Filter</text>
          <text x="33" y="44" font-size="7.5" fill="#475569" text-anchor="middle">Statistical</text>
          <text x="33" y="54" font-size="7.5" fill="#475569" text-anchor="middle">Distribution</text>
        </g>
        <g transform="translate(150, 32)">
          <rect width="70" height="60" rx="4" fill="#faf5ff" stroke="#e9d5ff" stroke-width="1" />
          <text x="35" y="15" font-size="8.5" font-weight="700" fill="#6b21a8" text-anchor="middle">Autoencoder</text>
          <text x="35" y="27" font-size="8" fill="#7e22ce" text-anchor="middle">PyTorch</text>
          <text x="35" y="44" font-size="7.5" fill="#475569" text-anchor="middle">Reconstruct</text>
          <text x="35" y="54" font-size="7.5" fill="#475569" text-anchor="middle">Anomaly MSE</text>
        </g>

        <!-- Fusion & Routing Box -->
        <g transform="translate(8, 102)">
          <rect width="212" height="48" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="106" y="16" font-size="9.5" font-weight="700" fill="#0f172a" text-anchor="middle">Canonical Heuristic Router [CE-12]</text>
          <text x="106" y="30" font-size="8" fill="#334155" text-anchor="middle">Classifier-First Mandate: known_attack | review |</text>
          <text x="106" y="42" font-size="8" fill="#334155" text-anchor="middle">unknown_anomaly_review | benign</text>
        </g>
      </g>
    </g>

    <!-- ==================== INTER-PHASE CONNECTORS ==================== -->
    <!-- Line: Known Attack (Fast Path) directly into Layer 5 Safety Verifier -->
    <path d="M 645 214 L 645 238 L 415 238 L 415 298" fill="none" stroke="#dc2626" stroke-width="2" stroke-dasharray="4,2" marker-end="url(#arrowRed)" />
    <rect x="475" y="229" width="160" height="18" rx="3" fill="#fef2f2" stroke="#f87171" stroke-width="0.8" />
    <text x="555" y="242" font-size="8" font-weight="700" fill="#991b1b" text-anchor="middle">Known Attack (Fast-Path Route)</text>

    <!-- Line: Ambiguous Anomaly (Cognitive Path) into Layer 4 Cognitive Advisory -->
    <path d="M 545 214 L 545 256 L 134 256 L 134 298" fill="none" stroke="#7c3aed" stroke-width="2" marker-end="url(#arrowPurple)" />
    <rect x="235" y="247" width="180" height="18" rx="3" fill="#faf5ff" stroke="#c084fc" stroke-width="0.8" />
    <text x="325" y="260" font-size="8" font-weight="700" fill="#6b21a8" text-anchor="middle">Ambiguous Anomaly / Review Signal</text>

    <!-- ==================== PHASE II CONTAINER ==================== -->
    <g transform="translate(10, 270)">
      <rect width="740" height="202" rx="8" fill="url(#p2Grad)" stroke="#cbd5e1" stroke-width="1.2" filter="url(#shadow)" />
      
      <!-- Phase II Header Badge -->
      <path d="M 0 8 Q 0 0 8 0 L 410 0 L 392 26 L 0 26 Z" fill="url(#headerGrad2)" />
      <text x="14" y="17.5" font-size="10.5" font-weight="700" fill="#ffffff" letter-spacing="0.5">PHASE II: COGNITIVE TRIAGE, SAFETY &amp; PERSISTENCE</text>

      <!-- Layer 4 Box -->
      <g transform="translate(14, 34)">
        <rect width="220" height="154" rx="6" fill="url(#boxGrad)" stroke="#94a3b8" stroke-width="1" />
        <rect width="220" height="26" rx="6" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1" />
        <text x="110" y="17" font-size="11" font-weight="700" fill="#0f172a" text-anchor="middle">Layer 4: Cognitive Advisory</text>
        
        <!-- Subcomponents -->
        <g transform="translate(10, 32)">
          <rect width="200" height="32" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="10" y="14" font-size="9" font-weight="600" fill="#1e293b">MITRE Graph-RAG Engine [CE-13]</text>
          <text x="10" y="25" font-size="7.5" fill="#64748b">ATT&amp;CK techniques + D3FEND defenses</text>
        </g>
        <g transform="translate(10, 68)">
          <rect width="200" height="32" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="10" y="14" font-size="9" font-weight="600" fill="#1e293b">Advisory LLM Explainer [CE-14]</text>
          <text x="10" y="25" font-size="7.5" fill="#64748b">Local quantized llama-server (decoupled)</text>
        </g>
        <g transform="translate(10, 104)">
          <rect width="200" height="40" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="10" y="14" font-size="9" font-weight="700" fill="#b91c1c">Contradiction Guard [CE-15]</text>
          <text x="10" y="25" font-size="7.5" fill="#64748b">Overrides hallucinated LLM benign verdict</text>
          <text x="10" y="35" font-size="7.5" fill="#64748b">when classifier confidence is high</text>
        </g>
      </g>

      <!-- Arrow L4 -> L5 -->
      <line x1="235" y1="112" x2="266" y2="112" stroke="#7c3aed" stroke-width="2" marker-end="url(#arrowPurple)" />
      <rect x="238" y="98" width="26" height="14" rx="2" fill="#faf5ff" stroke="#c084fc" stroke-width="0.5" />
      <text x="251" y="108" font-size="7" font-weight="700" fill="#6b21a8" text-anchor="middle">Cert</text>

      <!-- Layer 5 Box -->
      <g transform="translate(268, 34)">
        <rect width="232" height="154" rx="6" fill="url(#boxGrad)" stroke="#94a3b8" stroke-width="1" />
        <rect width="232" height="26" rx="6" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1" />
        <text x="116" y="17" font-size="11" font-weight="700" fill="#0f172a" text-anchor="middle">Layer 5: Safety Verification</text>
        
        <!-- Safety & Actuation -->
        <g transform="translate(10, 32)">
          <rect width="212" height="34" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="10" y="14" font-size="9" font-weight="700" fill="#0f172a">Formal Safety Verifier [CE-03, 16]</text>
          <text x="10" y="26" font-size="7.5" fill="#475569">FOL Invariant Verification (prevents Self-DoS)</text>
        </g>
        <g transform="translate(10, 70)">
          <rect width="212" height="32" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="10" y="14" font-size="9" font-weight="600" fill="#1e293b">Two-Person Rule Engine [CE-17]</text>
          <text x="10" y="25" font-size="7.5" fill="#64748b">Cryptographic dual-authorization token check</text>
        </g>
        <g transform="translate(10, 106)">
          <rect width="102" height="38" rx="4" fill="#eff6ff" stroke="#93c5fd" stroke-width="1" />
          <text x="51" y="16" font-size="8.5" font-weight="600" fill="#1e40af" text-anchor="middle">Host Firewall</text>
          <text x="51" y="28" font-size="7.5" fill="#3b82f6" text-anchor="middle">Windows / iptables</text>
        </g>
        <g transform="translate(120, 106)">
          <rect width="102" height="38" rx="4" fill="#eff6ff" stroke="#93c5fd" stroke-width="1" />
          <text x="51" y="16" font-size="8.5" font-weight="600" fill="#1e40af" text-anchor="middle">Process Isolation</text>
          <text x="51" y="28" font-size="7.5" fill="#3b82f6" text-anchor="middle">PID terminate/cgroup</text>
        </g>
      </g>

      <!-- Arrow L5 -> L6 -->
      <line x1="501" y1="112" x2="528" y2="112" stroke="#475569" stroke-width="2" marker-end="url(#arrowSlate)" />

      <!-- Layer 6 Box -->
      <g transform="translate(530, 34)">
        <rect width="196" height="154" rx="6" fill="url(#boxGrad)" stroke="#94a3b8" stroke-width="1" />
        <rect width="196" height="26" rx="6" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1" />
        <text x="98" y="17" font-size="11" font-weight="700" fill="#0f172a" text-anchor="middle">Layer 6: API &amp; Storage</text>
        
        <!-- Persistence -->
        <g transform="translate(10, 32)">
          <rect width="176" height="32" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="10" y="14" font-size="9" font-weight="600" fill="#1e293b">FastAPI REST Service</text>
          <text x="10" y="25" font-size="7.5" fill="#64748b">Port 8000, JWT auth, RBAC</text>
        </g>
        <g transform="translate(10, 68)">
          <rect width="176" height="32" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="10" y="14" font-size="9" font-weight="600" fill="#1e293b">SQLite WAL Database</text>
          <text x="10" y="25" font-size="7.5" fill="#64748b">Hash-chained audit ledger</text>
        </g>
        <g transform="translate(10, 104)">
          <rect width="176" height="40" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
          <text x="10" y="14" font-size="9" font-weight="600" fill="#1e293b">Operations Dashboard</text>
          <text x="10" y="25" font-size="7.5" fill="#64748b">Real-time SSE event stream &amp;</text>
          <text x="10" y="35" font-size="7.5" fill="#64748b">quarantine approval console</text>
        </g>
      </g>
    </g>
  </svg>
  `;

  await page.setContent(`
    <!DOCTYPE html>
    <html>
      <head>
        <style>
          body { background: white; font-family: sans-serif; padding: 20px; display: flex; justify-content: center; }
        </style>
      </head>
      <body>
        <div style="width: 760px;">
          ${svgContent}
        </div>
      </body>
    </html>
  `);
  
  const el = await page.$('svg');
  await el.screenshot({ path: 'report/scratch/fig4_svg_test.png' });
  console.log('Saved fig4_svg_test.png successfully.');
  await browser.close();
}
test();
