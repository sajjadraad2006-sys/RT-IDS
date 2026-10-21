import puppeteer from 'puppeteer-core';

const fig12Svg = `<div id="fig12-container" style="width: 100%; max-width: 760px; margin: 16px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<svg viewBox="0 0 760 290" width="100%" height="auto" xmlns="http://www.w3.org/2000/svg" style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
  <defs>
    <linearGradient id="headerGrad12" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#1e1b4b" />
    </linearGradient>
    <marker id="arr12Blue" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#2563eb" />
    </marker>
    <marker id="arr12Red" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#dc2626" />
    </marker>
    <marker id="arr12Green" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#16a34a" />
    </marker>
  </defs>

  <!-- Banner Header -->
  <rect x="0" y="0" width="760" height="34" rx="8" fill="url(#headerGrad12)" />
  <rect x="0" y="24" width="760" height="10" fill="url(#headerGrad12)" />
  <text x="380" y="22" text-anchor="middle" font-size="12" font-weight="700" fill="#ffffff" letter-spacing="0.5">
    MULTI-STAGE NEURO-SYMBOLIC DECISION ENGINE &amp; CONTRADICTION GUARD
  </text>

  <!-- Tier 1: Ingestion to Cognitive LLM (Top) -->
  <rect x="15" y="46" width="730" height="100" rx="6" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
  <text x="28" y="64" font-size="11" font-weight="700" fill="#334155" letter-spacing="0.3">TIER 1: TELEMETRY INGESTION, RETRIEVAL AUGMENTATION &amp; LLM INFERENCE</text>

  <!-- 1. Pipeline Alert -->
  <g transform="translate(25, 74)">
    <rect width="155" height="60" rx="4" fill="#ffffff" stroke="#64748b" stroke-width="1.2" />
    <text x="77" y="22" text-anchor="middle" font-size="10.5" font-weight="700" fill="#0f172a">Pipeline Alert</text>
    <text x="77" y="38" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#0284c7">known_attack</text>
    <text x="77" y="50" text-anchor="middle" font-size="8" fill="#475569">Detection alert stream</text>
  </g>

  <path d="M180, 104 L205, 104" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr12Blue)" />

  <!-- 2. Defense RAG -->
  <g transform="translate(210, 74)">
    <rect width="165" height="60" rx="4" fill="#ffffff" stroke="#64748b" stroke-width="1.2" />
    <text x="82" y="22" text-anchor="middle" font-size="10.5" font-weight="700" fill="#0f172a">Defense RAG</text>
    <text x="82" y="38" text-anchor="middle" font-size="8" fill="#475569">MITRE ATT&amp;CK &amp; D3FEND</text>
    <text x="82" y="50" text-anchor="middle" font-size="8" font-family="monospace" fill="#0284c7">Top-K Playbooks [CE-43]</text>
  </g>

  <path d="M375, 104 L400, 104" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr12Blue)" />

  <!-- 3. Context Assembly -->
  <g transform="translate(405, 74)">
    <rect width="160" height="60" rx="4" fill="#ffffff" stroke="#64748b" stroke-width="1.2" />
    <text x="80" y="22" text-anchor="middle" font-size="10.5" font-weight="700" fill="#0f172a">Context Assembly</text>
    <text x="80" y="38" text-anchor="middle" font-size="8" fill="#475569">Prompt sanitization</text>
    <text x="80" y="50" text-anchor="middle" font-size="8" fill="#64748b">Defends injection</text>
  </g>

  <path d="M565, 104 L590, 104" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr12Blue)" />

  <!-- 4. Llama-3-8B -->
  <g transform="translate(595, 74)">
    <rect width="140" height="60" rx="4" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5" />
    <text x="70" y="22" text-anchor="middle" font-size="10" font-weight="700" fill="#1e3a8a">Llama-3-8B</text>
    <text x="70" y="38" text-anchor="middle" font-size="8" fill="#1e40af">Local GPU inference</text>
    <text x="70" y="50" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#2563eb">SmartDecision JSON</text>
  </g>

  <!-- Turn Arrow from Llama-3 to Tier 2 -->
  <path d="M665, 134 L665, 155 L102, 155 L102, 178" fill="none" stroke="#2563eb" stroke-width="2" stroke-dasharray="4,3" marker-end="url(#arr12Blue)" />
  <rect x="330" y="147" width="120" height="16" rx="3" fill="#ffffff" stroke="#93c5fd" stroke-width="1" />
  <text x="390" y="159" text-anchor="middle" font-size="8" font-weight="600" fill="#1e40af">Raw LLM JSON Output</text>

  <!-- Tier 2: Validation & Contradiction Guard -->
  <rect x="15" y="170" width="730" height="110" rx="6" fill="#f0fdf4" stroke="#86efac" stroke-width="1" />
  <text x="28" y="188" font-size="11" font-weight="700" fill="#166534" letter-spacing="0.3">TIER 2: JSON SCHEMA VALIDATION, CONTRADICTION GUARD &amp; FORMAL SAFETY ADMISSION</text>

  <!-- 5. JSON Parser -->
  <g transform="translate(25, 198)">
    <rect width="155" height="70" rx="4" fill="#ffffff" stroke="#16a34a" stroke-width="1.2" />
    <text x="77" y="20" text-anchor="middle" font-size="10.5" font-weight="700" fill="#14532d">JSON Parser</text>
    <text x="77" y="36" text-anchor="middle" font-size="8" fill="#475569">Pydantic validation</text>
    <text x="77" y="48" text-anchor="middle" font-size="8" fill="#475569">Safe schema fallback</text>
    <text x="77" y="60" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#15803d">SmartDecision schema</text>
  </g>

  <path d="M180, 233 L210, 233" stroke="#16a34a" stroke-width="1.5" marker-end="url(#arr12Green)" />

  <!-- 6. Contradiction Guard Diamond -->
  <g transform="translate(215, 203)">
    <polygon points="85,0 170,30 85,60 0,30" fill="#fef2f2" stroke="#dc2626" stroke-width="1.5" />
    <text x="85" y="24" text-anchor="middle" font-size="9" font-weight="700" fill="#991b1b">ContradictionGuard</text>
    <text x="85" y="38" text-anchor="middle" font-size="7.5" font-weight="600" fill="#b91c1c">Sev HIGH &amp; LLM Benign?</text>
    <text x="85" y="50" text-anchor="middle" font-size="7" fill="#7f1d1d">[CE-14 / CE-44]</text>
  </g>

  <!-- Branch: High/Benign Override -->
  <path d="M385, 218 L430, 218" stroke="#dc2626" stroke-width="1.5" marker-end="url(#arr12Red)" />
  <text x="405" y="212" text-anchor="middle" font-size="8" font-weight="700" fill="#dc2626">YES</text>

  <g transform="translate(435, 198)">
    <rect width="140" height="34" rx="3" fill="#fee2e2" stroke="#ef4444" stroke-width="1.2" />
    <text x="70" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#991b1b">Overrule to Malicious</text>
    <text x="70" y="28" text-anchor="middle" font-size="7.5" fill="#7f1d1d">Suppresses hallucination</text>
  </g>

  <!-- Branch: Consistent -->
  <path d="M385, 248 L430, 248" stroke="#16a34a" stroke-width="1.5" marker-end="url(#arr12Green)" />
  <text x="405" y="258" text-anchor="middle" font-size="8" font-weight="700" fill="#16a34a">NO</text>

  <g transform="translate(435, 236)">
    <rect width="140" height="32" rx="3" fill="#f0fdf4" stroke="#86efac" stroke-width="1.2" />
    <text x="70" y="15" text-anchor="middle" font-size="8.5" font-weight="700" fill="#14532d">Corroborated Verdict</text>
    <text x="70" y="26" text-anchor="middle" font-size="7.5" fill="#166534">Admit LLM containment</text>
  </g>

  <!-- Merge to Formal Safety Gate -->
  <path d="M575, 215 L590, 215 L590, 233 L605, 233" stroke="#2563eb" stroke-width="1.5" />
  <path d="M575, 252 L590, 252 L590, 233 L605, 233" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr12Blue)" />

  <g transform="translate(610, 203)">
    <rect width="125" height="60" rx="4" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5" />
    <text x="62" y="20" text-anchor="middle" font-size="9.5" font-weight="700" fill="#1e3a8a">Formal Safety Gate</text>
    <text x="62" y="34" text-anchor="middle" font-size="8" fill="#475569">SymPy Invariants</text>
    <text x="62" y="46" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#2563eb">verify_action() [CE-18]</text>
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
  ${fig12Svg}
</body>
</html>`;

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
await page.setContent(html, { waitUntil: 'networkidle0' });
await (await page.$('#fig12-container')).screenshot({ path: 'report/scratch/test_fig12_svg.png' });
await browser.close();
console.log('Saved test_fig12_svg.png successfully.');
