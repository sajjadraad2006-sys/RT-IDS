import puppeteer from 'puppeteer-core';

const fig24Svg = `<div id="fig24-container" style="width: 100%; max-width: 760px; margin: 16px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<svg viewBox="0 0 760 370" width="100%" height="auto" xmlns="http://www.w3.org/2000/svg" style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
  <defs>
    <linearGradient id="headerGrad24" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#7f1d1d" />
      <stop offset="100%" stop-color="#991b1b" />
    </linearGradient>
    <marker id="arr24Red" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#dc2626" />
    </marker>
    <marker id="arr24Dark" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#475569" />
    </marker>
  </defs>

  <!-- Banner Header -->
  <rect x="0" y="0" width="760" height="34" rx="8" fill="url(#headerGrad24)" />
  <rect x="0" y="24" width="760" height="10" fill="url(#headerGrad24)" />
  <text x="380" y="22" text-anchor="middle" font-size="12" font-weight="700" fill="#ffffff" letter-spacing="0.5">
    ROOT-CAUSE FAULT TREE: 40/40 (100%) FALSE-POSITIVE CONTAINMENT DISASTER
  </text>

  <!-- Col 1: Defect 1 -->
  <rect x="15" y="46" width="230" height="310" rx="6" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
  <text x="130" y="66" text-anchor="middle" font-size="10.5" font-weight="700" fill="#1e293b">DEFECT 1: RAG RETRIEVAL</text>

  <!-- Box 1.1: Benign Input -->
  <g transform="translate(25, 78)">
    <rect width="210" height="54" rx="4" fill="#ffffff" stroke="#64748b" stroke-width="1.2" />
    <text x="105" y="18" text-anchor="middle" font-size="10" font-weight="700" fill="#0f172a">Benign Admin Activity</text>
    <text x="105" y="32" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#0284c7">mysqldump, CI/CD runner</text>
    <text x="105" y="45" text-anchor="middle" font-size="8" fill="#475569">Get-Process | Where CPU -gt 10</text>
  </g>

  <!-- Arrow down -->
  <path d="M130, 132 L130, 154" fill="none" stroke="#475569" stroke-width="1.5" marker-end="url(#arr24Dark)" />
  <text x="135" y="146" font-size="8" fill="#64748b">Query telemetry</text>

  <!-- Box 1.2: RAG Flaw -->
  <g transform="translate(25, 156)">
    <rect width="210" height="188" rx="4" fill="#fef2f2" stroke="#ef4444" stroke-width="1.5" />
    <text x="105" y="20" text-anchor="middle" font-size="10.5" font-weight="700" fill="#991b1b">Unconditional Top-K</text>
    <text x="105" y="36" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#b91c1c">retrieve_playbook(k=4)</text>

    <line x1="15" y1="46" x2="195" y2="46" stroke="#fca5a5" stroke-width="1" />

    <text x="15" y="64" font-size="8.5" font-weight="600" fill="#7f1d1d">• No Cosine Threshold Cutoff:</text>
    <text x="23" y="78" font-size="8" fill="#991b1b">tau_sim = 0.65 is missing</text>
    <text x="23" y="92" font-size="8" fill="#991b1b">Cosine sim ~ 0.0 with attack DB</text>

    <text x="15" y="112" font-size="8.5" font-weight="600" fill="#7f1d1d">• Forced MITRE Ingestion:</text>
    <text x="23" y="126" font-size="8" font-family="monospace" fill="#0284c7">T1190 (Exploit Public-Facing)</text>
    <text x="23" y="140" font-size="8" font-family="monospace" fill="#0284c7">T1071 (Standard App Protocol)</text>
    <text x="23" y="154" font-size="8" font-family="monospace" fill="#0284c7">T1059 (Command &amp; Scripting)</text>

    <rect x="15" y="162" width="180" height="20" rx="3" fill="#fee2e2" stroke="#f87171" stroke-width="1" />
    <text x="105" y="176" text-anchor="middle" font-size="8" font-weight="700" fill="#991b1b">4 Attack Tactics Injected</text>
  </g>

  <!-- Arrow Col 1 -> Col 2 -->
  <path d="M235, 250 L263, 250" fill="none" stroke="#dc2626" stroke-width="2" marker-end="url(#arr24Red)" />

  <!-- Col 2: Defect 2 -->
  <rect x="265" y="46" width="230" height="310" rx="6" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
  <text x="380" y="66" text-anchor="middle" font-size="10.5" font-weight="700" fill="#1e293b">DEFECT 2: HEURISTIC COUPLING</text>

  <g transform="translate(275, 78)">
    <rect width="210" height="266" rx="4" fill="#fef2f2" stroke="#ef4444" stroke-width="1.5" />
    <text x="105" y="20" text-anchor="middle" font-size="10.5" font-weight="700" fill="#991b1b">Severity Hardcoding</text>
    <text x="105" y="36" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#b91c1c">universal_parser.py:72</text>

    <line x1="15" y1="46" x2="195" y2="46" stroke="#fca5a5" stroke-width="1" />

    <text x="15" y="64" font-size="8.5" font-weight="600" fill="#7f1d1d">• Hardcoded Policy Rule:</text>
    <rect x="12" y="72" width="186" height="38" rx="3" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
    <text x="18" y="86" font-size="8" font-family="monospace" fill="#0f172a">if alert.get('mitre_ids'):</text>
    <text x="30" y="100" font-size="8" font-family="monospace" fill="#dc2626">severity = 'HIGH'</text>

    <text x="15" y="128" font-size="8.5" font-weight="600" fill="#7f1d1d">• Context Blindness:</text>
    <text x="23" y="142" font-size="8" fill="#475569">Parser ignores zero-confidence</text>
    <text x="23" y="156" font-size="8" fill="#475569">retrieval score and assumes all</text>
    <text x="23" y="170" font-size="8" fill="#475569">MITRE IDs indicate active breach.</text>

    <rect x="15" y="196" width="180" height="48" rx="4" fill="#fee2e2" stroke="#dc2626" stroke-width="1.2" />
    <text x="105" y="214" text-anchor="middle" font-size="9" font-weight="700" fill="#991b1b">FORCED SEVERITY:</text>
    <text x="105" y="232" text-anchor="middle" font-size="10" font-weight="800" fill="#b91c1c">AlertSeverity.HIGH</text>
  </g>

  <!-- Arrow Col 2 -> Col 3 -->
  <path d="M485, 250 L513, 250" fill="none" stroke="#dc2626" stroke-width="2" marker-end="url(#arr24Red)" />

  <!-- Col 3: Defect 3 & Disaster -->
  <rect x="515" y="46" width="230" height="310" rx="6" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
  <text x="630" y="66" text-anchor="middle" font-size="10.5" font-weight="700" fill="#1e293b">DEFECT 3: OVERRIDE &amp; OUTAGE</text>

  <g transform="translate(525, 78)">
    <!-- LLM Triage box -->
    <rect width="210" height="54" rx="4" fill="#ecfdf5" stroke="#10b981" stroke-width="1.2" />
    <text x="105" y="18" text-anchor="middle" font-size="9.5" font-weight="700" fill="#065f46">Advisory Llama-3 Triage</text>
    <text x="105" y="32" text-anchor="middle" font-size="9" font-weight="700" fill="#047857">Verdict: BENIGN (conf=0.94)</text>
    <text x="105" y="45" text-anchor="middle" font-size="7.5" fill="#065f46">Correctly identifies routine admin script</text>

    <!-- Down arrow to contradiction guard -->
    <path d="M105, 54 L105, 68" fill="none" stroke="#dc2626" stroke-width="1.5" marker-end="url(#arr24Red)" />

    <!-- Contradiction guard box -->
    <rect y="70" width="210" height="114" rx="4" fill="#fef2f2" stroke="#ef4444" stroke-width="1.5" />
    <text x="105" y="86" text-anchor="middle" font-size="10" font-weight="700" fill="#991b1b">ContradictionGuard</text>
    <text x="105" y="98" text-anchor="middle" font-size="8" font-family="monospace" fill="#b91c1c">decision/engine.py:314</text>

    <text x="15" y="116" font-size="8" font-weight="600" fill="#7f1d1d">• Hard Override Rule:</text>
    <text x="20" y="128" font-size="7.5" font-family="monospace" fill="#0f172a">if sev == HIGH: LLM is suppressed</text>
    <text x="15" y="144" font-size="8" font-weight="600" fill="#7f1d1d">• Overruled to MALICIOUS:</text>
    <text x="20" y="156" font-size="8" fill="#991b1b">Confidence forced to 1.0 (Zero OOD)</text>

    <rect x="15" y="162" width="180" height="16" rx="2" fill="#fee2e2" stroke="#dc2626" stroke-width="1" />
    <text x="105" y="174" text-anchor="middle" font-size="8" font-weight="700" fill="#b91c1c">Verdict: MALICIOUS (Forced)</text>

    <!-- Down arrow to actuation disaster -->
    <path d="M105, 184 L105, 200" fill="none" stroke="#dc2626" stroke-width="2" marker-end="url(#arr24Red)" />

    <!-- Disaster output box -->
    <rect y="202" width="210" height="64" rx="4" fill="#7f1d1d" stroke="#450a0a" stroke-width="1.5" />
    <text x="105" y="222" text-anchor="middle" font-size="10" font-weight="800" fill="#ffffff">SELF-DOS OUTAGE</text>
    <text x="105" y="238" text-anchor="middle" font-size="8.5" fill="#fecaca">Autonomous IPTables block &amp; SIGKILL</text>
    <text x="105" y="252" text-anchor="middle" font-size="9" font-weight="700" fill="#fca5a5">40 / 40 (100%) Benign Outage [CE-19]</text>
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
  ${fig24Svg}
</body>
</html>`;

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
await page.setContent(html, { waitUntil: 'networkidle0' });
await (await page.$('#fig24-container')).screenshot({ path: 'report/scratch/test_fig24_svg.png' });
await browser.close();
console.log('Saved test_fig24_svg.png successfully.');
