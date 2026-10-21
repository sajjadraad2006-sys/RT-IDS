import puppeteer from 'puppeteer-core';
import fs from 'fs';

const fig11Svg = `<div id="fig11-container" style="width: 100%; max-width: 760px; margin: 16px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<svg viewBox="0 0 760 280" width="100%" height="auto" xmlns="http://www.w3.org/2000/svg" style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
  <defs>
    <linearGradient id="headerGrad11" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#1e293b" />
    </linearGradient>
    <linearGradient id="cardSensorGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#f8fafc" />
      <stop offset="100%" stop-color="#f1f5f9" />
    </linearGradient>
    <linearGradient id="cardPipeGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#eff6ff" />
      <stop offset="100%" stop-color="#dbeafe" />
    </linearGradient>
    <marker id="arrBlue" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#2563eb" />
    </marker>
    <marker id="arrDark" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#475569" />
    </marker>
  </defs>

  <!-- Banner Header -->
  <rect x="0" y="0" width="760" height="34" rx="8" fill="url(#headerGrad11)" />
  <rect x="0" y="24" width="760" height="10" fill="url(#headerGrad11)" />
  <text x="380" y="22" text-anchor="middle" font-size="12" font-weight="700" fill="#ffffff" letter-spacing="0.5">
    SURICATA LIVE TAILER: EVE STREAMING INGESTION &amp; FEATURE SYNTHESIS TOPOLOGY
  </text>

  <!-- Tier 1: Log Generation & Sensor Tailer -->
  <rect x="15" y="46" width="730" height="98" rx="6" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
  <text x="28" y="64" font-size="11" font-weight="700" fill="#334155" letter-spacing="0.3">TIER 1: EXTERNAL NIDS SENSOR &amp; LOG TAILER</text>

  <!-- Box 1: Suricata Engine -->
  <g transform="translate(30, 72)">
    <rect width="200" height="60" rx="5" fill="#ffffff" stroke="#64748b" stroke-width="1.2" />
    <text x="100" y="22" text-anchor="middle" font-size="11" font-weight="700" fill="#0f172a">Suricata 7.x NIDS</text>
    <text x="100" y="38" text-anchor="middle" font-size="9" fill="#475569">Multi-threaded packet sniffing</text>
    <text x="100" y="50" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#0284c7">AF_PACKET / PF_RING</text>
  </g>

  <!-- Arrow 1 -> 2 -->
  <path d="M230, 102 L272, 102" fill="none" stroke="#475569" stroke-width="1.5" marker-end="url(#arrDark)" />
  <text x="251" y="94" text-anchor="middle" font-size="8" fill="#64748b">Appends alerts</text>

  <!-- Box 2: eve.json -->
  <g transform="translate(280, 72)">
    <rect width="200" height="60" rx="5" fill="#ffffff" stroke="#64748b" stroke-width="1.2" />
    <text x="100" y="22" text-anchor="middle" font-size="11" font-weight="700" fill="#0f172a">Live EVE Log Stream</text>
    <text x="100" y="38" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#0369a1">/var/log/suricata/eve.json</text>
    <text x="100" y="50" text-anchor="middle" font-size="8.5" fill="#475569">JSON stream records</text>
  </g>

  <!-- Arrow 2 -> 3 -->
  <path d="M480, 102 L522, 102" fill="none" stroke="#475569" stroke-width="1.5" marker-end="url(#arrDark)" />
  <text x="501" y="94" text-anchor="middle" font-size="8" fill="#64748b">Inotify / tail</text>

  <!-- Box 3: SuricataLiveTailer -->
  <g transform="translate(530, 72)">
    <rect width="200" height="60" rx="5" fill="#ffffff" stroke="#2563eb" stroke-width="1.5" />
    <text x="100" y="22" text-anchor="middle" font-size="11" font-weight="700" fill="#1e3a8a">SuricataLiveTailer</text>
    <text x="100" y="38" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#2563eb">backend/suricata/tailer.py</text>
    <text x="100" y="50" text-anchor="middle" font-size="8.5" font-weight="600" fill="#16a34a">[CE-05] Non-blocking reader</text>
  </g>

  <!-- Down/Turn Arrow: Tier 1 Tailer -> Tier 2 Feature Synthesis -->
  <path d="M630, 132 L630, 154 L130, 154 L130, 178" fill="none" stroke="#2563eb" stroke-width="2" stroke-dasharray="4,3" marker-end="url(#arrBlue)" />
  <rect x="320" y="146" width="120" height="16" rx="3" fill="#ffffff" stroke="#93c5fd" stroke-width="1" />
  <text x="380" y="158" text-anchor="middle" font-size="8.5" font-weight="600" fill="#1e40af">Parsed EVE Alert Dict</text>

  <!-- Tier 2: Feature Synthesis & Pipeline Ingestion -->
  <rect x="15" y="170" width="730" height="98" rx="6" fill="#f0fdf4" stroke="#86efac" stroke-width="1" />
  <text x="28" y="188" font-size="11" font-weight="700" fill="#166534" letter-spacing="0.3">TIER 2: CYBERGUARD FEATURE SYNTHESIS &amp; AUDIT PIPELINE</text>

  <!-- Box 4: Feature Synthesis -->
  <g transform="translate(30, 196)">
    <rect width="200" height="60" rx="5" fill="#ffffff" stroke="#16a34a" stroke-width="1.2" />
    <text x="100" y="22" text-anchor="middle" font-size="11" font-weight="700" fill="#14532d">Feature Synthesis</text>
    <text x="100" y="38" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#15803d">eve_to_flow_features()</text>
    <text x="100" y="50" text-anchor="middle" font-size="8.5" font-weight="600" fill="#0284c7">[CE-40] 32-Feature Vector</text>
  </g>

  <!-- Arrow 4 -> 5 -->
  <path d="M230, 226 L272, 226" fill="none" stroke="#16a34a" stroke-width="1.5" marker-end="url(#arrBlue)" />
  <text x="251" y="218" text-anchor="middle" font-size="8" fill="#15803d">Flow vector</text>

  <!-- Box 5: Pipeline Engine -->
  <g transform="translate(280, 196)">
    <rect width="200" height="60" rx="5" fill="#ffffff" stroke="#16a34a" stroke-width="1.2" />
    <text x="100" y="22" text-anchor="middle" font-size="11" font-weight="700" fill="#14532d">Pipeline v2 Engine</text>
    <text x="100" y="38" text-anchor="middle" font-size="9" fill="#475569">RandomForest / LightGBM</text>
    <text x="100" y="50" text-anchor="middle" font-size="8.5" font-weight="600" fill="#2563eb">[CE-08] Multi-class scoring</text>
  </g>

  <!-- Arrow 5 -> 6 -->
  <path d="M480, 226 L522, 226" fill="none" stroke="#16a34a" stroke-width="1.5" marker-end="url(#arrBlue)" />
  <text x="501" y="218" text-anchor="middle" font-size="8" fill="#15803d">Persist audit</text>

  <!-- Box 6: SQLite WAL DB -->
  <g transform="translate(530, 196)">
    <rect width="200" height="60" rx="5" fill="#ffffff" stroke="#16a34a" stroke-width="1.2" />
    <text x="100" y="22" text-anchor="middle" font-size="11" font-weight="700" fill="#14532d">SQLite WAL Storage</text>
    <text x="100" y="38" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#047857">cyberguard.db</text>
    <text x="100" y="50" text-anchor="middle" font-size="8.5" font-weight="600" fill="#16a34a">[CE-05] Concurrent WAL Mode</text>
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
  ${fig11Svg}
</body>
</html>`;

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
await page.setContent(html, { waitUntil: 'networkidle0' });
await (await page.$('#fig11-container')).screenshot({ path: 'report/scratch/test_fig11_svg.png' });
await browser.close();
console.log('Saved test_fig11_svg.png successfully.');
