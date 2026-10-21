import puppeteer from 'puppeteer-core';

const fig22Svg = `<div id="fig22-container" style="width: 100%; max-width: 760px; margin: 16px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<svg viewBox="0 0 760 360" width="100%" height="auto" xmlns="http://www.w3.org/2000/svg" style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
  <defs>
    <linearGradient id="headerGrad22" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#1e293b" />
    </linearGradient>
    <marker id="arr22Blue" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#2563eb" />
    </marker>
    <marker id="arr22Red" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#dc2626" />
    </marker>
    <marker id="arr22Green" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#16a34a" />
    </marker>
  </defs>

  <!-- Banner Header -->
  <rect x="0" y="0" width="760" height="34" rx="8" fill="url(#headerGrad22)" />
  <rect x="0" y="24" width="760" height="10" fill="url(#headerGrad22)" />
  <text x="380" y="22" text-anchor="middle" font-size="12" font-weight="700" fill="#ffffff" letter-spacing="0.5">
    PRE-DESERIALIZATION CRYPTOGRAPHIC VERIFICATION PROTOCOL (FAIL-CLOSED BOUNDARY)
  </text>

  <!-- Lane 1: Manifest & Schema Gate -->
  <rect x="15" y="46" width="355" height="300" rx="6" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
  <text x="30" y="66" font-size="11" font-weight="700" fill="#1e293b" letter-spacing="0.3">PHASE 1: MANIFEST &amp; SCHEMA INTEGRITY</text>

  <!-- Step 1.1: Init Request -->
  <g transform="translate(30, 80)">
    <rect width="325" height="42" rx="4" fill="#ffffff" stroke="#64748b" stroke-width="1.2" />
    <text x="162" y="18" text-anchor="middle" font-size="10.5" font-weight="700" fill="#0f172a">1. Pipeline Initialization Request</text>
    <text x="162" y="32" text-anchor="middle" font-size="8.5" fill="#475569">Detection pipeline startup or model hot-reload</text>
  </g>

  <!-- Down Arrow 1 -->
  <path d="M192, 122 L192, 138" fill="none" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr22Blue)" />

  <!-- Step 1.2: Read artifacts.json -->
  <g transform="translate(30, 140)">
    <rect width="325" height="46" rx="4" fill="#ffffff" stroke="#2563eb" stroke-width="1.5" />
    <text x="162" y="18" text-anchor="middle" font-size="10.5" font-weight="700" fill="#1e3a8a">2. Read Manifest (artifacts.json)</text>
    <text x="162" y="32" text-anchor="middle" font-size="8.5" font-weight="600" fill="#dc2626">Reject Symlinks: is_file() &amp;&amp; !is_symlink()</text>
    <text x="162" y="42" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#2563eb">[CE-11:405] Mitigates TOCTOU Race Condition</text>
  </g>

  <!-- Down Arrow 2 -->
  <path d="M192, 186 L192, 202" fill="none" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr22Blue)" />

  <!-- Step 1.3: Decision Schema & Hash -->
  <g transform="translate(30, 204)">
    <polygon points="162,0 325,32 162,64 0,32" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5" />
    <text x="162" y="24" text-anchor="middle" font-size="9.5" font-weight="700" fill="#1e3a8a">Schema == 'v1' &amp;&amp;</text>
    <text x="162" y="38" text-anchor="middle" font-size="9" font-weight="600" fill="#1e40af">Feature Hash == Code?</text>
    <text x="162" y="50" text-anchor="middle" font-size="7.5" fill="#475569">[CE-11:412] Schema Invariant</text>
  </g>

  <!-- No Branch: Reject Schema -->
  <path d="M192, 268 L192, 286" fill="none" stroke="#dc2626" stroke-width="1.5" marker-end="url(#arr22Red)" />
  <text x="180" y="280" text-anchor="end" font-size="8.5" font-weight="700" fill="#dc2626">NO</text>
  <g transform="translate(30, 288)">
    <rect width="325" height="44" rx="4" fill="#fef2f2" stroke="#ef4444" stroke-width="1.2" />
    <text x="162" y="18" text-anchor="middle" font-size="9.5" font-weight="700" fill="#b91c1c">FAIL-CLOSED: Raise IntegrityError</text>
    <text x="162" y="32" text-anchor="middle" font-size="8" fill="#991b1b">Schema drift or untrusted format detected</text>
  </g>

  <!-- Yes Branch to Lane 2 -->
  <path d="M355, 236 L393, 236 L393, 101 L418, 101" fill="none" stroke="#16a34a" stroke-width="2" marker-end="url(#arr22Green)" />
  <text x="368" y="228" font-size="9" font-weight="700" fill="#16a34a">YES</text>

  <!-- Lane 2: Artifact Streaming Digest & Execution Admission -->
  <rect x="390" y="46" width="355" height="300" rx="6" fill="#f0fdf4" stroke="#86efac" stroke-width="1" />
  <text x="405" y="66" font-size="11" font-weight="700" fill="#14532d" letter-spacing="0.3">PHASE 2: STREAMING DIGEST &amp; ADMISSION</text>

  <!-- Step 2.1: Iterate Files -->
  <g transform="translate(405, 80)">
    <rect width="325" height="42" rx="4" fill="#ffffff" stroke="#16a34a" stroke-width="1.2" />
    <text x="162" y="18" text-anchor="middle" font-size="10.5" font-weight="700" fill="#14532d">3. Iterate ARTIFACT_FILENAMES</text>
    <text x="162" y="32" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#15803d">normalizer.pkl, classifier.pkl, autoencoder.pt</text>
  </g>

  <!-- Down Arrow 3 -->
  <path d="M567, 122 L567, 138" fill="none" stroke="#16a34a" stroke-width="1.5" marker-end="url(#arr22Green)" />

  <!-- Step 2.2: Stream SHA-256 -->
  <g transform="translate(405, 140)">
    <rect width="325" height="46" rx="4" fill="#ffffff" stroke="#16a34a" stroke-width="1.2" />
    <text x="162" y="18" text-anchor="middle" font-size="10.5" font-weight="700" fill="#14532d">4. Compute Streaming SHA-256</text>
    <text x="162" y="32" text-anchor="middle" font-size="8.5" fill="#475569">1 MB buffer chunks (constant memory) [CE-11:426]</text>
    <text x="162" y="42" text-anchor="middle" font-size="7.5" fill="#166534">Rejects symlinks &amp;&amp; validates tau in (0, 1]</text>
  </g>

  <!-- Down Arrow 4 -->
  <path d="M567, 186 L567, 202" fill="none" stroke="#16a34a" stroke-width="1.5" marker-end="url(#arr22Green)" />

  <!-- Step 2.3: Checksum Diamond -->
  <g transform="translate(405, 204)">
    <polygon points="162,0 325,32 162,64 0,32" fill="#ecfdf5" stroke="#10b981" stroke-width="1.5" />
    <text x="162" y="24" text-anchor="middle" font-size="9.5" font-weight="700" fill="#065f46">SHA-256 == Declared Digest?</text>
    <text x="162" y="38" text-anchor="middle" font-size="8.5" fill="#047857">Constant-time string comparison</text>
    <text x="162" y="50" text-anchor="middle" font-size="7.5" fill="#475569">[CE-11:430] All artifacts valid</text>
  </g>

  <!-- Left/Down No: Reject Digest -->
  <path d="M405, 236 L393, 236 L393, 305 L357, 305" fill="none" stroke="#dc2626" stroke-width="1.5" marker-end="url(#arr22Red)" />
  <text x="390" y="250" text-anchor="middle" font-size="8" font-weight="700" fill="#dc2626">MISMATCH</text>

  <!-- Down Yes: Admit Deserialization -->
  <path d="M567, 268 L567, 286" fill="none" stroke="#16a34a" stroke-width="2" marker-end="url(#arr22Green)" />
  <text x="578" y="280" font-size="8.5" font-weight="700" fill="#16a34a">VERIFIED</text>
  <g transform="translate(405, 288)">
    <rect width="325" height="44" rx="4" fill="#dcfce7" stroke="#16a34a" stroke-width="1.5" />
    <text x="162" y="18" text-anchor="middle" font-size="10" font-weight="700" fill="#14532d">ADMIT TO DESERIALIZATION</text>
    <text x="162" y="32" text-anchor="middle" font-size="8.5" font-family="monospace" fill="#15803d">pickle.load() / joblib.load() permitted</text>
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
  ${fig22Svg}
</body>
</html>`;

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
await page.setContent(html, { waitUntil: 'networkidle0' });
await (await page.$('#fig22-container')).screenshot({ path: 'report/scratch/test_fig22_svg.png' });
await browser.close();
console.log('Saved test_fig22_svg.png successfully.');
