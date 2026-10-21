import puppeteer from 'puppeteer-core';

const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.0/dist/mermaid.min.js"></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fff; padding: 20px; width: 900px; }
    .mermaid { display: flex; justify-content: center; width: 100%; margin: 20px 0; }
    .mermaid svg { max-width: 100%; height: auto; }
  </style>
</head>
<body>
  <div class="mermaid">
flowchart LR
    subgraph D1 ["Defect 1: Unconditional Top-K"]
        direction TB
        B1["Benign Admin Activity<br/><code>CI/CD, mysqldump, scripts</code>"] --> R1["Defense RAG<br/><code>retrieve_playbook(k=4)</code>"]
        R1 -->|"Cosine Sim ~ 0.0<br/>(No Cutoff)"| F1["Forces 4 ATT&CK Matches<br/><code>T1190, T1071</code>"]
    end

    subgraph D2 ["Defect 2: Severity Forcing"]
        direction TB
        P2["universal_parser.py:72<br/><code>Normalizes MITRE IDs</code>"] -->|"Any Technique Present"| F2["Forced HIGH Severity<br/><code>AlertSeverity.HIGH</code>"]
    end

    subgraph D3 ["Defect 3: Override Cascade"]
        direction TB
        LLM["Llama-3 LLM<br/><code>Verdict: BENIGN</code>"]
        CG["ContradictionGuard<br/><code>decision/engine.py:314</code>"]
        LLM --> CG
        CG -->|"Severity HIGH Overrides LLM"| FM["Forced MALICIOUS<br/><code>Confidence = 1.0</code>"]
        FM --> ACT["Autonomous Containment<br/><code>Firewall Block (Outage)</code>"]
    end

    F1 ==> P2
    F2 ==> CG

    classDef input fill:#f8fafc,stroke:#64748b,stroke-width:1.5px;
    classDef defect fill:#fef2f2,stroke:#ef4444,stroke-width:2px;
    classDef output fill:#fee2e2,stroke:#b91c1c,stroke-width:2.5px;
    class B1,LLM input;
    class F1,F2,FM defect;
    class ACT output;
  </div>
  <script>
    mermaid.initialize({ startOnLoad: false, theme: 'neutral' });
    const code = document.querySelector('.mermaid').textContent;
    mermaid.parse(code).then(() => {
      mermaid.run();
      console.log("PARSE SUCCESS");
      window.__DONE = true;
    }).catch(err => {
      console.error("PARSE ERROR:", err.message || err.toString());
      window.__DONE = true;
    });
  </script>
</body>
</html>`;

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
page.on('console', msg => console.log('PAGE LOG:', msg.text()));
await page.setContent(html, { waitUntil: 'networkidle0' });
await page.waitForFunction(() => window.__DONE === true, { timeout: 10000 });

const dims = await page.evaluate(() => {
  const svg = document.querySelector('.mermaid svg');
  if (!svg) return null;
  const rect = svg.getBoundingClientRect();
  const vb = svg.getAttribute('viewBox');
  return { width: rect.width, height: rect.height, viewBox: vb };
});
if (dims) {
  console.log('Fig 11 dims:', dims, 'Aspect ratio:', (dims.width / dims.height).toFixed(2));
  await (await page.$('.mermaid')).screenshot({ path: 'report/scratch/test_fig11.png' });
} else {
  console.log('No SVG rendered.');
}
await browser.close();
