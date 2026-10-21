import puppeteer from 'puppeteer-core';
import path from 'path';
import fs from 'fs';

const edgeBinaryPath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';

const testHtml = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.0/dist/mermaid.min.js"></script>
  <style>
    body { font-family: -apple-system, sans-serif; background: #fff; width: 1000px; margin: 20px auto; }
    .mermaid { display: flex; justify-content: center; width: 100%; margin: 20px 0; }
    .mermaid svg { max-width: 100%; height: auto; }
  </style>
</head>
<body>
  <h2>Enhanced Fig. 11 (2-Tier Flow)</h2>
  <div class="mermaid">
flowchart TD
    subgraph Capture ["1. Sensor Log Capture Tier"]
        direction LR
        SURI["Suricata 7.x NIDS Engine"] -->|"Write EVE Alert JSON"| EVE["eve.json File Stream<br/>(/var/log/suricata/eve.json)"]
        EVE -->|"Win32 / Inotify Tailer"| TAIL["SuricataLiveTailer Engine"]
    end

    subgraph Synth ["2. Feature Synthesis & Pipeline Ingestion Tier"]
        direction LR
        TAIL -->|"Parse Raw Alert"| MAP["Feature Synthesis<br/>(eve_to_flow_features)"]
        MAP -->|"Approximated 32-Feature Vector"| PIPE["Pipeline v2 Inference Engine"]
        PIPE -->|"Persist Alert"| DB[("SQLite WAL Database<br/>(cyberguard.db)")]
    end

    Capture ==>|"Event Ingestion Stream"| Synth

    classDef tier fill:#f8fafc,stroke:#2563eb,stroke-width:1.5px;
    class Capture,Synth tier;
  </div>

  <h2>Enhanced Fig. 12 (2-Stage Flow)</h2>
  <div class="mermaid">
flowchart TD
    subgraph Gen ["1. Cognitive Advisory Generation"]
        direction LR
        Alert["Pipeline Alert:<br/>known_attack"] --> RAG["Defense RAG Engine<br/>(MITRE ATT&CK)"]
        RAG -->|"Top-K Context"| LLM["Llama-3-8B Advisory LLM"]
        LLM -->|"JSON Decision"| PARSE["Structured Decision Parser"]
    end

    subgraph Guard ["2. Contradiction & Safety Interlock"]
        direction LR
        PARSE --> GUARD{"Contradiction Guard<br/>(engine.py:79)"}
        GUARD -->|"High Severity & LLM Benign"| OVERRIDE["Safety Override:<br/>Force Malicious"]
        GUARD -->|"Consistent"| PROCEED["Submit to Formal Safety Gate"]
        OVERRIDE --> PROCEED
    end

    Gen ==> Guard

    classDef stage fill:#f8fafc,stroke:#7c3aed,stroke-width:1.5px;
    classDef alert fill:#fef2f2,stroke:#ef4444,stroke-width:1.5px;
    class Gen,Guard stage;
    class Alert,OVERRIDE alert;
  </div>

  <script>
    mermaid.initialize({
      startOnLoad: true,
      theme: 'neutral',
      flowchart: {
        useMaxWidth: true,
        nodeSpacing: 25,
        rankSpacing: 35
      }
    });
  </script>
</body>
</html>`;

fs.writeFileSync('report/scratch/test_fig11_12.html', testHtml, 'utf-8');

async function capture() {
  const browser = await puppeteer.launch({ executablePath: edgeBinaryPath, headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1240, height: 1200 });
  const htmlPath = path.resolve('report/scratch/test_fig11_12.html');
  await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), { waitUntil: 'networkidle0' });
  await new Promise(r => setTimeout(r, 2000));
  
  const dims = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('.mermaid svg')).map((svg, i) => {
      const rect = svg.getBoundingClientRect();
      const vb = svg.getAttribute('viewBox');
      return {
        figure: i === 0 ? 'Fig 11' : 'Fig 12',
        width: Math.round(rect.width),
        height: Math.round(rect.height),
        aspectRatio: (rect.width / (rect.height || 1)).toFixed(2),
        viewBox: vb
      };
    });
  });

  console.table(dims);

  const mermaids = await page.$$('.mermaid');
  if (mermaids.length >= 2) {
    await mermaids[0].screenshot({ path: 'report/scratch/test_fig11_rendered.png' });
    await mermaids[1].screenshot({ path: 'report/scratch/test_fig12_rendered.png' });
    console.log('Saved test_fig11_rendered.png and test_fig12_rendered.png');
  }
  await browser.close();
}
capture().catch(console.error);
