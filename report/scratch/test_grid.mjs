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
    body { font-family: -apple-system, sans-serif; background: #fff; width: 1100px; margin: 20px auto; }
    .mermaid { display: flex; justify-content: center; width: 100%; margin: 20px 0; }
    .mermaid svg { max-width: 100%; height: auto; }
  </style>
</head>
<body>
  <h2>Test Fig. 5 in 2x2 Balanced Grid</h2>
  <div class="mermaid">
flowchart TB
    subgraph Row1 [" "]
        direction LR
        subgraph S1 ["Stage 1: Telemetry Ingestion"]
            direction TB
            A["Network Socket / Mirror TAP"] --> B["LiveFlowSniffer"]
            B -->|"TCP Teardown / Timeout"| D["32 Canonical Features"]
            E["Suricata EVE JSON"] -->|"eve_to_flow_features"| D
            F["Upload Ingest Adapter"] --> D
        end

        subgraph S2 ["Stage 2: Multi-Signal Inference & Routing"]
            direction TB
            D --> NORM["Robust Normalization (Median / IQR)"]
            NORM --> H["Supervised XGBoost"]
            NORM --> I["Statistical Z-Score"]
            NORM --> J["Deep Autoencoder MSE"]
            H & I & J --> ROUTE{"Canonical Router"}
        end
        S1 ==> S2
    end

    subgraph Row2 [" "]
        direction LR
        subgraph S3 ["Stage 3: Cognitive Advisory & SMT Safety"]
            direction TB
            ROUTE2["Router: known_attack"] --> ENG["Decision Engine"]
            ENG --> RAG["Defense RAG (ATT&CK)"]
            RAG --> LLM["Advisory LLM (Llama-3-8B)"]
            LLM --> SMT{"Formal Safety Gate"}
        end

        subgraph S4 ["Stage 4: Actuation & Human Oversight"]
            direction TB
            SMT -->|"Violated / Self-DoS"| BLK["Blocked (Log Only)"]
            SMT -->|"Admitted"| TPR{"Two-Person Rule"}
            TPR -->|"Approved"| ACT["Actuators: Firewall / Process"]
            ACT --> REC["HMAC Rollback Receipt"]
        end
        S3 ==> S4
    end

    S2 ==>|"known_attack Alert"| S3
    ROUTE -->|"unknown_anomaly / out_of_scope"| HR["Human Analyst Review Queue"]
    ROUTE -->|"benign"| BEN["Quiet Audit Stream"]

    classDef stage fill:#f8fafc,stroke:#2563eb,stroke-width:1.5px;
    classDef safety fill:#fef2f2,stroke:#ef4444,stroke-width:1.5px;
    classDef success fill:#ecfdf5,stroke:#10b981,stroke-width:1.5px;
    class S1,S2,S3,S4 stage;
    class BLK safety;
    class REC,BEN success;
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

fs.writeFileSync('report/scratch/test_grid.html', testHtml, 'utf-8');

async function testRender() {
  const browser = await puppeteer.launch({ executablePath: edgeBinaryPath, headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1240, height: 1754 });
  const htmlPath = path.resolve('report/scratch/test_grid.html');
  await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), { waitUntil: 'networkidle0' });
  await new Promise(r => setTimeout(r, 2000));

  const dims = await page.evaluate(() => {
    const svg = document.querySelector('.mermaid svg');
    const rect = svg.getBoundingClientRect();
    const vb = svg.getAttribute('viewBox');
    return {
      width: Math.round(rect.width),
      height: Math.round(rect.height),
      aspectRatio: (rect.width / (rect.height || 1)).toFixed(2),
      viewBox: vb
    };
  });

  console.log('2x2 Grid Dims:', dims);

  const mermaid = await page.$('.mermaid');
  if (mermaid) {
    await mermaid.screenshot({ path: 'report/scratch/test_fig5_grid.png' });
    console.log('Saved screenshot test_fig5_grid.png');
  }

  await browser.close();
}

testRender().catch(console.error);
