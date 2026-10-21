import puppeteer from 'puppeteer-core';
import fs from 'fs';

async function test() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1000, height: 1200, deviceScaleFactor: 2 });
  
  const m1 = `flowchart TD
    subgraph P1 ["Phase I: Real-Time Detection & Ingestion Pipeline"]
        direction LR
        subgraph L1 ["Layer 1: Ingestion"]
            L1_A["Raw Socket Sniffer"]
            L1_B["Suricata EVE Tailer"]
            L1_C["Universal Parser"]
        end
        subgraph L2 ["Layer 2: Features"]
            L2_A["32-Feature Extraction"]
            L2_B["Log1p Normalizer"]
            L2_A --> L2_B
        end
        subgraph L3 ["Layer 3: Evidence Fusion"]
            L3_A["XGBoost Classifier"]
            L3_B["Z-Score Filter"]
            L3_C["Deep Autoencoder"]
            L3_D["Canonical Router"]
            L3_A & L3_B & L3_C --> L3_D
        end
        L1 --> L2 --> L3
    end

    subgraph P2 ["Phase II: Cognitive Triage, Safety & Storage"]
        direction LR
        subgraph L4 ["Layer 4: Cognitive Advisory"]
            L4_A["MITRE Graph-RAG"]
            L4_B["Advisory LLM"]
            L4_C["Contradiction Guard"]
            L4_A --> L4_B --> L4_C
        end
        subgraph L5 ["Layer 5: Safety Verification"]
            L5_A["Formal Safety Verifier"]
            L5_B["Two-Person Rule"]
            L5_C["Containment Actuators"]
            L5_A --> L5_B --> L5_C
        end
        subgraph L6 ["Layer 6: API & Storage"]
            L6_A["FastAPI REST Service"]
            L6_B["SQLite WAL DB"]
            L6_C["Dashboard UI"]
            L6_A --> L6_B & L6_C
        end
        L4 --> L5 --> L6
    end

    L3 -->|"Ambiguous Anomaly"| L4
    L3 -->|"Known Attack"| L5
    L4 -.->|"Certified Advice"| L5
`;

  await page.setContent(`
    <!DOCTYPE html>
    <html>
      <head>
        <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
        <style>
          body { background: white; font-family: sans-serif; padding: 20px; }
          .mermaid { max-width: 820px; margin: 0 auto; }
        </style>
      </head>
      <body>
        <div class="mermaid">${m1}</div>
        <script>
          mermaid.initialize({
            startOnLoad: true,
            theme: 'neutral',
            fontFamily: 'Inter, system-ui, sans-serif'
          });
        </script>
      </body>
    </html>
  `);
  await page.waitForSelector('svg');
  const svg = await page.$('svg');
  const bb = await svg.boundingBox();
  console.log('BoundingBox:', bb);
  await svg.screenshot({ path: 'report/scratch/fig4_compact.png' });
  await browser.close();
}
test();
