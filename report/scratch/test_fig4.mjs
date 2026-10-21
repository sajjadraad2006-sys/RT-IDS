import puppeteer from 'puppeteer-core';
import fs from 'fs';

const mermaidCode = `flowchart TD
    subgraph Row1 ["Phase I: Real-Time Detection and Ingestion Pipeline"]
        direction LR
        subgraph L1 ["Layer 1: Ingestion"]
            L1_A["Raw Socket Sniffer"]
            L1_B["Suricata EVE Tailer"]
            L1_C["Universal Parser"]
        end

        subgraph L2 ["Layer 2: Features"]
            L2_A["32-Feature Extraction"]
            L2_B["Log1p Normalizer"]
        end

        subgraph L3 ["Layer 3: Evidence Fusion"]
            L3_A["XGBoost Classifier"]
            L3_B["Z-Score Filter"]
            L3_C["Deep Autoencoder"]
            L3_D["Canonical Router"]
        end

        L1_A & L1_B & L1_C --> L2_A
        L2_A --> L2_B
        L2_B --> L3_A & L3_B & L3_C
        L3_A & L3_B & L3_C --> L3_D
    end

    subgraph Row2 ["Phase II: Cognitive Triage, Safety Verification and Storage"]
        direction LR
        subgraph L4 ["Layer 4: Cognitive Advisory"]
            L4_A["MITRE Graph-RAG"]
            L4_B["Advisory LLM"]
            L4_C["Contradiction Guard"]
            L4_A --> L4_B --> L4_C
        end

        subgraph L5 ["Layer 5: Safety and Containment"]
            L5_A["Formal Safety Verifier"]
            L5_B["Two-Person Rule"]
            L5_C["Host Firewall Actuator"]
            L5_D["Process Isolation"]
            L5_A --> L5_B --> L5_C & L5_D
        end

        subgraph L6 ["Layer 6: API and Storage"]
            L6_A["FastAPI REST Service"]
            L6_B["SQLite WAL Persistence"]
            L6_C["Operations Dashboard"]
            L6_A --> L6_B & L6_C
        end
    end

    L3_D -->|"Ambiguous Anomaly"| L4_A
    L3_D -->|"Known Attack"| L5_A
    L4_C -->|"Certified Response"| L5_A
    L5_A --> L6_A`;

const html = `<!DOCTYPE html><html><head>
<script src="../node_modules/mermaid/dist/mermaid.min.js"></script>
<script>
document.addEventListener("DOMContentLoaded", async function() {
  mermaid.initialize({ startOnLoad: true, theme: 'neutral', themeVariables: { fontSize: '13px' } });
  await mermaid.run();
  window.__READY = true;
});
</script>
</head><body style="background:#fff; margin:20px;">
<div class="mermaid">${mermaidCode}</div>
</body></html>`;

fs.writeFileSync('scratch/test_fig4.html', html, 'utf-8');

async function test() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    headless: 'new'
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1100, height: 900 });
  await page.goto('file:///' + 'report/scratch/test_fig4.html', { waitUntil: 'networkidle0' });
  await page.waitForFunction(() => window.__READY === true);
  await new Promise(r => setTimeout(r, 1000));
  const el = await page.$('.mermaid');
  await el.screenshot({ path: 'dist/screenshots/fig4_test.png' });
  console.log('Saved fig4_test.png');
  await browser.close();
}
test();
