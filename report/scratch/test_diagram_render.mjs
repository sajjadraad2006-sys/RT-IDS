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
    .mermaid .messageText { font-size: 14px !important; font-weight: 500 !important; }
    .mermaid .actor { font-size: 14px !important; font-weight: 600 !important; }
    .mermaid .noteText { font-size: 13px !important; }
  </style>
</head>
<body>
  <h2>Test Fig. 5 (Redesigned Horizontal 4-Stage Flowchart)</h2>
  <div class="mermaid">
flowchart LR
    subgraph S1 ["1. Telemetry Ingestion"]
        direction TB
        A["Network Interface / Raw Socket"] --> B["LiveFlowSniffer"]
        B -->|"TCP Teardown / Timeout"| D["32 Canonical Features"]
        E["Suricata EVE JSON"] -->|"eve_to_flow_features"| D
        F["Upload Ingest Adapter"] --> D
    end

    subgraph S2 ["2. Pipeline Inference & Routing"]
        direction TB
        D --> NORM["Robust Normalization"]
        NORM --> H["XGBoost (Supervised 4-Class)"]
        NORM --> I["Statistical Baseline (Z-Score)"]
        NORM --> J["Autoencoder (Reconstruction MSE)"]
        H & I & J --> ROUTE{"Canonical Router"}
    end

    subgraph S3 ["3. Cognitive Triage & Formal Safety"]
        direction TB
        ROUTE -->|"known_attack"| ENG["Smart Decision Engine"]
        ENG --> RAG["Defense RAG (ATT&CK / D3FEND)"]
        RAG --> LLM["Advisory LLM (Llama-3-8B)"]
        LLM --> SMT{"Formal Safety Gate<br/>(Invariants I1-I4)"}
    end

    subgraph S4 ["4. Actuation & Governance"]
        direction TB
        SMT -->|"Violated / Self-DoS"| BLK["Blocked (Log Only)"]
        SMT -->|"Admitted"| TPR{"Two-Person Rule<br/>(Disruption > 0.50)"}
        TPR -->|"Approved"| ACT["Actuators: Firewall / Process"]
        ACT --> REC["HMAC-SHA256 Rollback Receipt"]
    end

    ROUTE -->|"anomaly / out_of_scope"| HR["Human Review Queue"]
    ROUTE -->|"benign"| BEN["Quiet Audit Stream"]

    classDef stage fill:#f8fafc,stroke:#3b82f6,stroke-width:1.5px;
    classDef safety fill:#fef2f2,stroke:#ef4444,stroke-width:1.5px;
    classDef success fill:#ecfdf5,stroke:#10b981,stroke-width:1.5px;
    class S1,S2,S3,S4 stage;
    class BLK safety;
    class REC,BEN success;
  </div>

  <h2>Test Fig. 8 (Redesigned Sequence Diagram)</h2>
  <div class="mermaid">
sequenceDiagram
    autonumber
    participant Router as CanonicalRouter
    participant Engine as DecisionEngine
    participant LLM as Llama-3 + Guard
    participant Gate as FormalSafetyVerifier
    participant Actuator as HostFirewall / Process
    participant Admin as Security Analyst (2nd Person)

    Router->>Engine: Alert (route="known_attack", DDoS, conf=0.99)
    Engine->>LLM: Advisory Prompt + DefenseRAG playbooks
    LLM-->>Engine: Proposed Action: block_ip("198.51.100.22")
    Engine->>Gate: verify_and_sign("block_ip", "198.51.100.22")
    Gate->>Gate: Evaluate Invariants I1-I4 (K_crit non-overlap)
    Gate->>Gate: Generate HMAC-SHA256 Rollback Receipt
    Gate-->>Engine: Admitted (Disruption=0.40 <= Bound=0.85)
    alt Disruption > 0.50
        Engine->>Admin: Require Dual Authorization (Two-Person Rule)
        Admin-->>Engine: Approved (approver_id != initiator_id)
    end
    Engine->>Actuator: execute("block_ip", "198.51.100.22")
    Actuator->>Actuator: Insert Netsh / iptables rule
    Actuator-->>Engine: Execution Success + Proof Token
    Note over Engine,Actuator: Later: Analyst triggers atomic rollback
    Admin->>Engine: rollback(token, receipt)
    Engine->>Gate: verify_signature(receipt)
    Gate-->>Engine: Cryptographically Valid
    Engine->>Actuator: revert("block_ip", "198.51.100.22")
    Actuator-->>Admin: Rollback Completed (Firewall Rule Removed)
  </div>

  <script>
    mermaid.initialize({
      startOnLoad: true,
      theme: 'neutral',
      sequence: {
        diagramMarginX: 10,
        diagramMarginY: 10,
        actorMargin: 40,
        width: 140,
        height: 45,
        boxMargin: 10,
        boxTextMargin: 5,
        noteMargin: 10,
        messageMargin: 30,
        useMaxWidth: true
      },
      flowchart: {
        useMaxWidth: true,
        nodeSpacing: 25,
        rankSpacing: 35
      }
    });
  </script>
</body>
</html>`;

fs.writeFileSync('report/scratch/test_diagrams.html', testHtml, 'utf-8');

async function testRender() {
  const browser = await puppeteer.launch({ executablePath: edgeBinaryPath, headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1240, height: 1754 });
  const htmlPath = path.resolve('report/scratch/test_diagrams.html');
  await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), { waitUntil: 'networkidle0' });
  await new Promise(r => setTimeout(r, 2000));

  const dims = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('.mermaid svg')).map((svg, i) => {
      const rect = svg.getBoundingClientRect();
      const vb = svg.getAttribute('viewBox');
      return {
        figure: i === 0 ? 'Fig 5' : 'Fig 8',
        width: Math.round(rect.width),
        height: Math.round(rect.height),
        aspectRatio: (rect.width / (rect.height || 1)).toFixed(2),
        viewBox: vb
      };
    });
  });

  console.table(dims);

  // Take screenshot of both
  const mermaids = await page.$$('.mermaid');
  if (mermaids.length >= 2) {
    await mermaids[0].screenshot({ path: 'report/scratch/test_fig5.png' });
    await mermaids[1].screenshot({ path: 'report/scratch/test_fig8.png' });
    console.log('Saved screenshots test_fig5.png and test_fig8.png');
  }

  await browser.close();
}

testRender().catch(console.error);
