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
    
    /* Crisp Academic Sequence Diagram Styling */
    .mermaid text.actor > tspan { font-size: 13.5px !important; font-weight: 700 !important; fill: #0f172a !important; }
    .mermaid rect.actor { fill: #f8fafc !important; stroke: #2563eb !important; stroke-width: 1.5px !important; rx: 4px !important; }
    .mermaid text.messageText { font-size: 13px !important; font-weight: 600 !important; fill: #0f172a !important; }
    .mermaid line.messageLine0, .mermaid line.messageLine1 { stroke: #334155 !important; stroke-width: 1.5px !important; }
    .mermaid marker#arrowhead path { fill: #334155 !important; stroke: #334155 !important; }
    .mermaid .note { fill: #fef3c7 !important; stroke: #f59e0b !important; stroke-width: 1px !important; }
    .mermaid text.noteText { font-size: 12.5px !important; font-weight: 600 !important; fill: #92400e !important; }
    .mermaid .alt { fill: #f8fafc !important; stroke: #94a3b8 !important; stroke-dasharray: 4 4 !important; }
    .mermaid text.labelText { font-size: 12.5px !important; font-weight: 700 !important; fill: #b91c1c !important; }
  </style>
</head>
<body>
  <h2>Enhanced Sequence Diagram Fig. 8</h2>
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
    LLM-->>Engine: Proposed: block_ip("198.51.100.22") [IOC match]
    Engine->>Gate: verify_and_sign("block_ip", "198.51.100.22")
    Gate->>Gate: Evaluate Invariants I1-I4 (FOL non-overlap)
    Gate->>Gate: Generate HMAC-SHA256 Rollback Receipt
    Gate-->>Engine: Admitted (Disruption = 0.40 &le; Bound = 0.85)
    alt Disruption &gt; 0.50
        Engine->>Admin: Require Dual Authorization (Two-Person Rule)
        Admin-->>Engine: Approved (approver_id &ne; initiator_id)
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
        actorMargin: 35,
        width: 140,
        height: 44,
        boxMargin: 8,
        boxTextMargin: 4,
        noteMargin: 8,
        messageMargin: 30,
        useMaxWidth: true
      }
    });
  </script>
</body>
</html>`;

fs.writeFileSync('report/scratch/test_fig8_enhanced.html', testHtml, 'utf-8');

async function capture() {
  const browser = await puppeteer.launch({ executablePath: edgeBinaryPath, headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1240, height: 1200 });
  const htmlPath = path.resolve('report/scratch/test_fig8_enhanced.html');
  await page.goto('file:///' + htmlPath.replace(/\\/g, '/'), { waitUntil: 'networkidle0' });
  await new Promise(r => setTimeout(r, 2000));
  const el = await page.$('.mermaid');
  if (el) {
    await el.screenshot({ path: 'report/scratch/test_fig8_enhanced.png' });
    console.log('Saved test_fig8_enhanced.png');
  }
  await browser.close();
}
capture().catch(console.error);
