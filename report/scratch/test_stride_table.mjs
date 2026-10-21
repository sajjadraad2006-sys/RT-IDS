import puppeteer from 'puppeteer-core';
import fs from 'fs';
import path from 'path';

async function testTable() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1240, height: 1754 });

  const tableHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          padding: 25mm;
          width: 210mm;
          box-sizing: border-box;
          background: white;
        }
        .table-stride {
          width: 100%;
          margin: 16px 0;
        }
        .table-stride table {
          width: 100% !important;
          table-layout: fixed !important;
          border-collapse: collapse;
          font-size: 7.5pt !important;
          line-height: 1.35 !important;
        }
        .table-stride th, .table-stride td {
          border: 0.5pt solid #cbd5e1;
          padding: 4px 5px !important;
          vertical-align: top;
          word-wrap: break-word !important;
          word-break: break-word !important;
          overflow-wrap: break-word !important;
        }
        .table-stride th {
          background-color: #f1f5f9;
          color: #0f172a;
          font-weight: 600;
          text-align: left;
        }
        .table-stride tr:nth-child(even) td {
          background-color: #f8fafc;
        }
        .table-stride th:nth-child(1), .table-stride td:nth-child(1) { width: 12% !important; }
        .table-stride th:nth-child(2), .table-stride td:nth-child(2) { width: 19% !important; }
        .table-stride th:nth-child(3), .table-stride td:nth-child(3) { width: 14% !important; }
        .table-stride th:nth-child(4), .table-stride td:nth-child(4) { width: 18% !important; }
        .table-stride th:nth-child(5), .table-stride td:nth-child(5) { width: 18% !important; }
        .table-stride th:nth-child(6), .table-stride td:nth-child(6) { width: 19% !important; }
        
        code {
          font-family: "Fira Code", Consolas, monospace;
          font-size: 7pt;
          background: #f1f5f9;
          color: #0369a1;
          padding: 1px 3px;
          border-radius: 2px;
        }
      </style>
    </head>
    <body>
      <div style="text-align: center; margin-bottom: 8px;">
        <b>TABLE XVI.</b> COMPREHENSIVE STRIDE THREAT EVALUATION MATRIX
      </div>
      <div class="table-stride">
        <table>
          <thead>
            <tr>
              <th>STRIDE Category</th>
              <th>Threat Scenario</th>
              <th>Target Subsystem</th>
              <th>Defensive Control</th>
              <th>Residual Risk &amp; Finding</th>
              <th>Hardening Recommendation</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Spoofing</strong></td>
              <td>Adversary spoofs IP source address in UDP/SYN floods</td>
              <td><code>LiveFlowSniffer</code> (<code>live_sniffer.py</code>)</td>
              <td>Ingress reverse path filtering (BCP 38); TCP 3-way handshake verification</td>
              <td>Stateless UDP flows reflect spoofed origin; asymmetric routing causes dropped returns</td>
              <td>Deploy BPF/XDP line filters; correlate flow features with upstream NetFlow / BGP telemetry</td>
            </tr>
            <tr>
              <td><strong>Spoofing</strong></td>
              <td>Attacker injects forged <code>X-Forwarded-For</code> header to bypass rate limits</td>
              <td>REST API Gateway (<code>security.py</code>)</td>
              <td><code>resolve_client_ip()</code> validates peer socket against <code>CG_TRUSTED_PROXIES</code></td>
              <td>Misconfiguration of <code>CG_TRUSTED_PROXIES</code> allows arbitrary IP forgery</td>
              <td>Mandate explicit proxy IP declarations; reject wildcards in trusted CIDR lists</td>
            </tr>
            <tr>
              <td><strong>Tampering</strong></td>
              <td>Local adversary replaces <code>classifier.pkl</code> with weaponized gadget</td>
              <td>Pipeline Model Loader (<code>integrity.py</code>)</td>
              <td>Pre-deserialization SHA-256 manifest check (<code>validate_artifact_bundle</code>)</td>
              <td>Manifest <code>artifacts.json</code> is unsigned; local attacker can recalculate hashes</td>
              <td>Implement asymmetric cryptographic signatures (Ed25519) on artifact manifests</td>
            </tr>
            <tr>
              <td><strong>Tampering</strong></td>
              <td>Malicious network flow modifies SQLite incident state</td>
              <td>Incident Repository (<code>database.py</code>)</td>
              <td>SQLAlchemy ORM parameterized SQL queries</td>
              <td>Unbounded database growth under sustained high-volume flood attacks</td>
              <td>Enforce strict WAL auto-vacuuming and partition rotation policies</td>
            </tr>
            <tr>
              <td><strong>Repudiation</strong></td>
              <td>Operator denies initiating an erroneous containment action</td>
              <td>Actuator Dispatcher (<code>actuators/router.py</code>)</td>
              <td>Two-Person Rule dual IDs; HMAC-SHA256 rollback receipts logged to disk</td>
              <td>Logs reside in local file system; root user can overwrite log files</td>
              <td>Stream audit events to append-only remote syslog / SIEM with cryptographic timestamps</td>
            </tr>
            <tr>
              <td><strong>Information Disclosure</strong></td>
              <td>Model inversion attack extracts proprietary training topology</td>
              <td>Inference Pipeline (<code>pipeline.py</code>)</td>
              <td>Abstract confidence scores; strict error masking on public API</td>
              <td>Model parameter counts and XGBoost tree depths exposed via <code>/api/models/info</code></td>
              <td>Disable diagnostic model inspection endpoints in production deployments</td>
            </tr>
            <tr>
              <td><strong>Information Disclosure</strong></td>
              <td>Advisory LLM prompts leak sensitive internal subnet topology</td>
              <td>LLM Advisory Engine (<code>llm/</code>)</td>
              <td>Prompt sanitization; CIDR regex redaction in context builder</td>
              <td>Outbound prompt context sent to external cloud APIs without end-to-end encryption</td>
              <td>Restrict advisory LLM deployments strictly to local air-gapped instances (Ollama / vLLM)</td>
            </tr>
            <tr>
              <td><strong>Denial of Service</strong></td>
              <td>Flow table exhaustion via high-rate random 5-tuple SYN floods</td>
              <td><code>LiveFlowSniffer</code> (<code>live_sniffer.py</code>)</td>
              <td>Maximum active flow clamping (N_max = 100,000); 5.0 s idle eviction</td>
              <td>Memory allocation spikes to ~500 MB under 100k concurrent micro-flows</td>
              <td>Implement cuckoo hashing / Bloom filter pre-filtering in kernel space via eBPF</td>
            </tr>
            <tr>
              <td><strong>Denial of Service</strong></td>
              <td>Automated containment blocks default gateway or DNS servers</td>
              <td>Containment Engine (<code>formal_verifier.py</code>)</td>
              <td>Invariant <code>I1_CRITICAL_ASSET</code> blocks <code>127.0.0.1</code>, <code>8.8.8.8</code>, <code>0.0.0.0/0</code></td>
              <td>Complex multi-homed routing topologies may contain unlisted critical routers</td>
              <td>Ingest dynamic routing tables from OS kernel into verifier critical asset list</td>
            </tr>
            <tr>
              <td><strong>Elevation of Privilege</strong></td>
              <td>Unauthenticated loopback client executes admin actions</td>
              <td>Authentication Engine (<code>auth.py</code>)</td>
              <td>Strict auth enforced when <code>CG_ENV == "production"</code></td>
              <td>Default developer mode automatically grants <code>Role.ADMIN</code> to loopback clients</td>
              <td>Deprecate loopback auto-elevation entirely; enforce bootstrap credentials universally</td>
            </tr>
            <tr>
              <td><strong>Elevation of Privilege</strong></td>
              <td>PowerShell command injection via crafted containment target</td>
              <td>Firewall Actuator (<code>firewall.py</code>)</td>
              <td><code>SafetyGuardrails.validate_target()</code> enforces strict IP/port regex</td>
              <td>Direct invocation of <code>FirewallActuator.execute()</code> bypasses guardrails</td>
              <td>Replace string-interpolated <code>-Command</code> with direct Win32 Netsh / API bindings</td>
            </tr>
          </tbody>
        </table>
      </div>
    </body>
    </html>
  `;

  await page.setContent(tableHtml);
  const tableEl = await page.$('.table-stride');
  await tableEl.screenshot({ path: 'report/scratch/table_stride_test.png' });
  console.log('Saved table_stride_test.png');
  await browser.close();
}

testTable();
