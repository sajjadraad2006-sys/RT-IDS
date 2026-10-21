import html

svg = '''<div id="fig5-container" style="text-align: center; margin: 24px auto; width: 100%; max-width: 760px;">
  <svg viewBox="0 0 760 440" width="100%" height="auto" xmlns="http://www.w3.org/2000/svg" style="background:#ffffff; border:1px solid #cbd5e1; border-radius:8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
    <defs>
      <linearGradient id="gHeader" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#0f172a" />
        <stop offset="100%" stop-color="#1e293b" />
      </linearGradient>
      <linearGradient id="gCol1" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#f8fafc" />
        <stop offset="100%" stop-color="#f1f5f9" />
      </linearGradient>
      <linearGradient id="gCol2" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#eff6ff" />
        <stop offset="100%" stop-color="#dbeafe" />
      </linearGradient>
      <linearGradient id="gCol3" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#f5f3ff" />
        <stop offset="100%" stop-color="#ede9fe" />
      </linearGradient>
      <linearGradient id="gCol4" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#f0fdf4" />
        <stop offset="100%" stop-color="#dcfce7" />
      </linearGradient>
      <marker id="arr" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#475569" />
      </marker>
      <marker id="arrBlue" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#2563eb" />
      </marker>
      <marker id="arrRed" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#dc2626" />
      </marker>
    </defs>

    <!-- Title Bar -->
    <rect x="0" y="0" width="760" height="34" rx="8" fill="url(#gHeader)" />
    <rect x="0" y="24" width="760" height="10" fill="url(#gHeader)" />
    <text x="380" y="22" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle" letter-spacing="0.5">CYBERGUARD END-TO-END PIPELINE: TELEMETRY &rarr; INFERENCE &rarr; TRIAGE &rarr; ACTUATION</text>

    <!-- 4 Swimlane Columns -->
    <!-- Lane 1: Ingestion -->
    <g transform="translate(12, 44)">
      <rect width="172" height="382" rx="6" fill="url(#gCol1)" stroke="#cbd5e1" stroke-width="1" />
      <rect width="172" height="24" rx="6" fill="#e2e8f0" stroke="#cbd5e1" stroke-width="1" />
      <text x="86" y="16" font-size="10" font-weight="700" fill="#1e293b" text-anchor="middle">1. TELEMETRY INGESTION</text>

      <!-- Box: Live Sniffer -->
      <g transform="translate(8, 32)">
        <rect width="156" height="52" rx="4" fill="#ffffff" stroke="#94a3b8" stroke-width="1" />
        <text x="8" y="16" font-size="9.5" font-weight="700" fill="#0f172a">LiveFlowSniffer [CE-04]</text>
        <text x="8" y="29" font-size="8" fill="#475569">AF_PACKET raw socket</text>
        <text x="8" y="42" font-size="8" fill="#64748b">Stateful 5-tuple TCP/UDP tracking</text>
      </g>

      <!-- Box: Suricata -->
      <g transform="translate(8, 92)">
        <rect width="156" height="42" rx="4" fill="#ffffff" stroke="#94a3b8" stroke-width="1" />
        <text x="8" y="16" font-size="9.5" font-weight="700" fill="#0f172a">Suricata Tailer [CE-06]</text>
        <text x="8" y="29" font-size="8" fill="#475569">eve.json log stream adapter</text>
      </g>

      <!-- Box: Upload Ingest -->
      <g transform="translate(8, 142)">
        <rect width="156" height="42" rx="4" fill="#ffffff" stroke="#94a3b8" stroke-width="1" />
        <text x="8" y="16" font-size="9.5" font-weight="700" fill="#0f172a">Universal Ingest [CE-20]</text>
        <text x="8" y="29" font-size="8" fill="#475569">PCAP / CSV / Zeek / NDJSON</text>
      </g>

      <!-- Connector Lines into Feature Vector -->
      <line x1="86" y1="84" x2="86" y2="200" stroke="#64748b" stroke-width="1.5" />
      <line x1="86" y1="134" x2="86" y2="200" stroke="#64748b" stroke-width="1.5" />
      <line x1="86" y1="184" x2="86" y2="200" stroke="#64748b" stroke-width="1.5" marker-end="url(#arr)" />

      <!-- Box: 32 Features -->
      <g transform="translate(8, 202)">
        <rect width="156" height="58" rx="4" fill="#f1f5f9" stroke="#3b82f6" stroke-width="1.5" />
        <text x="78" y="18" font-size="9.5" font-weight="700" fill="#1e40af" text-anchor="middle">Canonical 32-Feature Vector</text>
        <text x="78" y="32" font-size="8" fill="#1e293b" text-anchor="middle">Durations, Packet Rates, Flag Counts,</text>
        <text x="78" y="46" font-size="8" fill="#1e293b" text-anchor="middle">Byte Volumes, IAT Means &amp; Stds</text>
      </g>

      <!-- Backpressure Queue -->
      <g transform="translate(8, 276)">
        <rect width="156" height="46" rx="4" fill="#ffffff" stroke="#94a3b8" stroke-width="1" stroke-dasharray="3 3" />
        <text x="8" y="16" font-size="9" font-weight="700" fill="#0f172a">Bounded Queue [CE-22]</text>
        <text x="8" y="30" font-size="8" fill="#475569">FIFO Capacity N = 10,000</text>
        <text x="8" y="41" font-size="7.5" fill="#64748b">Drops oldest on saturation</text>
      </g>

      <!-- Batch Dispatcher -->
      <g transform="translate(8, 332)">
        <rect width="156" height="38" rx="4" fill="#e2e8f0" stroke="#64748b" stroke-width="1" />
        <text x="78" y="16" font-size="9" font-weight="600" fill="#1e293b" text-anchor="middle">Batch Worker (B = 50)</text>
        <text x="78" y="28" font-size="7.5" fill="#475569" text-anchor="middle">Micro-batched pipeline feed</text>
      </g>
    </g>

    <!-- Arrow Lane 1 -> Lane 2 -->
    <line x1="184" y1="275" x2="198" y2="275" stroke="#2563eb" stroke-width="2" marker-end="url(#arrBlue)" />

    <!-- Lane 2: Pipeline Inference & Routing -->
    <g transform="translate(198, 44)">
      <rect width="180" height="382" rx="6" fill="url(#gCol2)" stroke="#bfdbfe" stroke-width="1" />
      <rect width="180" height="24" rx="6" fill="#dbeafe" stroke="#bfdbfe" stroke-width="1" />
      <text x="90" y="16" font-size="10" font-weight="700" fill="#1e40af" text-anchor="middle">2. INFERENCE &amp; ROUTING</text>

      <!-- Box: Normalization -->
      <g transform="translate(10, 32)">
        <rect width="160" height="40" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1" />
        <text x="8" y="16" font-size="9.5" font-weight="700" fill="#1e3a8a">Robust Normalizer [CE-03]</text>
        <text x="8" y="29" font-size="8" fill="#2563eb">log1p + RobustScaler (IQR)</text>
      </g>

      <!-- 3 Models Stack -->
      <g transform="translate(10, 80)">
        <!-- XGBoost -->
        <rect width="160" height="38" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1" />
        <text x="8" y="15" font-size="9" font-weight="700" fill="#0f172a">XGBoost Classifier [CE-08]</text>
        <text x="8" y="28" font-size="7.5" fill="#475569">4-Class: Benign, Bot, DDoS, PortScan</text>
      </g>

      <g transform="translate(10, 124)">
        <!-- Statistical -->
        <rect width="160" height="38" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1" />
        <text x="8" y="15" font-size="9" font-weight="700" fill="#0f172a">Statistical Filter [CE-09]</text>
        <text x="8" y="28" font-size="7.5" fill="#475569">Welford Streaming Z-Score (z &gt; 3.0)</text>
      </g>

      <g transform="translate(10, 168)">
        <!-- Autoencoder -->
        <rect width="160" height="38" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1" />
        <text x="8" y="15" font-size="9" font-weight="700" fill="#0f172a">PyTorch Autoencoder [CE-10]</text>
        <text x="8" y="28" font-size="7.5" fill="#475569">32&rarr;16&rarr;8&rarr;16&rarr;32 MSE Loss vs &tau;</text>
      </g>

      <!-- Multi-Signal Router -->
      <g transform="translate(10, 220)">
        <polygon points="80,0 160,25 80,50 0,25" fill="#ffffff" stroke="#1d4ed8" stroke-width="1.5" />
        <text x="80" y="22" font-size="9" font-weight="700" fill="#1e40af" text-anchor="middle">Canonical Router</text>
        <text x="80" y="34" font-size="7.5" fill="#2563eb" text-anchor="middle">[CE-11] Precedence Table</text>
      </g>

      <!-- Route Outputs -->
      <g transform="translate(10, 282)">
        <rect width="160" height="26" rx="4" fill="#fee2e2" stroke="#f87171" stroke-width="1" />
        <text x="8" y="17" font-size="8.5" font-weight="700" fill="#b91c1c">Route: known_attack &rarr;</text>
      </g>
      <g transform="translate(10, 314)">
        <rect width="160" height="26" rx="4" fill="#fef3c7" stroke="#fcd34d" stroke-width="1" />
        <text x="8" y="17" font-size="8.5" font-weight="700" fill="#b45309">Route: human_review [OOD]</text>
      </g>
      <g transform="translate(10, 346)">
        <rect width="160" height="26" rx="4" fill="#ecfdf5" stroke="#6ee7b7" stroke-width="1" />
        <text x="8" y="17" font-size="8.5" font-weight="700" fill="#047857">Route: benign [Safe Log]</text>
      </g>
    </g>

    <!-- Arrow Lane 2 -> Lane 3 -->
    <line x1="378" y1="295" x2="394" y2="295" stroke="#dc2626" stroke-width="2" marker-end="url(#arrRed)" />

    <!-- Lane 3: Cognitive Triage & Verification -->
    <g transform="translate(394, 44)">
      <rect width="176" height="382" rx="6" fill="url(#gCol3)" stroke="#ddd6fe" stroke-width="1" />
      <rect width="176" height="24" rx="6" fill="#ede9fe" stroke="#ddd6fe" stroke-width="1" />
      <text x="88" y="16" font-size="10" font-weight="700" fill="#6d28d9" text-anchor="middle">3. COGNITIVE &amp; FORMAL SAFETY</text>

      <!-- Decision Engine -->
      <g transform="translate(10, 32)">
        <rect width="156" height="42" rx="4" fill="#ffffff" stroke="#c4b5fd" stroke-width="1" />
        <text x="8" y="16" font-size="9.5" font-weight="700" fill="#4c1d95">Decision Engine [CE-14]</text>
        <text x="8" y="29" font-size="8" fill="#6d28d9">Threshold scoring &amp; triage policy</text>
      </g>

      <!-- Defense RAG -->
      <g transform="translate(10, 82)">
        <rect width="156" height="42" rx="4" fill="#ffffff" stroke="#c4b5fd" stroke-width="1" />
        <text x="8" y="16" font-size="9.5" font-weight="700" fill="#4c1d95">Defense RAG [CE-26]</text>
        <text x="8" y="29" font-size="8" fill="#6d28d9">MITRE ATT&amp;CK &amp; D3FEND embed</text>
      </g>

      <!-- Advisory LLM -->
      <g transform="translate(10, 132)">
        <rect width="156" height="46" rx="4" fill="#ffffff" stroke="#c4b5fd" stroke-width="1" />
        <text x="8" y="16" font-size="9.5" font-weight="700" fill="#4c1d95">Advisory LLM [CE-27]</text>
        <text x="8" y="29" font-size="8" fill="#6d28d9">Llama-3-8B-Q4 local GPU</text>
        <text x="8" y="40" font-size="7.5" fill="#7c3aed">Generates containment JSON</text>
      </g>

      <!-- Contradiction Guard -->
      <g transform="translate(10, 186)">
        <rect width="156" height="46" rx="4" fill="#ffffff" stroke="#f43f5e" stroke-width="1.5" />
        <text x="8" y="16" font-size="9" font-weight="700" fill="#be123c">Contradiction Guard [CE-21]</text>
        <text x="8" y="29" font-size="7.5" fill="#9f1239">Suppresses hallucinated benigns</text>
        <text x="8" y="40" font-size="7.5" fill="#e11d48">Overrules LLM on high severity</text>
      </g>

      <!-- Formal Verifier Gate -->
      <g transform="translate(10, 244)">
        <rect width="156" height="66" rx="4" fill="#ffffff" stroke="#6d28d9" stroke-width="1.5" />
        <text x="8" y="16" font-size="9.5" font-weight="700" fill="#4c1d95">Formal Safety Gate [CE-18]</text>
        <text x="8" y="29" font-size="8" fill="#1e293b">SymPy FOL Invariants I1 &ndash; I4:</text>
        <text x="8" y="42" font-size="7.5" fill="#581c87">&not;(quarantine &and; unverified &and; &not;override)</text>
        <text x="8" y="55" font-size="7.5" fill="#581c87">(quarantine &and; &not;high_risk) &rArr; override</text>
      </g>

      <!-- Blocked Indicator -->
      <g transform="translate(10, 324)">
        <rect width="156" height="38" rx="4" fill="#fee2e2" stroke="#dc2626" stroke-width="1" />
        <text x="78" y="16" font-size="8.5" font-weight="700" fill="#b91c1c" text-anchor="middle">Violation / Self-DoS Intercept</text>
        <text x="78" y="28" font-size="7.5" fill="#991b1b" text-anchor="middle">Action Aborted &amp; Alert Persisted</text>
      </g>
    </g>

    <!-- Arrow Lane 3 -> Lane 4 -->
    <line x1="570" y1="277" x2="586" y2="277" stroke="#16a34a" stroke-width="2" marker-end="url(#arr)" />

    <!-- Lane 4: Actuation & Governance -->
    <g transform="translate(586, 44)">
      <rect width="162" height="382" rx="6" fill="url(#gCol4)" stroke="#bbf7d0" stroke-width="1" />
      <rect width="162" height="24" rx="6" fill="#dcfce7" stroke="#bbf7d0" stroke-width="1" />
      <text x="81" y="16" font-size="10" font-weight="700" fill="#15803d" text-anchor="middle">4. ACTUATION &amp; AUDIT</text>

      <!-- Two-Person Rule Gate -->
      <g transform="translate(8, 32)">
        <rect width="146" height="58" rx="4" fill="#ffffff" stroke="#22c55e" stroke-width="1.5" />
        <text x="8" y="16" font-size="9" font-weight="700" fill="#14532d">Two-Person Rule [CE-48]</text>
        <text x="8" y="29" font-size="7.5" fill="#166534">Disruption Score &gt; 0.50</text>
        <text x="8" y="41" font-size="7.5" fill="#15803d">Mandates Operator Sign-off:</text>
        <text x="8" y="52" font-size="7.5" fill="#14532d">approver_id &ne; initiator_id</text>
      </g>

      <!-- Actuator Base Router -->
      <g transform="translate(8, 100)">
        <rect width="146" height="42" rx="4" fill="#ffffff" stroke="#86efac" stroke-width="1" />
        <text x="8" y="16" font-size="9" font-weight="700" fill="#0f172a">Actuator Router [CE-09]</text>
        <text x="8" y="29" font-size="7.5" fill="#166534">Dispatches to targets</text>
      </g>

      <!-- Concrete Actuators -->
      <g transform="translate(8, 150)">
        <rect width="146" height="36" rx="4" fill="#ffffff" stroke="#86efac" stroke-width="1" />
        <text x="8" y="15" font-size="8.5" font-weight="600" fill="#1e293b">Host Firewall Actuator</text>
        <text x="8" y="27" font-size="7.5" fill="#475569">Netsh (Win) / iptables (Linux)</text>
      </g>

      <g transform="translate(8, 192)">
        <rect width="146" height="36" rx="4" fill="#ffffff" stroke="#86efac" stroke-width="1" />
        <text x="8" y="15" font-size="8.5" font-weight="600" fill="#1e293b">Process Actuator [CE-15]</text>
        <text x="8" y="27" font-size="7.5" fill="#475569">SIGSTOP suspension / taskkill</text>
      </g>

      <!-- Cryptographic Rollback -->
      <g transform="translate(8, 236)">
        <rect width="146" height="54" rx="4" fill="#ecfdf5" stroke="#16a34a" stroke-width="1.5" />
        <text x="73" y="16" font-size="9" font-weight="700" fill="#15803d" text-anchor="middle">Rollback Receipt [CE-49]</text>
        <text x="73" y="29" font-size="7.5" fill="#166534" text-anchor="middle">HMAC-SHA256 Token</text>
        <text x="73" y="42" font-size="7.5" fill="#14532d" text-anchor="middle">Cryptographic Undo State</text>
      </g>

      <!-- Audit Ledger -->
      <g transform="translate(8, 302)">
        <rect width="146" height="54" rx="4" fill="#ffffff" stroke="#86efac" stroke-width="1" />
        <text x="73" y="16" font-size="9" font-weight="700" fill="#0f172a" text-anchor="middle">Immutable Audit Ledger</text>
        <text x="73" y="29" font-size="7.5" fill="#475569" text-anchor="middle">[CE-54] SHA-256 Hash Chain</text>
        <text x="73" y="42" font-size="7.5" fill="#166534" text-anchor="middle">Forward-Secure State</text>
      </g>
    </g>
  </svg>
</div>'''

with open('report/scratch/test_fig5_svg.html', 'w', encoding='utf-8') as f:
    f.write(f'''<!DOCTYPE html><html><head><meta charset="utf-8"></head><body style="background:#f8fafc; padding:20px;">{svg}</body></html>''')

print("Wrote test_fig5_svg.html")
