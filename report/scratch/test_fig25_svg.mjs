import puppeteer from 'puppeteer-core';

const fig25Svg = `<div id="fig25-container" style="width: 100%; max-width: 760px; margin: 16px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<svg viewBox="0 0 760 450" width="100%" height="auto" xmlns="http://www.w3.org/2000/svg" style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
  <defs>
    <linearGradient id="headerGrad25" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#0369a1" />
    </linearGradient>
    <marker id="arr25Blue" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#0284c7" />
    </marker>
    <marker id="arr25Green" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#16a34a" />
    </marker>
    <marker id="arr25Red" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#dc2626" />
    </marker>
    <marker id="arr25Purple" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#7c3aed" />
    </marker>
  </defs>

  <!-- Banner Header -->
  <rect x="0" y="0" width="760" height="34" rx="8" fill="url(#headerGrad25)" />
  <rect x="0" y="24" width="760" height="10" fill="url(#headerGrad25)" />
  <text x="380" y="22" text-anchor="middle" font-size="11.5" font-weight="700" fill="#ffffff" letter-spacing="0.5">
    PROPOSED REAL-TIME MECHATRONIC IDS (RT-M-IDS) ARCHITECTURE [PROPOSED CONCEPT - NOT IMPLEMENTED]
  </text>

  <!-- Zone Left: Physical Cell (Level 0 / 1) -->
  <rect x="15" y="46" width="250" height="390" rx="6" fill="#f8fafc" stroke="#64748b" stroke-width="1.2" />
  <rect x="25" y="54" width="230" height="20" rx="3" fill="#e2e8f0" />
  <text x="140" y="68" text-anchor="middle" font-size="10" font-weight="700" fill="#1e293b">MECHATRONIC CELL (LEVEL 0 / 1)</text>

  <!-- Node A1: Robot Arm -->
  <g transform="translate(30, 84)">
    <rect width="220" height="56" rx="4" fill="#ffffff" stroke="#475569" stroke-width="1.2" />
    <text x="110" y="20" text-anchor="middle" font-size="10.5" font-weight="700" fill="#0f172a">6-DOF Articulated Robot</text>
    <text x="110" y="34" text-anchor="middle" font-size="8.5" fill="#475569">Joint positions, TCP velocity, torque</text>
    <text x="110" y="46" text-anchor="middle" font-size="7.5" fill="#0284c7">ISO 10218-1 Industrial Robot</text>
  </g>

  <!-- Bidirectional arrow A1 <-> A2 -->
  <path d="M140, 140 L140, 160" stroke="#64748b" stroke-width="1.5" stroke-dasharray="2,2" />

  <!-- Node A2: Servo Drives -->
  <g transform="translate(30, 162)">
    <rect width="220" height="52" rx="4" fill="#ffffff" stroke="#475569" stroke-width="1.2" />
    <text x="110" y="18" text-anchor="middle" font-size="10" font-weight="700" fill="#0f172a">Servo Drives &amp; Inverters</text>
    <text x="110" y="32" text-anchor="middle" font-size="8.5" fill="#475569">PWM inverter, resolver feedback</text>
    <text x="110" y="44" text-anchor="middle" font-size="7.5" fill="#64748b">Fieldbus: EtherCAT / PROFINET IRT</text>
  </g>

  <!-- Bidirectional arrow A2 <-> A3 -->
  <path d="M140, 214 L140, 234" stroke="#64748b" stroke-width="1.5" stroke-dasharray="2,2" />

  <!-- Node A3: Safety PLC -->
  <g transform="translate(30, 236)">
    <rect width="220" height="56" rx="4" fill="#fef2f2" stroke="#dc2626" stroke-width="1.5" />
    <text x="110" y="18" text-anchor="middle" font-size="10" font-weight="700" fill="#991b1b">Safety PLC (ISO 13849 PLe)</text>
    <text x="110" y="32" text-anchor="middle" font-size="8.5" font-weight="600" fill="#b91c1c">Dual-Channel SIL 3 Safety Logic</text>
    <text x="110" y="46" text-anchor="middle" font-size="7.5" fill="#475569">FSoE / PROFIsafe Interlock</text>
  </g>

  <!-- Bidirectional arrow A3 <-> A4 -->
  <path d="M140, 292 L140, 312" stroke="#64748b" stroke-width="1.5" stroke-dasharray="2,2" />

  <!-- Node A4: Managed Switch -->
  <g transform="translate(30, 314)">
    <rect width="220" height="56" rx="4" fill="#ffffff" stroke="#0284c7" stroke-width="1.5" />
    <text x="110" y="18" text-anchor="middle" font-size="10" font-weight="700" fill="#0369a1">Industrial Managed Switch</text>
    <text x="110" y="32" text-anchor="middle" font-size="8.5" fill="#475569">TAP / Mirror Port (Promiscuous)</text>
    <text x="110" y="46" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#0284c7">Modbus TCP :502 | OPC UA :4840</text>
  </g>

  <!-- Zone Right: Proposed RT-M-IDS Appliance -->
  <rect x="280" y="46" width="465" height="390" rx="6" fill="#f0fdf4" stroke="#16a34a" stroke-width="1.2" />
  <rect x="290" y="54" width="445" height="20" rx="3" fill="#dcfce7" />
  <text x="512" y="68" text-anchor="middle" font-size="10" font-weight="700" fill="#14532d">PROPOSED RT-M-IDS EDGE APPLIANCE [NOT IMPLEMENTED]</text>

  <!-- Sub-block 1: OT Protocol Ingestion -->
  <rect x="292" y="80" width="441" height="74" rx="5" fill="#ffffff" stroke="#86efac" stroke-width="1" />
  <text x="302" y="94" font-size="9" font-weight="700" fill="#15803d">1. ZERO-LATENCY OT INGESTION LAYER</text>

  <!-- TAP Box -->
  <g transform="translate(302, 100)">
    <rect width="130" height="46" rx="3" fill="#f5f3ff" stroke="#7c3aed" stroke-width="1.2" />
    <text x="65" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#6d28d9">Passive Optical TAP</text>
    <text x="65" y="28" text-anchor="middle" font-size="7.5" fill="#7c3aed">Listen-only mode</text>
    <text x="65" y="38" text-anchor="middle" font-size="7" font-weight="600" fill="#dc2626">TX Fiber physically cut</text>
  </g>

  <!-- Modbus Parser Box -->
  <g transform="translate(446, 100)">
    <rect width="135" height="46" rx="3" fill="#f8fafc" stroke="#64748b" stroke-width="1" />
    <text x="67" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#0f172a">Modbus TCP Parser</text>
    <text x="67" y="28" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#0284c7">Port 502 MBAP Parser</text>
    <text x="67" y="38" text-anchor="middle" font-size="7" fill="#475569">Func 0x03, 0x05, 0x10</text>
  </g>

  <!-- OPC UA Parser Box -->
  <g transform="translate(592, 100)">
    <rect width="131" height="46" rx="3" fill="#f8fafc" stroke="#64748b" stroke-width="1" />
    <text x="65" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#0f172a">OPC UA Binary Parser</text>
    <text x="65" y="28" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#0284c7">Port 4840 opc.tcp://</text>
    <text x="65" y="38" text-anchor="middle" font-size="7" fill="#475569">WriteRequest monitoring</text>
  </g>

  <path d="M432, 123 L444, 123" stroke="#7c3aed" stroke-width="1.5" marker-end="url(#arr25Purple)" />
  <path d="M581, 123 L590, 123" stroke="#64748b" stroke-width="1" />

  <!-- Sub-block 2: Detection Engines -->
  <rect x="292" y="162" width="441" height="110" rx="5" fill="#ffffff" stroke="#86efac" stroke-width="1" />
  <text x="302" y="176" font-size="9" font-weight="700" fill="#15803d">2. DUAL-STAGE CYBER-PHYSICAL DETECTION ENGINES</text>

  <!-- Engine 1 -->
  <g transform="translate(302, 182)">
    <rect width="135" height="80" rx="3" fill="#eff6ff" stroke="#3b82f6" stroke-width="1.2" />
    <text x="67" y="18" text-anchor="middle" font-size="9" font-weight="700" fill="#1e3a8a">Deterministic Timing</text>
    <text x="67" y="32" text-anchor="middle" font-size="8" fill="#1e40af">Cyclical Jitter Detector</text>
    <line x1="10" y1="40" x2="125" y2="40" stroke="#bfdbfe" stroke-width="1" />
    <text x="67" y="52" text-anchor="middle" font-size="7.5" fill="#475569">Period: T_cycle = 4.0 ms</text>
    <text x="67" y="64" text-anchor="middle" font-size="7.5" fill="#475569">Detects timing drift / injection</text>
    <text x="67" y="74" text-anchor="middle" font-size="7" font-weight="600" fill="#dc2626">Delta-t &gt; 2.5 sigma alert</text>
  </g>

  <!-- Engine 2 -->
  <g transform="translate(446, 182)">
    <rect width="135" height="80" rx="3" fill="#eff6ff" stroke="#3b82f6" stroke-width="1.2" />
    <text x="67" y="18" text-anchor="middle" font-size="9" font-weight="700" fill="#1e3a8a">State-Space AE</text>
    <text x="67" y="32" text-anchor="middle" font-size="8" fill="#1e40af">Kinematic Model</text>
    <line x1="10" y1="40" x2="125" y2="40" stroke="#bfdbfe" stroke-width="1" />
    <text x="67" y="52" text-anchor="middle" font-size="7.5" fill="#475569">Joint torque &amp; velocity</text>
    <text x="67" y="64" text-anchor="middle" font-size="7.5" fill="#475569">Newton-Euler dynamics</text>
    <text x="67" y="74" text-anchor="middle" font-size="7" font-weight="600" fill="#dc2626">Physics anomaly cutoff</text>
  </g>

  <!-- Engine 3 -->
  <g transform="translate(592, 182)">
    <rect width="131" height="80" rx="3" fill="#eff6ff" stroke="#3b82f6" stroke-width="1.2" />
    <text x="65" y="18" text-anchor="middle" font-size="9" font-weight="700" fill="#1e3a8a">IEC 62443 Whitelist</text>
    <text x="65" y="32" text-anchor="middle" font-size="8" fill="#1e40af">Protocol Conformance</text>
    <line x1="10" y1="40" x2="121" y2="40" stroke="#bfdbfe" stroke-width="1" />
    <text x="65" y="52" text-anchor="middle" font-size="7.5" fill="#475569">Permitted function codes</text>
    <text x="65" y="64" text-anchor="middle" font-size="7.5" fill="#475569">Allowed register ranges</text>
    <text x="65" y="74" text-anchor="middle" font-size="7" font-weight="600" fill="#dc2626">Rejects unauthorized writes</text>
  </g>

  <!-- Sub-block 3: Containment Gate -->
  <rect x="292" y="280" width="441" height="146" rx="5" fill="#fef2f2" stroke="#fca5a5" stroke-width="1" />
  <text x="302" y="296" font-size="9" font-weight="700" fill="#991b1b">3. FUNCTIONAL SAFETY CONTAINMENT INTERLOCK (IEC 60204-1)</text>

  <!-- Functional Safety Gate -->
  <g transform="translate(302, 304)">
    <rect width="200" height="112" rx="4" fill="#ffffff" stroke="#ef4444" stroke-width="1.5" />
    <text x="100" y="20" text-anchor="middle" font-size="10" font-weight="700" fill="#991b1b">Functional Safety Gate</text>
    <text x="100" y="34" text-anchor="middle" font-size="8.5" fill="#b91c1c">IEC 60204-1 Safe Motion Interlock</text>
    <line x1="10" y1="42" x2="190" y2="42" stroke="#fecaca" stroke-width="1" />
    <text x="12" y="56" font-size="8" font-weight="600" fill="#7f1d1d">• Prohibits Instant IT Drop:</text>
    <text x="18" y="68" font-size="7.5" fill="#475569">No abrupt kill during high-speed move</text>
    <text x="12" y="84" font-size="8" font-weight="600" fill="#7f1d1d">• Interlock Dispatch:</text>
    <text x="18" y="96" font-size="7.5" fill="#15803d">Dispatches Category 1 controlled stop</text>
  </g>

  <!-- Actions -->
  <g transform="translate(515, 304)">
    <!-- Cat 1/2 Stop -->
    <rect width="208" height="52" rx="3" fill="#ffffff" stroke="#dc2626" stroke-width="1.2" />
    <text x="104" y="18" text-anchor="middle" font-size="9.5" font-weight="700" fill="#991b1b">Controlled Category 1/2 Stop</text>
    <text x="104" y="32" text-anchor="middle" font-size="8" fill="#475569">Maintains drive power to decelerate</text>
    <text x="104" y="44" text-anchor="middle" font-size="7.5" fill="#dc2626">Zero kinetic crash on robot tooling</text>

    <!-- Perimeter FW -->
    <rect y="60" width="208" height="52" rx="3" fill="#ffffff" stroke="#0284c7" stroke-width="1.2" />
    <text x="104" y="78" text-anchor="middle" font-size="9.5" font-weight="700" fill="#0369a1">OT Perimeter Isolation</text>
    <text x="104" y="92" text-anchor="middle" font-size="8" fill="#475569">Isolates IT/OT boundary firewall</text>
    <text x="104" y="104" text-anchor="middle" font-size="7.5" fill="#15803d">Fieldbus communication intact</text>
  </g>

  <!-- Connection: Managed Switch -> TAP (Purple dashed) -->
  <path d="M250, 342 L270, 342 L270, 123 L300, 123" fill="none" stroke="#7c3aed" stroke-width="2" stroke-dasharray="4,3" marker-end="url(#arr25Purple)" />
  <rect x="252" y="215" width="36" height="30" rx="3" fill="#ffffff" stroke="#7c3aed" stroke-width="1" />
  <text x="270" y="228" text-anchor="middle" font-size="7" font-weight="700" fill="#7c3aed">Optical</text>
  <text x="270" y="238" text-anchor="middle" font-size="7" font-weight="700" fill="#7c3aed">SPAN</text>

  <!-- Connection: Safety Gate -> Safety PLC (Red feedback) -->
  <path d="M302, 360 L280, 360 L280, 264 L252, 264" fill="none" stroke="#dc2626" stroke-width="2" marker-end="url(#arr25Red)" />
  <rect x="254" y="285" width="46" height="28" rx="3" fill="#ffffff" stroke="#dc2626" stroke-width="1" />
  <text x="277" y="297" text-anchor="middle" font-size="7" font-weight="700" fill="#b91c1c">FSoE / Dry</text>
  <text x="277" y="307" text-anchor="middle" font-size="7" font-weight="700" fill="#b91c1c">Contact</text>
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
  ${fig25Svg}
</body>
</html>`;

const browser = await puppeteer.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: 'new'
});
const page = await browser.newPage();
await page.setContent(html, { waitUntil: 'networkidle0' });
await (await page.$('#fig25-container')).screenshot({ path: 'report/scratch/test_fig25_svg.png' });
await browser.close();
console.log('Saved test_fig25_svg.png successfully.');
