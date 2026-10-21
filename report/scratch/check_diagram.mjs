import mermaid from 'mermaid';
mermaid.initialize({ startOnLoad: false });

async function test(name, code) {
  try {
    await mermaid.parse(code.trim());
    console.log(`[PASS] ${name}`);
  } catch (err) {
    console.log(`[FAIL] ${name}:`, err.message || err);
  }
}

// Test Fig 11
const fig11 = `
flowchart TD
    subgraph S1 ["1. Network Sensor & Log Stream"]
        direction LR
        SURI["Suricata 7.x Engine<br/>Raw Packet Sniffing / NIDS"] -->|Append Alert Records| EVE["Live EVE Log Stream<br/>/var/log/suricata/eve.json"]
        EVE -->|Inotify / ReadLine Tail| TAIL["SuricataLiveTailer<br/>backend/suricata/tailer.py"]
    end

    subgraph S2 ["2. Synthesis & Ingestion Pipeline"]
        direction LR
        MAP["Feature Synthesis<br/>eve_to_flow_features()"] -->|32-Feature Vector [CE-40]| PIPE["Pipeline v2 Engine<br/>RandomForest / LightGBM"]
        PIPE -->|Persist Alert Record| DB["SQLite WAL Storage<br/>cyberguard.db [CE-05]"]
    end

    TAIL ==>|Parse Alert JSON Record| MAP

    classDef stage fill:#f8fafc,stroke:#0284c7,stroke-width:1.5px;
    classDef nodeStyle fill:#ffffff,stroke:#334155,stroke-width:1.2px;
    class S1,S2 stage;
    class SURI,EVE,TAIL,MAP,PIPE,DB nodeStyle;
`;

await test('Fig 11', fig11);
