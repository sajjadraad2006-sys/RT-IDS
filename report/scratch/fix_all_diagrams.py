import re

# 1. Fix 01-introduction.md (Fig. 1)
with open('report/chapters/01-introduction.md', 'r', encoding='utf-8') as f:
    c1 = f.read()

old_fig1 = re.search(r'```mermaid\s*graph LR[\s\S]*?```', c1).group(0)
new_fig1 = '''```mermaid
flowchart TD
    subgraph Sub_Net ["1. Enterprise Network Ingestion"]
        P["Network Packets (Raw NIC)"] --> S["Raw Sniffer Bridge (AF_PACKET / Raw)"]
        L["Suricata EVE JSON Logs"] --> S
    end
    
    subgraph Sub_Core ["2. CyberGuard RT-IDS Core Pipeline"]
        S --> F["32-Feature Flow Assembler (FlowRecord)"]
        F --> P2["Pipeline v2 Evidence Fusion"]
        P2 --> CLF["XGBoost Known-Attack Classifier"]
        P2 --> STAT["Statistical Z-Score Baseline"]
        P2 --> AE["Deep Autoencoder Anomaly Detector"]
        CLF --> R["Canonical Routing Matrix"]
        STAT --> R
        AE --> R
        R -->|High Confidence Alert| DEC["Decision Engine & Advisory LLM"]
        R -->|Ambiguous Anomaly| HR["Human-in-the-Loop SOC Review"]
        DEC -->|Proposed Containment| SG["Formal Safety Invariant Gate"]
    end
    
    subgraph Sub_Act ["3. Autonomous Containment & Enforcement"]
        SG -->|Safety Certified| ACT["Dual-Authorization Actuator Engine"]
        ACT --> FW["Host Firewall Actuator (Netsh / iptables)"]
        ACT --> PK["Process Isolation Actuator (SIGSTOP / taskkill)"]
        ACT --> SIG["Suricata Drop Rule Generator"]
    end
```'''
c1 = c1.replace(old_fig1, new_fig1)
with open('report/chapters/01-introduction.md', 'w', encoding='utf-8') as f:
    f.write(c1)
print('Fixed Fig. 1 in 01-introduction.md')

# 2. Fix 02-literature-review.md (Diagram #2)
with open('report/chapters/02-literature-review.md', 'r', encoding='utf-8') as f:
    c2 = f.read()

old_fig3 = re.search(r'```mermaid\s*graph TD\s*subgraph Data Collection[\s\S]*?```', c2).group(0)
new_fig3 = '''```mermaid
flowchart TD
    subgraph Sub_Data ["1. Data Collection"]
        P1["P1: Sampling Bias"]
        P2["P2: Label Inaccuracy"]
    end
    subgraph Sub_Feat ["2. Feature Processing"]
        P3["P3: Data Snooping / Leakage"]
        P4["P4: Spurious Correlations"]
        P5["P5: Concept Drift & Temporal Bias"]
    end
    subgraph Sub_Sys ["3. System Design"]
        P6["P6: Inappropriate Baselines"]
        P7["P7: Inappropriate Metrics"]
    end
    subgraph Sub_Eval ["4. Evaluation"]
        P8["P8: Base Rate Fallacy"]
        P9["P9: Lab-Only Evaluation"]
        P10["P10: Compartmentalized Threat Models"]
    end
    P1 --> P3
    P2 --> P4
    P3 --> P6
    P4 --> P7
    P5 --> P8
    P6 --> P9
    P7 --> P10
```'''
c2 = c2.replace(old_fig3, new_fig3)
with open('report/chapters/02-literature-review.md', 'w', encoding='utf-8') as f:
    f.write(c2)
print('Fixed Fig. 3 in 02-literature-review.md')

# 3. Fix 03-system-architecture.md (Fig. 4 and Fig. 6)
with open('report/chapters/03-system-architecture.md', 'r', encoding='utf-8') as f:
    c3 = f.read()

old_fig4 = re.search(r'```mermaid\s*graph TD\s*subgraph Layer 1: Ingestion & Telemetry[\s\S]*?```', c3).group(0)
new_fig4 = '''```mermaid
flowchart TD
    subgraph L1 ["Layer 1: Ingestion & Telemetry"]
        L1_A["Raw Socket Sniffer (AF_PACKET / Raw)"]
        L1_B["Suricata EVE Tailer (eve.json)"]
        L1_C["Universal Ingestion Engine"]
    end

    subgraph L2 ["Layer 2: Feature Engineering & Preprocessing"]
        L2_A["32-Feature Extraction (FlowRecord)"]
        L2_B["Robust Log1p Normalizer"]
    end

    subgraph L3 ["Layer 3: Pipeline v2 Inference & Evidence Fusion"]
        L3_A["XGBoost Known-Attack Classifier"]
        L3_B["Statistical Z-Score Filter"]
        L3_C["PyTorch Deep Autoencoder"]
        L3_D["Canonical Heuristic Router"]
    end

    subgraph L4 ["Layer 4: Cognitive Advisory & Decision Engine"]
        L4_A["MITRE ATT&CK & D3FEND Graph-RAG"]
        L4_B["Advisory LLM Incident Explainer"]
        L4_C["Contradiction Guard Interlock"]
    end

    subgraph L5 ["Layer 5: Safety Verification & Containment"]
        L5_A["Formal Safety Gate (Propositional / SMT)"]
        L5_B["Two-Person Authorization Engine"]
        L5_C["Host Firewall Actuator"]
        L5_D["Process Suspension Actuator"]
        L5_E["Suricata Rule Generator"]
    end

    subgraph L6 ["Layer 6: API, Storage & Presentation"]
        L6_A["FastAPI Async REST Service"]
        L6_B["SQLite WAL Persistence (cyberguard.db)"]
        L6_C["Real-Time Operations Dashboard"]
    end

    L1_A --> L2_A
    L1_B --> L2_A
    L1_C --> L2_A
    L2_A --> L2_B
    L2_B --> L3_A
    L2_B --> L3_B
    L2_B --> L3_C
    L3_A --> L3_D
    L3_B --> L3_D
    L3_C --> L3_D
    L3_D -->|Volumetric Attack| L5_A
    L3_D -->|Complex Anomaly| L4_A
    L4_A --> L4_B
    L4_B --> L4_C
    L4_C --> L5_A
    L5_A --> L5_B
    L5_B --> L5_C
    L5_B --> L5_D
    L5_B --> L5_E
    L3_D --> L6_A
    L5_A --> L6_A
    L6_A --> L6_B
    L6_A --> L6_C
```'''
c3 = c3.replace(old_fig4, new_fig4)

old_fig6 = re.search(r'```mermaid\s*graph TD\s*subgraph Capture Thread[\s\S]*?```', c3).group(0)
new_fig6 = '''```mermaid
flowchart TD
    subgraph Sub_Cap ["Capture Thread (LiveFlowSniffer)"]
        S1["Live Sniffer Thread"] -->|recvfrom| S2["Packet Parsing & Filtering"]
        S2 -->|Acquire _lock| S3["Stateful Flow Table Update"]
        S3 -->|Release _lock| S1
    end
    
    subgraph Sub_Queue ["Ingestion Queue & Worker (LiveWorker)"]
        S3 -->|enqueue_flow| WQ["Bounded FIFO Queue (max 10,000)"]
        WQ -->|Drain Batch (B=50)| W1["Live Worker Thread"]
        W1 -->|detect_batch| PL["Pipeline v2 Inference Engine"]
        PL -->|commit_stats| ST["Atomic Telemetry Statistics"]
    end
    
    subgraph Sub_Api ["FastAPI Gateway & Runtime Lifespan"]
        API["Uvicorn Async Worker"] -->|GET /health| PL
        API -->|POST /upload| PL
        LS["Lifespan Context Manager"] -->|Start / Stop| W1
    end
```'''
c3 = c3.replace(old_fig6, new_fig6)
with open('report/chapters/03-system-architecture.md', 'w', encoding='utf-8') as f:
    f.write(c3)
print('Fixed Fig. 4 and Fig. 6 in 03-system-architecture.md')

# 4. Fix 04-implementation-analysis.md (Fig. 11)
with open('report/chapters/04-implementation-analysis.md', 'r', encoding='utf-8') as f:
    c4 = f.read()

old_fig11 = re.search(r'```mermaid\s*graph LR\s*SURI\[Suricata Engine\][\s\S]*?```', c4).group(0)
new_fig11 = '''```mermaid
flowchart TD
    SURI["Suricata 7.x Network IDS Engine"] -->|Append Alert Records| EVE["Live EVE Log Stream (/var/log/suricata/eve.json)"]
    EVE -->|Tail Inotify / ReadLine| TAIL["SuricataLiveTailer Bridge Engine"]
    TAIL -->|Parse JSON Record| MAP["Feature Synthesis (eve_to_flow_features)"]
    MAP -->|Approximated 32-Feature Vector| PIPE["Pipeline v2 Inference Engine"]
    PIPE -->|Persist Alert Record| DB["SQLite WAL Storage (cyberguard.db)"]
```'''
c4 = c4.replace(old_fig11, new_fig11)
with open('report/chapters/04-implementation-analysis.md', 'w', encoding='utf-8') as f:
    f.write(c4)
print('Fixed Fig. 11 in 04-implementation-analysis.md')

# 5. Fix 05-methodology.md (Fig. 14)
with open('report/chapters/05-methodology.md', 'r', encoding='utf-8') as f:
    c5 = f.read()

old_fig14 = re.search(r'```mermaid\s*flowchart LR\s*subgraph Reality\["Ground Truth Reality"\][\s\S]*?```', c5).group(0)
new_fig14 = '''```mermaid
flowchart TD
    subgraph Reality ["Ground Truth Reality"]
        ActPos["Condition Positive (P)"]
        ActNeg["Condition Negative (N)"]
    end

    subgraph Prediction ["Model Decision"]
        PredPos["Predicted Positive (PP)"]
        PredNeg["Predicted Negative (PN)"]
    end

    ActPos -->|Correct Detection| TP["True Positive (TP)"]
    ActPos -->|Missed Attack| FN["False Negative (FN) - Type II Error"]
    ActNeg -->|False Alarm| FP["False Positive (FP) - Type I Error"]
    ActNeg -->|Correct Clean| TN["True Negative (TN)"]
    
    TP --> PredPos
    FP --> PredPos
    FN --> PredNeg
    TN --> PredNeg
```'''
c5 = c5.replace(old_fig14, new_fig14)
with open('report/chapters/05-methodology.md', 'w', encoding='utf-8') as f:
    f.write(c5)
print('Fixed Fig. 14 in 05-methodology.md')
