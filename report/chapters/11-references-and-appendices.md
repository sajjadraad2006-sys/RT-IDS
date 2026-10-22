# REFERENCES AND APPENDICES



## Appendix A: Master Code Evidence Ledger

This appendix indexes every primary code reference (`[CE-01]` through `[CE-54]`) cited as verifiable evidence throughout this report. Every claim regarding system architecture, vulnerability mechanics, and feature extraction maps directly to an audited source file and line range in the workspace.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XXI.</b> MASTER CODE EVIDENCE INDEX
</div>

| Evidence ID | Target Source File | Line Range | Architectural Fact / Empirical Evidence Proven |
|:---:|:---|:---|:---|
| **[CE-01]** | [`data/models/trained/artifacts.json`](data/models/trained/artifacts.json#L1-L38) | Lines 1–38 | Model metadata declares `production_approved=false`, `evaluation_only=true`, `independent_test_split=false`, 4 classes, and calibrated threshold $\tau_{\text{AE}} = 0.004597$. |
| **[CE-02]** | [`cyberguard/datasets/generate_sample.py`](cyberguard/datasets/generate_sample.py#L34-L65) | Lines 34–65 | Synthetic dataset generation using hardcoded random distributions with `np.random.seed(42)` generating 2,000 synthetic flows. |
| **[CE-03]** | [`backend/detection/features.py`](backend/detection/features.py#L1-L85) | Lines 1–85 | Canonical 32-feature statistical flow schema, feature ordering, and SHA-256 schema hash derivation. |
| **[CE-04]** | [`backend/detection/live_sniffer.py`](backend/detection/live_sniffer.py#L210-L245) | Lines 210–245 | Flow record data structure, sliding window aggregation, and dictionary conversion for inference pipeline. |
| **[CE-05]** | [`backend/detection/live_worker.py`](backend/detection/live_worker.py#L45-L95) | Lines 45–95 | Real-time queue worker consuming flows from `LiveFlowSniffer` with bounded queue size ($Q_{\max}=10,000$). |
| **[CE-06]** | [`backend/detection/pipeline.py`](backend/detection/pipeline.py#L120-L165) | Lines 120–165 | Pipeline v2 inference routing: XGBoost classification, autoencoder reconstruction error, and heuristic router. |
| **[CE-07]** | [`backend/detection/pipeline.py`](backend/detection/pipeline.py#L30-L55) | Lines 30–55 | Thread-safe double-checked singleton lock pattern initializing model bundle. |
| **[CE-08]** | [`backend/detection/classifier.py`](backend/detection/classifier.py#L1-L45) | Lines 1–45 | Multi-class XGBoost model wrapper and probability calibration logic. |
| **[CE-09]** | [`backend/detection/statistical.py`](backend/detection/statistical.py#L1-L60) | Lines 1–60 | Statistical anomaly baseline using Z-score deviations across normalized feature distributions. |
| **[CE-10]** | [`backend/detection/autoencoder.py`](backend/detection/autoencoder.py#L1-L75) | Lines 1–75 | PyTorch deep autoencoder architecture (32 -> 16 -> 8 -> 16 -> 32) and MSE loss calculation. |
| **[CE-11]** | [`backend/detection/router.py`](backend/detection/router.py#L40-L110) | Lines 40–110 | Multi-signal routing decision matrix classifying flows into BENIGN, ATTACK, SUSPICIOUS, or REVIEW. |
| **[CE-12]** | [`backend/suricata/tailer.py`](backend/suricata/tailer.py#L168-L235) | Lines 168–235 | Feature fabrication heuristic: hardcoded TCP window sizes (64240/29200), zero variance, and microsecond conversion error. |
| **[CE-13]** | [`backend/detection/input_contract.py`](backend/detection/input_contract.py#L1-L50) | Lines 1–50 | Strict input schema validation: rejection of non-numeric, NaN, infinite, and out-of-order feature payloads. |
| **[CE-14]** | [`backend/decision/engine.py`](backend/decision/engine.py#L1-L80) | Lines 1–80 | Autonomous containment decision engine evaluating threat severity against policy thresholds. |
| **[CE-15]** | [`backend/actuators/process_actuator.py`](backend/actuators/process_actuator.py#L1-L65) | Lines 1–65 | Process containment actuator: target verification, process suspension via `SIGSTOP`/`taskkill`, and rollback receipts. |
| **[CE-16]** | [`backend/actuators/guardrails.py`](backend/actuators/guardrails.py#L1-L50) | Lines 1–50 | Deterministic safety guardrails preventing quarantine of loopback, gateway, and DNS infrastructure. |
| **[CE-17]** | [`backend/actuators/base.py`](backend/actuators/base.py#L1-L35) | Lines 1–35 | Abstract base actuator defining `execute()` and atomic `rollback()` interface. |
| **[CE-18]** | [`backend/safety/formal_verifier.py`](backend/safety/formal_verifier.py#L1-L55) | Lines 1–55 | Formal verification module: SymPy propositional `satisfiable()` check over 4 boolean symbols and inert SMT-LIB2 string. |
| **[CE-19]** | [`backend/api/auth.py`](backend/api/auth.py#L1-L85) | Lines 1–85 | FastAPI authentication: RBAC token extraction, role hierarchy, and unauthenticated loopback elevation bug. |
| **[CE-20]** | [`backend/api/security.py`](backend/api/security.py#L1-L45) | Lines 1–45 | Client IP resolution trusting reverse proxy headers (`X-Forwarded-For`) and rate limiting. |
| **[CE-21]** | [`backend/main.py`](backend/main.py#L55-L70) | Lines 55–70 | App OpenAPI description explicitly declaring live ingestion and automated response as "not implemented". |
| **[CE-22]** | [`backend/config.py`](backend/config.py#L25-L35) | Lines 25–35 | Application configuration: `CG_AUTOSTART_LIVE_WORKER` default set to `"false"`. |
| **[CE-23]** | [`backend/detection/integrity.py`](backend/detection/integrity.py#L402-L439) | Lines 402–439 | Deserialization integrity: SHA-256 pre-verification of pickle files before `joblib.load()` or `pickle.load()`. |
| **[CE-24]** | [`backend/mitre/mapper.py`](backend/mitre/mapper.py#L1-L65) | Lines 1–65 | Mapping of anomalous flow feature patterns to MITRE ATT&CK technique IDs (T1046, T1498, T1071). |
| **[CE-25]** | [`backend/mitre/d3fend.py`](backend/mitre/d3fend.py#L1-L50) | Lines 1–50 | Mapping MITRE ATT&CK offensive techniques to defensive counter-measures in NSA D3FEND framework. |
| **[CE-26]** | [`backend/llm/rag.py`](backend/llm/rag.py#L1-L75) | Lines 1–75 | Retrieval-Augmented Generation context assembly combining flow features, MITRE techniques, and playbook text. |
| **[CE-27]** | [`backend/llm/advisory.py`](backend/llm/advisory.py#L1-L60) | Lines 1–60 | Advisory LLM interface generating incident narrative summaries with structured hallucination guardrails. |
| **[CE-28]** | [`backend/detection/live_sniffer.py`](backend/detection/live_sniffer.py#L461-L512) | Lines 461–512 | TCP state tracking: handshake completion flag, FIN/RST teardown handling, and sequence number tracking. |
| **[CE-29]** | [`backend/detection/live_sniffer.py`](backend/detection/live_sniffer.py#L432-L460) | Lines 432–460 | UDP flow assembly: bi-directional session grouping with 5.0-second inactivity timeout. |
| **[CE-30]** | [`backend/detection/live_sniffer.py`](backend/detection/live_sniffer.py#L278-L315) | Lines 278–315 | Raw packet processing loop, IP header parsing, and protocol demultiplexing. |
| **[CE-31]** | [`backend/detection/live_sniffer.py`](backend/detection/live_sniffer.py#L400-L425) | Lines 400–425 | Active flow table management and periodic eviction of timed-out flow objects. |
| **[CE-32]** | [`backend/detection/live_sniffer.py`](backend/detection/live_sniffer.py#L521-L541) | Lines 521–541 | Socket creation logic: Linux `IPPROTO_TCP` raw socket and Windows `127.0.0.1` binding override. |
| **[CE-33]** | [`backend/detection/live_sniffer.py`](backend/detection/live_sniffer.py#L538-L541) | Lines 538–541 | Unprivileged socket failure handler falling back to `synthetic_harness` while returning `True`. |
| **[CE-34]** | [`backend/detection/live_sniffer.py`](backend/detection/live_sniffer.py#L331-L334) | Lines 331–334 | IPv4 header version check: `if version != 4: return None`, silently dropping all IPv6 frames. |
| **[CE-35]** | [`backend/detection/live_sniffer.py`](backend/detection/live_sniffer.py#L234-L235) | Lines 234–235 | Feature dictionary assembly hardcoding `active_mean: 0.0` and `idle_mean: 0.0`. |
| **[CE-36]** | [`backend/db/models.py`](backend/db/models.py#L12-L32) | Lines 12–32 | SQLite WAL mode configuration, foreign key enforcement, relaxed sync pragmas, and chmod 0o600 permissions. |
| **[CE-37]** | [`backend/db/models.py`](backend/db/models.py#L34-L58) | Lines 34–58 | Machine-local Fernet credential encryption with `O_NOFOLLOW` symlink protection and `0o600` access mode. |
| **[CE-38]** | [`backend/decision/audit.py`](backend/decision/audit.py#L15-L42) | Lines 15–42 | Append-only audit ledger with SHA-256 cryptographic hash-chain state transition over canonicalized JSON. |
| **[CE-39]** | [`backend/decision/audit.py`](backend/decision/audit.py#L44-L62) | Lines 44–62 | Sequential hash-chain verification algorithm detecting historical record modification and deletion. |
| **[CE-40]** | [`backend/db/init_db.py`](backend/db/init_db.py#L8-L48) | Lines 8–48 | Forward-only non-destructive database migrations applying schema alterations via SQLAlchemy reflection. |
| **[CE-41]** | [`backend/actuators/process_actuator.py`](backend/actuators/process_actuator.py#L155-L210) | Lines 155–210 | Dual-authorization validation against database records and cryptographic rollback receipt issuance. |
| **[CE-42]** | [`backend/safety/formal_verifier.py`](backend/safety/formal_verifier.py#L45-L52) | Lines 45–52 | Propositional logic encoding and inert SMT-LIB2 dialect string formatting (`QF_UF`). |
| **[CE-43]** | [`backend/detection/router.py`](backend/detection/router.py#L112-L168) | Lines 112–168 | Non-mutating candidate shadow model promotion gate evaluating routing parity. |
| **[CE-44]** | [`backend/suricata/attack_extractor.py`](backend/suricata/attack_extractor.py#L25-L80) | Lines 25–80 | Extraction of attack signatures and flow metadata from Suricata EVE JSON alert payloads. |
| **[CE-45]** | [`backend/mitre/mapper.py`](backend/mitre/mapper.py#L45-L110) | Lines 45–110 | Heuristic mapping rules converting statistical flow anomaly vectors into MITRE ATT&CK technique IDs. |
| **[CE-46]** | [`backend/actuators/guardrails.py`](backend/actuators/guardrails.py#L30-L75) | Lines 30–75 | Deterministic process protection guardrails preventing quarantine of critical system tasks (`lsass.exe`, `init`, `systemd`). |
| **[CE-47]** | [`backend/actuators/guardrails.py`](backend/actuators/guardrails.py#L80-L125) | Lines 80–125 | Sanitization of actuation commands preventing shell injection operators (`;`, `|`, `>`) in target host/process strings. |
| **[CE-48]** | [`backend/actuators/base.py`](backend/actuators/base.py#L20-L55) | Lines 20–55 | Atomic containment and deterministic rollback specification returning cryptographic undo tokens. |
| **[CE-49]** | [`backend/decision/engine.py`](backend/decision/engine.py#L45-L95) | Lines 45–95 | Threat severity proportionality interlocks preventing destructive containment dispatch on unverified minor anomalies. |
| **[CE-50]** | [`backend/safety/formal_verifier.py`](backend/safety/formal_verifier.py#L185-L204) | Lines 185–204 | Formal verification propositional boolean evaluation engine utilizing SymPy boolean AST satisfiability checking. |
| **[CE-51]** | [`backend/safety/formal_verifier.py`](backend/safety/formal_verifier.py#L246-L270) | Lines 246–270 | Formatted SMT-LIB2 theory dialect string template generation for persistent audit proof certificates. |
| **[CE-52]** | [`backend/auth.py`](backend/auth.py#L61-L85) | Lines 61–85 | User authentication and cryptographic credential storage using PBKDF2-HMAC-SHA256 with 100,000 hash iterations. |
| **[CE-53]** | [`backend/actuators/router.py`](backend/actuators/router.py#L73-L110) | Lines 73–110 | Two-Person Rule authorization barrier requiring distinct initiator and human operator approver IDs before actuation. |
| **[CE-54]** | [`backend/decision/audit.py`](backend/decision/audit.py#L15-L62) | Lines 15–62 | Immutable cryptographic audit ledger maintaining forward hash-chain integrity via SHA-256 state transitions. |

---

## Appendix B: Full Test and Benchmark Logs Summary

This appendix provides the full empirical test logs generated across our test battery. All source JSON log files are permanently archived under `report/results/`.

### B.1 Dynamic Pytest Test Suite Execution (`pytest_run.json`)
- **Execution Date:** 2026-10-17T14:22:18 UTC
- **Environment:** Microsoft Windows 11 Enterprise (NT Build 22631), Python 3.12.10 (64-bit AMD64)
- **Invocation Command:** `pytest -q`
- **Total Test Files Evaluated:** 41 test modules
- **AST Top-Level Function Count:** 425 `def test_*` functions
- **Collected Test Items (Parameterized):** Exactly 536 items
- **Passed Tests:** **536 passed**
- **Failed / Skipped Tests:** 0 failed, 0 skipped
- **Warnings:** 6 warnings (scikit-learn `InconsistentVersionWarning` on version 1.9.0 vs 1.9.1; XGBoost unpickling deprecation warning)
- **Total Duration:** **53.84 seconds**

### B.2 Master 41-Module Empirical Test Suite Catalog
Table XXIII details the empirical test distribution across all 41 test modules comprising the CyberGuard verification suite.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XXIII.</b> MASTER 41-MODULE EMPIRICAL TEST SUITE CATALOG
</div>

| Test Module Filename | Function Count | Target Subsystem | Core Invariants and Failure Modes Verified | Execution Scope |
|:---|:---:|:---|:---|:---:|
| `test_active_containment_and_rollback.py` | 13 | Actuation & Safety | Process suspension, firewall port block, HMAC rollback token redemption | Integration |
| `test_actuators.py` | 13 | Autonomous Actuators | Atomic actuation rollback, timeout handling, non-zero return codes | Unit |
| `test_api.py` | 23 | REST API Gateway | Strict flow schema upload, health endpoints, HTTP 422 contract rejection | Integration |
| `test_auth_rbac.py` | 7 | Auth & RBAC | Role escalation prevention, JWT verification, Two-Person Rule dual sign-off | Unit |
| `test_autoencoder.py` | 7 | Stage 4 Anomaly ML | Reconstruction MSE on normal flows, out-of-distribution anomaly scoring | Unit |
| `test_autonomous_decision.py` | 4 | Decision Engine | Policy threshold comparison, autonomous containment action dispatch | Unit |
| `test_candidate_workflow.py` | 7 | ML Shadow Promotion | Zero-leakage temporal splits, schema hash verification, calibration parity | Unit |
| `test_classifier.py` | 4 | Stage 3 XGBoost | Multi-class prediction, probability calibration, class label ordering | Unit |
| `test_d3fend.py` | 5 | Threat Frameworks | NSA D3FEND countermeasure relationship mapping, ontology traversal | Unit |
| `test_dataset_acquisition.py` | 4 | Dataset Ingestion | Fail-closed network download handling, SHA-256 archive integrity checks | Unit |
| `test_defense_rag.py` | 12 | LLM / Playbooks | Knowledge retrieval relevance, vector similarity search, context bounding | Integration |
| `test_doctoral_empirical_benchmark.py` | 12 | Research Verification | Throughput scaling, latency percentiles, formal safety invariant coverage | Integration |
| `test_e2e_containment_pipeline.py` | 1 | Full System E2E | Sniffer stream -> Smart Log -> Two-Person Rule -> Containment & Rollback | System E2E |
| `test_evaluation_intake.py` | 12 | Intake Validation | Prevention of fixture data leakage into official evaluation benchmark | Regression |
| `test_evaluation_report.py` | 5 | Provenance Envelopes | Verification that evaluation envelopes cannot manufacture artificial scores | Regression |
| `test_features.py` | 11 | Flow Feature Extraction | Zero division guards, non-negative durations, canonical 32-vector typing | Unit |
| `test_formal_safety_adversarial.py` | 9 | Neuro-Symbolic Safety | SymPy satisfiability under adversarial input permutations, invariant proof | Unit |
| `test_formal_verifier.py` | 7 | Safety Invariants | 4-proposition satisfiability checking, SMT-LIB2 dialect string export | Unit |
| `test_frontend_live_operations.py` | 1 | SOC UI Controller | Bounded polling controller, adaptive jitter backoff, disconnected handling | Integration |
| `test_honesty_contracts.py` | 4 | Verification Contracts | Bounded claims enforcement, prevention of LLM hallucination in SOC logs | Regression |
| `test_input_schema.py` | 12 | Input Validation | Type enforcement, rejection of infinite, NaN, and negative field values | Unit |
| `test_integrity.py` | 8 | Artifact Integrity | SHA-256 pre-verification of model pickles, forward-only DB migrations | Security |
| `test_knowledge_graph.py` | 3 | Threat Knowledge | Node/edge insertions, technique-to-tactic traversal, cycle prevention | Unit |
| `test_knowledge_graph_comprehensive.py` | 5 | Threat Hypergraph | Stress testing graph traversals under high-degree node fanouts | Integration |
| `test_live_sniffer.py` | 12 | Link-Layer Sniffer | TCP handshake state machine, FIN/RST teardown, UDP session tracking | Unit / System |
| `test_mitre.py` | 29 | MITRE ATT&CK | ATT&CK technique lookups, tactic classification, STIX 2.1 taxonomy | Integration |
| `test_operations.py` | 7 | Incident Triage | Incident correlation, alert deduplication, transparent risk calculation | Unit |
| `test_pipeline.py` | 10 | Inference Pipeline | Routing invariants, double-checked lock concurrency, feature scaling | Unit |
| `test_realtime_pipeline_worker.py` | 8 | Worker Thread & Queue | Queue backpressure, thread lifecycle, worker shutdown synchronization | Concurrency |
| `test_reproducibility.py` | 7 | Seed & Environment | Deterministic random seed propagation, environment variable defaults | Regression |
| `test_routing_parity.py` | 7 | Serving Parity | Exact routing parity between serving model, candidate, and shadow pipeline | Parity |
| `test_security.py` | 21 | Web & API Security | Client IP spoofing, header injection, CORS policies, timing attack guards | Security |
| `test_semantic_rag.py` | 14 | Semantic Retrieval | Dense vector retrieval, hybrid BM25 + embedding ranking, cache hits | Integration |
| `test_shadow_promotion.py` | 16 | Production Promotion | Candidate promotion gates, F1 score non-regression requirements | Integration |
| `test_simulation_and_universal_api.py` | 3 | Attack Simulation | SYN flood, port scan, and slowloris synthetic traffic injection harnesses | Integration |
| `test_smart_decision.py` | 16 | Guarded Decision | Smart Log assembly, prompt versioning, contradictory response filtering | Unit |
| `test_suricata_bridge.py` | 59 | Suricata Translation | EVE JSON parsing, 32-feature approximation heuristics, protocol mapping | Integration |
| `test_suricata_tailer.py` | 4 | Log File Tailer | Inotify/Win32 file tailing, truncation detection, log rotation resilience | Unit |
| `test_threat_intelligence.py` | 7 | CISA KEV / EPSS | External vulnerability feed sync, EPSS score enrichment, timeout guards | Integration |
| `test_universal_ingestion.py` | 4 | Multi-Format Ingest | PCAP, EVE JSON, CSV, and Zeek connection log parsing abstractions | Integration |
| `test_upload_stream.py` | 12 | Stream Processing | Memory-bounded chunked upload processing, archive decompression bombs | Security |

### B.3 Live Sniffer Micro-Benchmarks (`sniffer_experiments.json`)
- **Evaluated Volume:** 50,000 synthetic raw IPv4 frames
- **Elapsed Duration:** 0.06958 seconds
- **Throughput:** **718,569.41 packets/second**
- **Mean Processing Latency:** **1.392 $\mu\text{s}$ per packet**
- **Protocol Tests:** 8/8 passed (TCP Handshake, Teardown, Immediate RST, 5.0 s Idle Timeout, TIME_WAIT ACK Absorption, Interim Micro-Windows, UDP Aggregation, IPv6 Frame Dropping).

### B.4 End-to-End Pipeline Latency and Batch Scaling (`pipeline_benchmarks.json`)
- **Sequential Inferences Evaluated:** 1,000 single-flow inferences on `CyberGuardPipelineV2`
- **Percentiles:** $P_{50} = 3.250$ ms, $P_{90} = 4.027$ ms, $P_{95} = 4.196$ ms, $P_{99} = 5.911$ ms ($\mu = 3.380$ ms, $\sigma = 0.610$ ms)
- **Batch Scaling Throughput:** Scales from 163.55 flows/sec ($B=1$) to 3,109.19 flows/sec ($B=2,000$)
- **Amortized Latency:** Decreases from 6.11 ms ($B=1$) to 0.32 ms ($B=2,000$)
- **Peak Memory Growth:** 18.27 KB ($B=1$) to 10,414.59 KB ($B=2,000$), strictly $\mathcal{O}(B)$ linear.

### B.5 Bundled Model Performance and Autoencoder Anomaly Scoring (`model_evaluation_bundled.json`)
- **Overall Accuracy:** 96.25% (1,925 / 2,000 correct)
- **Macro-Averaged $F_1$:** 0.9222
- **Per-Class Metrics:**
  - Benign: Precision 99.55%, Recall 95.75%, $F_1 = 0.9761$
  - Bot: Precision 57.76%, Recall 93.00%, $F_1 = 0.7126$ (68 false alarms)
  - DDoS: Precision 100.00%, Recall 100.00%, $F_1 = 1.0000$
  - PortScan: Precision 100.00%, Recall 100.00%, $F_1 = 1.0000$
- **Autoencoder Flaw:** Calibrated threshold $\tau_{\text{AE}} = 0.004597$; test set mean MSE is $8.10 \times 10^9$. Flagged rate is **100.0% across all classes**, proving catastrophic model-scaler dimensional misalignment.

---

## Appendix C: Canonical 32-Feature Statistical Flow Dictionary

Table XXIV provides an exhaustive technical specification of all 32 statistical flow features extracted by `FlowRecord` ([`backend/detection/live_sniffer.py`](backend/detection/live_sniffer.py#L210-L245) [CE-04]) and evaluated by `CyberGuardPipelineV2` ([`backend/detection/features.py`](backend/detection/features.py#L18-L55) [CE-03]).

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XXIV.</b> EXHAUSTIVE 32-FEATURE STATISTICAL FLOW DICTIONARY WITH NORMALIZATION BOUNDS
</div>

<div class="table-dense">

| # | Feature Name (Canonical) | Units | Formula / Extraction Logic | Normalizer ($\mu \pm \sigma$) | Range [Min, Max] | Operational Security Relevance |
|:---:|:---|:---:|:---|:---:|:---:|:---|
| 1 | `Destination Port` | Port | Transport layer destination port ($P_{\text{dst}}$) | $8,079.3 \pm 18,283.4$ | $[0, 65535]$ | Identifies targeted service (HTTP, SSH, RDP) |
| 2 | `Flow Duration` | $\mu\text{s}$ | $(t_{\text{last}} - t_{\text{first}}) \times 10^6$ | $14.78\text{M} \pm 33.65\text{M}$ | $[1, 1.2 \times 10^8]$ | Distinguishes ephemeral scans from persistent C2 |
| 3 | `Total Fwd Packets` | pkts | $\sum p \in \mathcal{P}_{\text{fwd}}$ | $9.38 \pm 748.2$ | $[1, 219,759]$ | Asymmetric volume indicator in SYN/UDP floods |
| 4 | `Total Backward Packets` | pkts | $\sum p \in \mathcal{P}_{\text{bwd}}$ | $10.21 \pm 998.4$ | $[0, 291,922]$ | Zero in unacknowledged floods and one-way scans |
| 5 | `Total Length of Fwd Packets` | bytes | $\sum L(p), p \in \mathcal{P}_{\text{fwd}}$ | $549.3 \pm 9,921.4$ | $[0, 1.29 \times 10^7]$ | Identifies data exfiltration and buffer overflows |
| 6 | `Total Length of Bwd Packets` | bytes | $\sum L(p), p \in \mathcal{P}_{\text{bwd}}$ | $1,618.9 \pm 22,631.8$ | $[0, 6.55 \times 10^8]$ | Reflects server response data transfer volume |
| 7 | `Fwd Packet Length Mean` | bytes | $(\sum L_{\text{fwd}}) / N_{\text{fwd}}$ | $50.82 \pm 182.4$ | $[0, 2,320]$ | Characterizes forward application payload size |
| 8 | `Bwd Packet Length Mean` | bytes | $(\sum L_{\text{bwd}}) / N_{\text{bwd}}$ | $112.45 \pm 340.1$ | $[0, 2,482]$ | Characterizes server response packet size profile |
| 9 | `Flow Bytes/s` | B/s | $(\text{TotBytes}) / (\Delta t_{\text{flow}} \times 10^{-6})$ | $1.48\text{M} \pm 25.10\text{M}$ | $[0, 3.2 \times 10^9]$ | Quantifies aggregate link bandwidth consumption |
| 10 | `Flow Packets/s` | pkts/s | $(N_{\text{f}} + N_{\text{b}}) / (\Delta t_{\text{flow}} \times 10^{-6})$ | $69,214 \pm 254,110$ | $[0, 2.0 \times 10^6]$ | Primary discriminator for high-rate volumetric DDoS |
| 11 | `Flow IAT Mean` | $\mu\text{s}$ | $(\tau_M - \tau_1) / (M - 1)$ | $1.29\text{M} \pm 4.51\text{M}$ | $[0, 1.2 \times 10^8]$ | Temporal packet spacing; low in automated floods |
| 12 | `Flow IAT Std` | $\mu\text{s}$ | Welford streaming standard deviation | $1.84\text{M} \pm 6.32\text{M}$ | $[0, 8.4 \times 10^7]$ | Variance in packet arrival intervals |
| 13 | `Flow IAT Max` | $\mu\text{s}$ | $\max(\tau_{k+1} - \tau_k)$ | $4.22\text{M} \pm 12.49\text{M}$ | $[0, 1.2 \times 10^8]$ | Maximum inter-packet pause in the connection |
| 14 | `Flow IAT Min` | $\mu\text{s}$ | $\min(\tau_{k+1} - \tau_k)$ | $162.4 \pm 58,201$ | $[-14, 1.2 \times 10^8]$ | Minimum inter-packet pause (negative indicates clock skew) |
| 15 | `Fwd IAT Mean` | $\mu\text{s}$ | $(\tau_{N_{\text{f}}}^{\text{f}} - \tau_1^{\text{f}}) / (N_{\text{f}} - 1)$ | $1.30\text{M} \pm 4.68\text{M}$ | $[0, 1.2 \times 10^8]$ | Client transmission interval pacing |
| 16 | `Bwd IAT Mean` | $\mu\text{s}$ | $(\tau_{N_{\text{b}}}^{\text{b}} - \tau_1^{\text{b}}) / (N_{\text{b}} - 1)$ | $982,142 \pm 3.92\text{M}$ | $[0, 1.2 \times 10^8]$ | Server transmission interval pacing |
| 17 | `Min Packet Length` | bytes | $\min(L_i)$ across all packets | $15.2 \pm 24.8$ | $[0, 1,460]$ | Detects fixed-size probe packets (e.g., 40-byte SYN) |
| 18 | `Max Packet Length` | bytes | $\max(L_i)$ across all packets | $324.8 \pm 610.2$ | $[0, 65,535]$ | Reflects MTU path utilization and jumbo frames |
| 19 | `Packet Length Mean` | bytes | $(\sum L_i) / (N_{\text{f}} + N_{\text{b}})$ | $68.4 \pm 198.5$ | $[0, 2,320]$ | Aggregate packet size central tendency |
| 20 | `Packet Length Std` | bytes | Sample standard deviation of $L_i$ | $82.1 \pm 245.9$ | $[0, 4,710]$ | Dispersion in packet sizes within the flow |
| 21 | `FIN Flag Count` | count | $\sum \mathbb{I}(p.\text{flags} \ \& \ \text{FIN})$ | $0.035 \pm 0.184$ | $[0, 1]$ | Graceful connection termination counter |
| 22 | `SYN Flag Count` | count | $\sum \mathbb{I}(p.\text{flags} \ \& \ \text{SYN})$ | $0.046 \pm 0.209$ | $[0, 1]$ | Connection initiation counter (elevated in SYN scans) |
| 23 | `RST Flag Count` | count | $\sum \mathbb{I}(p.\text{flags} \ \& \ \text{RST})$ | $0.002 \pm 0.045$ | $[0, 1]$ | Abrupt connection reset indicator (high in port scans) |
| 24 | `PSH Flag Count` | count | $\sum \mathbb{I}(p.\text{flags} \ \& \ \text{PSH})$ | $0.298 \pm 0.457$ | $[0, 1]$ | Immediate data push flag (interactive protocols) |
| 25 | `ACK Flag Count` | count | $\sum \mathbb{I}(p.\text{flags} \ \& \ \text{ACK})$ | $0.315 \pm 0.464$ | $[0, 1]$ | Packet acknowledgment counter (dominant in TCP) |
| 26 | `URG Flag Count` | count | $\sum \mathbb{I}(p.\text{flags} \ \& \ \text{URG})$ | $0.0001 \pm 0.010$ | $[0, 1]$ | Out-of-band urgent pointer indicator |
| 27 | `Down/Up Ratio` | ratio | $N_{\text{bwd}} / N_{\text{fwd}}$ | $0.68 \pm 0.82$ | $[0, 156]$ | Directional packet asymmetry ratio |
| 28 | `Init_Win_bytes_forward` | bytes | TCP window size in first forward packet | $6,982.4 \pm 14,209.1$ | $[-1, 65,535]$ | OS fingerprinting metric; -1 in UDP flows |
| 29 | `Init_Win_bytes_backward` | bytes | TCP window size in first backward packet | $1,984.2 \pm 7,812.5$ | $[-1, 65,535]$ | Server TCP stack fingerprinting metric |
| 30 | `min_seg_size_forward` | bytes | Minimum transport header size in forward | $22.4 \pm 5.8$ | $[0, 60]$ | Identifies TCP options (timestamps, window scaling) |
| 31 | `Active Mean` | $\mu\text{s}$ | Mean duration flow was active before pause | $0.0 \pm 0.0$ | $[0, 0]$ | **Bug [CE-35]:** Hardcoded 0.0 in live sniffer |
| 32 | `Idle Mean` | $\mu\text{s}$ | Mean duration flow was idle before resuming | $0.0 \pm 0.0$ | $[0, 0]$ | **Bug [CE-35]:** Hardcoded 0.0 in live sniffer |

</div>

---

## Appendix D: Step-by-Step Reproduction Guide and Production Manifests

To ensure absolute scientific and engineering reproducibility, this appendix provides the complete environment commands, empirical harness execution sequences, and production container orchestration manifests.

### D.1 Prerequisites and Environment Setup
- **Operating System:** Windows 10/11 (x86_64) or Linux (Ubuntu 22.04 LTS / Debian 12 recommended)
- **Python:** Python 3.12 (64-bit)
- **Node.js:** Node.js v20+ (with npm 10+)
- **System Memory:** Minimum 8 GB RAM (16 GB recommended)

Clone or navigate to the workspace root:
```bash
cd .
```

Create and activate a clean virtual environment:
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install core dependencies pinned to compatible releases:
```powershell
pip install --upgrade pip
pip install fastapi==0.110.0 uvicorn==0.28.0 scikit-learn==1.4.1.post1 xgboost==2.0.3 torch==2.2.1 sympy==1.12 pandas==2.2.1 numpy==1.26.4 pytest==8.1.1 pytest-json-report==1.5.0
```

### D.2 Executing Empirical Verification Harnesses
Execute the empirical benchmark suite in order. All scripts deposit structured JSON results directly into `report/results/`:

1. **Verify Full Pytest Suite (536 tests):**
   ```powershell
   pytest -q
   ```
2. **Execute Sniffer Micro-Benchmarks (718k PPS & state transitions):**
   ```powershell
   python report/experiments/exp_p3b_sniffer.py
   ```
3. **Execute Pipeline Benchmarks (Latency percentiles & batch scaling):**
   ```powershell
   python report/experiments/exp_p3c_pipeline.py
   ```
4. **Execute Model Evaluation (Classifier accuracy & autoencoder divergence):**
   ```powershell
   python report/experiments/exp_p3d_model_eval.py
   ```
5. **Execute Robustness & Adversarial Perturbation Tests:**
   ```powershell
   python report/experiments/exp_p3e_robustness.py
   ```

### D.3 Executing Citation Engine TDD Tests
Validate citation numbering order, range compression, and missing key fail-closed behavior:
```powershell
pytest report/tests/test_citations.py -v
```

### D.4 Compiling the Master's Thesis Technical Report
The build pipeline compiles all Markdown chapters into a unified HTML document with KaTeX equations, Mermaid diagrams, and Paged.js running headers/footers, exporting to print-ready PDF:

```powershell
node report/build.mjs
```

The compiled report artifacts will be generated under:
- `report/dist/report.html` (Interactive, self-contained single-page report)
- `report/dist/report.pdf` (Print-ready, paginated A4 master document)

### D.5 Production Multi-Stage Hardened Dockerfile
Listing D.1 presents the production multi-stage Docker build specification enforcing non-root execution and minimal attack surface.

```dockerfile
# Listing D.1: Production Multi-Stage Dockerfile (Dockerfile.production)
# Stage 1: Build Environment
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Minimal Hardened Runtime
FROM python:3.12-slim-bookworm AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 libcap2-bin iptables curl && \
    rm -rf /var/lib/apt/lists/*

# Create unprivileged system user
RUN groupadd -g 1001 cyberguard && \
    useradd -u 1001 -g cyberguard -s /usr/sbin/nologin -M cyberguard

WORKDIR /app
COPY --from=builder /root/.local /home/cyberguard/.local
COPY --chown=cyberguard:cyberguard . /app

ENV PATH=/home/cyberguard/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    CG_ENV=production \
    CG_AUTOSTART_LIVE_WORKER=true

# Grant packet sniffing capability without full root
RUN setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/python3.12

USER cyberguard
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/health || exit 1

ENTRYPOINT ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### D.6 Multi-Container Production Orchestration Specification
Listing D.2 provides the production `docker-compose.production.yml` orchestrating Suricata sensor capture, CyberGuard pipeline processing, Redis task queuing, and Prometheus metrics scraping.

```yaml
# Listing D.2: Production Docker Compose Orchestration (docker-compose.production.yml)
version: '3.8'

services:
  suricata:
    image: jasonish/suricata:7.0.3
    container_name: cyberguard-suricata
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_NICE
    volumes:
      - ./config/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - suricata-logs:/var/log/suricata
    restart: unless-stopped

  cyberguard-core:
    build:
      context: .
      dockerfile: Dockerfile.production
    container_name: cyberguard-core
    network_mode: host
    environment:
      - CG_ENV=production
      - CG_DATABASE_URL=sqlite:////app/data/cyberguard.db
      - CG_REDIS_URL=redis://127.0.0.1:6379/0
      - CG_AUTOSTART_LIVE_WORKER=true
      - CG_SURICATA_EVE_PATH=/var/log/suricata/eve.json
    volumes:
      - cyberguard-data:/app/data
      - suricata-logs:/var/log/suricata:ro
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7.2-alpine
    container_name: cyberguard-redis
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:v2.50.0
    container_name: cyberguard-prometheus
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    restart: unless-stopped

volumes:
  suricata-logs:
  cyberguard-data:
  redis-data:
  prometheus-data:
```

---

## Appendix E: Formal Neuro-Symbolic Safety Gate Specification and SMT-LIB2 Encodings

This appendix provides the formal mathematical and logical specification of CyberGuard's Neuro-Symbolic Safety Gate (`backend/safety/formal_verifier.py` `[CE-18]`), including the complete truth table evaluation across all 16 possible boolean assignments and the standard SMT-LIB2 theory representation.

### E.1 Complete 16-Row Propositional Truth Table
The formal safety gate evaluates four boolean variables:
- $b_1$: `allow_high_risk_remediation` (Administrative flag permitting destructive intervention)
- $b_2$: `manual_override` (Human-in-the-loop manual confirmation)
- $b_3$: `quarantine_requested` (Autonomous engine requests network/process quarantine)
- $b_4$: `unverified_anomaly` (Detection signal is based solely on uncalibrated anomaly scores)

The fundamental safety invariant $I_{\text{safe}}$ mandates:
$$I_{\text{safe}} = \neg \left( b_3 \land b_4 \land \neg b_2 \right) \land \left( b_3 \land \neg b_1 \implies b_2 \right) \tag{E.1}$$

Table XXV documents the complete truth evaluation across all $2^4 = 16$ interpretations $\mathcal{I}_0$ through $\mathcal{I}_{15}$.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XXV.</b> COMPLETE PROPOSITIONAL TRUTH TABLE FOR SAFETY GATE INVARIANTS
</div>

| Row | $b_1$ (`allow_high`) | $b_2$ (`override`) | $b_3$ (`quarantine`) | $b_4$ (`unverified`) | Clause 1: $\neg(b_3 \land b_4 \land \neg b_2)$ | Clause 2: $(b_3 \land \neg b_1 \implies b_2)$ | Overall Verdict: $I_{\text{safe}}$ | Operational Safety Action |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| 0 | 0 | 0 | 0 | 0 | **1** | **1** | **PASS** | No action requested; safe baseline |
| 1 | 0 | 0 | 0 | 1 | **1** | **1** | **PASS** | Unverified telemetry observed; no intervention |
| 2 | 0 | 0 | 1 | 0 | **1** | **0** | <span style="color:red; font-weight:bold;">BLOCK</span> | Quarantine denied: high risk not permitted, no human override |
| 3 | 0 | 0 | 1 | 1 | **0** | **0** | <span style="color:red; font-weight:bold;">BLOCK</span> | Quarantine denied: unverified anomaly without override |
| 4 | 0 | 1 | 0 | 0 | **1** | **1** | **PASS** | Manual override idle; no quarantine |
| 5 | 0 | 1 | 0 | 1 | **1** | **1** | **PASS** | Manual override idle; telemetry logged |
| 6 | 0 | 1 | 1 | 0 | **1** | **1** | **PASS** | Quarantine permitted: explicit manual human override |
| 7 | 0 | 1 | 1 | 1 | **1** | **1** | **PASS** | Quarantine permitted: explicit manual human override |
| 8 | 1 | 0 | 0 | 0 | **1** | **1** | **PASS** | High risk permitted; no quarantine |
| 9 | 1 | 0 | 0 | 1 | **1** | **1** | **PASS** | High risk permitted; telemetry logged |
| 10 | 1 | 0 | 1 | 0 | **1** | **1** | **PASS** | Quarantine permitted: high risk flag active, verified attack |
| 11 | 1 | 0 | 1 | 1 | **0** | **1** | <span style="color:red; font-weight:bold;">BLOCK</span> | Quarantine denied: unverified anomaly cannot auto-trigger |
| 12 | 1 | 1 | 0 | 0 | **1** | **1** | **PASS** | High risk & override idle; no quarantine |
| 13 | 1 | 1 | 0 | 1 | **1** | **1** | **PASS** | High risk & override idle; telemetry logged |
| 14 | 1 | 1 | 1 | 0 | **1** | **1** | **PASS** | Quarantine permitted: high risk flag & human override |
| 15 | 1 | 1 | 1 | 1 | **1** | **1** | **PASS** | Quarantine permitted: high risk flag & human override |

As proven by the truth table, exactly 3 of the 16 states (Rows 2, 3, and 11) violate the safety specification and are deterministically blocked by the safety gate.

### E.2 SymPy Abstract Syntax Tree Reduction
In `backend/safety/formal_verifier.py`, SymPy constructs a boolean logic Abstract Syntax Tree (AST):

```python
# SymPy Propositional Invariant Reduction
from sympy import symbols, Not, And, Implies
b1, b2, b3, b4 = symbols("b1 b2 b3 b4")
c1 = Not(And(b3, b4, Not(b2)))
c2 = Implies(And(b3, Not(b1)), b2)
formula = And(c1, c2)
```

Applying boolean distribution and De Morgan's laws:
$$c_1 = \neg b_3 \lor \neg b_4 \lor b_2$$
$$c_2 = \neg (b_3 \land \neg b_1) \lor b_2 = \neg b_3 \lor b_1 \lor b_2$$
Conjoining the clauses yields the simplified Conjunctive Normal Form (CNF):
$$I_{\text{safe}} = (\neg b_3 \lor b_2 \lor \neg b_4) \land (\neg b_3 \lor b_2 \lor b_1)$$
Factoring out common terms $(\neg b_3 \lor b_2)$:
$$I_{\text{safe}} = (\neg b_3 \lor b_2) \lor (\neg b_4 \land b_1) \tag{E.2}$$

This mathematical reduction proves that the safety check requires only a single 2-term boolean expression, demonstrating that invocation of general symbolic solver engines is redundant for this logic.

### E.3 SMT-LIB2 Standard Benchmark Script
Listing E.1 presents the valid SMT-LIB2 benchmark script that can be verified by any standard compliant SMT solver (e.g., Microsoft Z3).

```smt2
; Listing E.1: CyberGuard Safety Invariants in SMT-LIB2 Format (safety.smt2)
(set-logic QF_BOOL)
(set-info :source |CyberGuard Formal Safety Invariant Benchmark|)
(set-info :status sat)

; Declare boolean propositions
(declare-fun allow_high_risk () Bool)
(declare-fun manual_override () Bool)
(declare-fun quarantine_requested () Bool)
(declare-fun unverified_anomaly () Bool)

; Safety Clause 1: Never quarantine on unverified anomaly without manual override
(assert (not (and quarantine_requested unverified_anomaly (not manual_override))))

; Safety Clause 2: Quarantine without high-risk permission mandates manual override
(assert (=> (and quarantine_requested (not allow_high_risk)) manual_override))

(check-sat)
(get-model)
(exit)
```

Executing `z3 safety.smt2` confirms that the invariant system is satisfiable (`sat`) and yields consistent counterexample models when an unsafe assertion is introduced, verifying the formal correctness of the underlying propositional design.

---

<div class="page-break"></div>

## Appendix F: Reference Verification Results
Per the independent thesis audit protocol, every bibliographic reference cited within this work has been audited against authoritative registries. DOIs were validated via live REST API queries against Crossref (`api.crossref.org`) and DataCite (`api.datacite.org`) requiring normalized title Levenshtein similarity $\ge 0.85$, first-author surname matching, and year validation. Non-DOI entries, conference proceedings without Crossref deposits (e.g., USENIX Security 10.5555 pseudo-DOIs), official international standards (IEC, ISO), and industry specifications (Modbus Organization, OPC Foundation, MITRE, OWASP, SMT-LIB) were verified against official publisher registries and cataloged as `MANUAL`.
**Verification Audit Summary:**
- Total Audited Citations: **45**
- Live API Verified (`VERIFIED`): **32**
- Authoritative Standards & Manual Checks (`MANUAL`): **13**
- Mismatched Metadata (`MISMATCH`): **0**
- Untraceable / Fabricated (`NOT_FOUND`): **0** (4 unverified entries purged)

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XXVI.</b> COMPLETE BIBLIOGRAPHIC REFERENCE VERIFICATION AUDIT LEDGER
</div>

| Citation Key | Status | Authority / Catalog | Title / Document Name |
|:---|:---:|:---|:---|
| `sharafaldin2018toward` | **VERIFIED** | Crossref DOI (`10.5220/0006639801080116`) | Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization |
| `engelen2021troubleshooting` | **VERIFIED** | Crossref DOI (`10.1109/SPW53761.2021.00009`) | Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study |
| `tavallaee2009detailed` | **VERIFIED** | Crossref DOI (`10.1109/CISDA.2009.5356528`) | A detailed analysis of the KDD CUP 99 data set |
| `shiravi2012towards` | **VERIFIED** | Crossref DOI (`10.1016/j.cose.2011.12.012`) | Toward developing a systematic approach to generate benchmark datasets for intrusion detection |
| `ring2019survey` | **VERIFIED** | Crossref DOI (`10.1016/j.cose.2019.06.005`) | A survey of network-based intrusion detection data sets |
| `sommer2010outside` | **VERIFIED** | Crossref DOI (`10.1109/SP.2010.25`) | Outside the Closed World: On Using Machine Learning for Network Intrusion Detection |
| `arp2022dos` | *MANUAL (with live evidence)* | USENIX / ACM DL Official Catalog | Dos and Don'ts of Machine Learning in Computer Security |
| `pendlebury2019tesseract` | *MANUAL (with live evidence)* | USENIX / ACM DL Official Catalog | TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time |
| `axelsson2000base` | **VERIFIED** | Crossref DOI (`10.1145/357830.357849`) | The base-rate fallacy and the difficulty of intrusion detection |
| `pierazzi2020intriguing` | **VERIFIED** | Crossref DOI (`10.1109/SP40000.2020.00073`) | Intriguing Properties of Adversarial ML Attacks in the Problem Space |
| `chen2016xgboost` | **VERIFIED** | Crossref DOI (`10.1145/2939672.2939785`) | XGBoost |
| `breiman2001random` | **VERIFIED** | Crossref DOI (`10.1023/A:1010933404324`) | Random Forests |
| `liu2008isolation` | **VERIFIED** | Crossref DOI (`10.1109/ICDM.2008.17`) | Isolation Forest |
| `mirsky2018kitsune` | **VERIFIED** | Crossref DOI (`10.14722/ndss.2018.23204`) | Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection |
| `sakurada2014anomaly` | **VERIFIED** | Crossref DOI (`10.1145/2689746.2689747`) | Anomaly Detection Using Autoencoders with Nonlinear Dimensionality Reduction |
| `chandola2009anomaly` | **VERIFIED** | Crossref DOI (`10.1145/1541880.1541882`) | Anomaly detection |
| `zhou2017anomaly` | **VERIFIED** | Crossref DOI (`10.1145/3097983.3098052`) | Anomaly Detection with Robust Deep Autoencoders |
| `paxson1999bro` | **VERIFIED** | Crossref DOI (`10.1016/S1389-1286(99)00112-7`) | Bro: a system for detecting network intruders in real-time |
| `roesch1999snort` | *MANUAL (with live evidence)* | USENIX / ACM DL Official Catalog | Snort: Lightweight Intrusion Detection for Networks |
| `mccanne1993bsd` | *MANUAL (with live evidence)* | USENIX / ACM DL Official Catalog | The BSD Packet Filter: A New Architecture for User-Level Packet Capture |
| `suricata2024engine` | *MANUAL (with live evidence)* | Official Standards Body / Tech Spec | Suricata User Guide (Release 7.0) |
| `rfc9293tcp` | **VERIFIED** | Crossref DOI (`10.17487/RFC9293`) | Transmission Control Protocol (TCP) |
| `rfc791ip` | **VERIFIED** | Crossref DOI (`10.17487/RFC0791`) | Internet Protocol |
| `strom2018mitre` | *MANUAL (with live evidence)* | Official Standards Body / Tech Spec | MITRE ATT&CK: Design and Philosophy |
| `kaloroumakis2021d3fend` | *MANUAL (with live evidence)* | MITRE Technical Publication | Toward a Knowledge Graph of Cybersecurity Countermeasures |
| `shostack2014threat` | *MANUAL (with live evidence)* | Official Standards Body / Tech Spec | Threat Modeling: Designing for Security |
| `demoura2008z3` | **VERIFIED** | Crossref DOI (`10.1007/978-3-540-78800-3_24`) | Z3: An Efficient SMT Solver |
| `barrett2010smtlib` | *MANUAL (with live evidence)* | Official Standards Body / Tech Spec | The SMT-LIB Standard: Version 2.0 |
| `islam2019soar` | **VERIFIED** | Crossref DOI (`10.1145/3305268`) | A Multi-Vocal Review of Security Orchestration |
| `cichonski2012incident` | **VERIFIED** | Crossref DOI (`10.6028/NIST.SP.800-61r2`) | Computer Security Incident Handling Guide : Recommendations of the National Institute of Standards and Technology |
| `greshake2023not` | **VERIFIED** | Crossref DOI (`10.1145/3605764.3623985`) | Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection |
| `liu2023prompt` | **VERIFIED** | DataCite DOI (`10.48550/arXiv.2305.13860`) | Jailbreaking ChatGPT via Prompt Engineering: An Empirical Study |
| `touvron2023llama` | **VERIFIED** | DataCite DOI (`10.48550/arXiv.2307.09288`) | Llama 2: Open Foundation and Fine-Tuned Chat Models |
| `owasp2023top10llm` | *MANUAL (with live evidence)* | Official Standards Body / Tech Spec | OWASP Top 10 for Large Language Model Applications (Version 1.0) |
| `stouffer2015nist80082` | **VERIFIED** | Crossref DOI (`10.6028/NIST.SP.800-82r2`) | Guide to Industrial Control Systems (ICS) Security |
| `iec62443standard` | *MANUAL (with live evidence)* | Official Standards Body / Tech Spec | Security for Industrial Automation and Control Systems - Part 4-2: Technical Security Requirements for IACS Components |
| `genge2012cyber` | **VERIFIED** | Crossref DOI (`10.1007/978-3-642-24864-1_12`) | Analyzing Cyber-Physical Attacks on Networked Industrial Control Systems |
| `krotofil2013industrial` | **VERIFIED** | Crossref DOI (`10.1007/978-3-642-41488-6_12`) | Resilience of Process Control Systems to Cyber-Physical Attacks |
| `hadziosmanovic2014nids` | **VERIFIED** | Crossref DOI (`10.1145/2664243.2664277`) | Through the eye of the PLC |
| `alcaraz2012scada` | **VERIFIED** | Crossref DOI (`10.1016/j.ijcip.2012.08.003`) | Analysis of requirements for critical control systems |
| `cardenas2011attacks` | **VERIFIED** | Crossref DOI (`10.1145/1966913.1966959`) | Attacks against process control systems |
| `dolev1983security` | **VERIFIED** | Crossref DOI (`10.1109/TIT.1983.1056650`) | On the security of public key protocols |
| `japkowicz2011evaluating` | **VERIFIED** | Crossref DOI (`10.1017/CBO9780511921803`) | Evaluating Learning Algorithms |
| `modbus2012spec` | *MANUAL (with live evidence)* | Official Standards Body / Tech Spec | Specifications and Implementation Guides - Modbus Organization |
| `opcfoundation2022spec` | *MANUAL (with live evidence)* | Official Standards Body / Tech Spec | OPC Unified Architecture - Part 2: Security Model |

---

## Appendix F: Disaggregated Repository Codebase Inventory

To satisfy absolute structural transparency and empirical verification, Table XXVII presents the complete byte-and-AST source code disaggregation across all 299 files comprising the CyberGuard repository, partitioned into six mutually exclusive categories summing to 113,107 total lines.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XXVII.</b> DISAGGREGATED REPOSITORY CODEBASE INVENTORY (EXACT 299 FILES)
</div>

| Category Index | Architectural Codebase Category | File Extensions Included | File Count | Total Lines | Code / Data SLOC | Comments | Blank Lines | Verifiable Primary Evidence |
|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|:---|
| **CAT-01** | **Python Core Source Files** | `.py` (backend, cyberguard) | **139** | **31,865** | 27,750 | 1,216 | 2,899 | AST Parse & LOC Inventory (`loc_inventory.json`) |
| **CAT-02** | **Python Verification Test Suite** | `.py` (tests/, report/tests/) | **44** | **9,682** | 7,756 | 1 | 1,925 | AST Parse & LOC Inventory (`loc_inventory.json`) |
| **CAT-03** | **Web Frontend Telemetry UI** | `.html`, `.css`, `.js` (frontend/) | **13** | **6,917** | 6,223 | 184 | 510 | Static Inventory (`loc_inventory.json`) |
| **CAT-04** | **Documentation & Configuration** | `.md`, `.json`, `.ini`, `.txt`, `.yaml` | **31** | **12,606** | 11,816 | 253 | 537 | Static Inventory (`loc_inventory.json`) |
| **CAT-05** | **Operational & Automation Scripts** | `.sh`, `.bat`, `.ps1` (scripts/) | **8** | **617** | 513 | 30 | 74 | Static Inventory (`loc_inventory.json`) |
| **CAT-06** | **Datasets, Raw Fixtures & Binary Assets** | `.csv`, `.pcap`, `.pkl`, `.bin`, `.pt` | **64** | **51,420** | 49,053 | 640 | 1,727 | File Header & Byte Audit (`loc_inventory.json`) |
| **TOTAL** | **Complete Repository Workspace** | **All 299 Repository Files** | **299** | **113,107** | **103,111** | **2,324** | **7,672** | **Sum Assertion Check: 299 Files, 113,107 Lines** |

---

<div class="page-break"></div>

## REFERENCES: Verified Academic and Standards Bibliography

The complete, verified academic bibliography is compiled directly from `report/references.json` and rendered in strict accordance with the IEEE Citation Style. Every listed citation has been verified against official digital object identifiers (DOIs) or authoritative standards registries with live evidence. Each cited source is cross-linked bidirectionally to its appearances within the dissertation.

<!-- BIBLIOGRAPHY_SLOT -->
