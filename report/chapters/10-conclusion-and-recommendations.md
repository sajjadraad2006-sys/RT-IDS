# CHAPTER 10: RECOMMENDATIONS, FUTURE WORK, AND CONCLUSION

## 10.1 Synthesis of Critical Findings

This thesis has presented an exhaustive, empirical, and architectural evaluation of the **CyberGuard Real-Time Intrusion Detection and Autonomous Containment System**. By executing rigorous code forensics, static AST dependency mapping, and reproducible empirical benchmarks across five dedicated test harnesses, we evaluated the system against both its published specifications and foundational network security principles.

### 10.1.1 Architectural Strengths
Our audit identified notable architectural strengths within the codebase:
1. **High Ingestion Efficiency:** The standalone user-space packet parser in `LiveFlowSniffer` achieves a sustained in-memory parsing throughput of **718,569 packets per second** (1.392 $\mu\text{s}$ per packet) in single-threaded user space on synthetic frames. While this provides sufficient headroom for medium and standard MTU-sized Gigabit traffic (Table VIII-B), it represents an in-memory parsing upper bound (excluding kernel syscalls, queue contention, feature extraction, and ML inference) and falls short of line rate for minimum 64-byte frames (1.488 Mpps).
2. **Deterministic Flow Lifecycle Management:** The `FlowRecord` finite state machine correctly manages bidirectional connection tracking, absorbing trailing teardown ACKs without spawning phantom sessions and supporting early micro-window feature extraction for rapid attack classification (Table VII).
3. **Defense-in-Depth Model Integrity:** CyberGuard acknowledges the inherent risks of Python pickle deserialization, enforcing pre-deserialization SHA-256 checksum validation, non-symlink verification, and schema hash binding in `validate_artifact_bundle()` prior to loading serialized model weights (Fig. 22).
4. **Formal Containment Safety Interlocks:** The formal safety verification gate (`FormalSafetyVerifier`) successfully intercepts destructive containment actions, preventing self-denial-of-service against loopback addresses, default gateways, public DNS resolvers, critical operating system processes, and neutralizing shell injection attempts (Table XIV).
5. **Human-in-the-Loop Safeguards:** For live containment enforcement, the `ActuatorRouter` strictly enforces the Two-Person Rule, requiring distinct initiator and approver identities and generating cryptographically signed HMAC-SHA256 rollback receipts for atomic state reversion (Fig. 23).

### 10.1.2 Critical Architectural Vulnerabilities and Model Findings
Our empirical evaluations across both model pipelines uncovered critical vulnerabilities that preclude production deployment:
1. **The Synthetic Training Fixture Trap (Bundled Model):** The shipped XGBoost classifier was trained exclusively on a synthetic, parametric sample dataset (`artifacts.json: production_approved=false`, seed 42) spanning only four basic classes. When evaluated against real network traffic, the model collapses down to **38.15% accuracy and 0.0757 Macro-$F_1$**, while falsely flagging **55.07% of all benign flows as attacks** (189,977 false alarms out of 344,984 clean flows), proving that synthetic fixtures provide zero real-world operational protection.
2. **The Candidate Real-Data Model Reality (`candidate_cicids2017`):** While trained on 2,096,796 real flows from CICIDS2017, the candidate pipeline remains strictly unpromoted (`shadow_only_not_promoted, production_approved=false`). Although its headline accuracy (0.9849) and Weighted-$F_1$ (0.9855) appear high, they are heavily masked by the 84.8% prevalence of Benign traffic. Unweighted Macro-$F_1$ reaches only **0.6852** [95% CI: 0.6447, 0.7133], unmasking fatal operational blind spots: **complete detection collapse on Botnet C2 traffic** (0.00% recall, 0.00 $F_1$; 113/113 flows missed) and severe precision collapse on PortScan (0.1862).
3. **Four Critical Methodological Decisions:**
   - *Decision D1 (Conflicting Duplicate Policy):* `backend/detection/trainer.py:221-254` silently resolves 6,132 exact and 3,228 near conflicting duplicate groups by first-seen CSV order, injecting arbitrary order-dependent label bias while relaxing promotion gates (`candidate_workflow.py:766-768`).
   - *Decision D2 (Within-Session Split Optimism):* The `capture_group` split slices each capture session into 5 contiguous row blocks, masking a **65.69% silent miss rate on novel attacks** exposed under true day-disjoint temporal evaluation (Mon–Wed train vs. Thu–Fri test).
   - *Decision D3 (Autoencoder Truncation Anomaly):* Training the PyTorch autoencoder strictly on the first 100,000 benign flows creates multi-day temporal drift, causing benign test traffic to exhibit higher mean reconstruction error ($11,488$) than attack traffic ($4,126$), inverting the anomaly detection signal.
   - *Decision D4 (Train/Serve Feature Skew):* The candidate model expects 32 features, but the live sniffer hardcodes `active_mean` and `idle_mean` to 0.0 and cannot extract initial TCP window sizes, collapsing candidate Macro-$F_1$ from 0.6852 down to **0.3668** (40.79% attack miss rate). Under Suricata approximations, the attack miss rate surges to **98.59%**.
4. **Autoencoder Calibration Collapse (Bundled Model):** Due to an unscaled feature mismatch between data pre-processing and model evaluation, the bundled deep PyTorch autoencoder exhibits an empirical reconstruction error nine orders of magnitude above its calibrated threshold ($8.1 \times 10^9$ vs. $0.004597$), **flagging 100.0% of all flows as anomalous** and corrupting downstream risk-based routing (Table XII).
5. **OS Raw Socket Limitations:** On Linux, the sniffer binds an `AF_INET` socket with `IPPROTO_TCP`, capturing only inbound TCP traffic and completely blinding the system to link-layer frames, outbound flows, UDP floods, and ICMP probes. On Windows, binding `0.0.0.0` is silently coerced to `127.0.0.1`, and IPv6 frames are discarded universally (Chapter 4).
6. **Loopback Administrative Elevation:** In non-production environments where `CG_ENFORCE_AUTH != "true"`, any unauthenticated client connecting over loopback is automatically elevated to `Role.ADMIN`, creating severe exposure to SSRF and browser-based cross-site port attacks (Chapter 7).
7. **The 40/40 False Positive Disaster & Latency Bottleneck:** Unconditional top-$k$ RAG retrieval coupled with a flawed severity heuristic in `universal_parser.py` and over-suppression in `engine.py` caused a 100% false positive rate on benign administrative scripts, while the local LLM advisory path incurred an unworkable median decision latency of $P_{50} = 27.55$ seconds (Chapter 8).
8. **Core Scientific Limitations:** The real-data evaluation is bounded by five unavoidable constraints: (i) reliance on a third-party Hugging Face mirror with unverified upstream University of New Brunswick checksums; (ii) documented labeling and flow bugs inherent to CICIDS2017 {{cite:engelen2021troubleshooting}}; (iii) microscopic support for critical minority classes (Infiltration $N=7$); (iv) lack of cross-dataset generalization against a secondary benchmark (such as CSE-CIC-IDS2018); and (v) absence of live end-to-end packet PCAP replay to confirm Java-vs-Python feature equivalence.

---

## 10.2 System Hardening Roadmap

To transition CyberGuard from an academic prototype to an enterprise-grade defense platform, we outline a prioritized technical remediation roadmap in Table XX.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XX.</b> PRIORITIZED CYBERGUARD HARDENING AND REMEDIATION ROADMAP
</div>

| Subsystem / Layer | Priority | Technical Vulnerability / Architectural Gap | Concrete Hardening Recommendation | Implementation Target |
|:---|:---:|:---|:---|:---|
| **Model Integrity** | **CRITICAL** | Manifest `artifacts.json` is unsigned; local attacker can recalculate hashes | Sign manifest using Ed25519 asymmetric cryptography; verify against embedded public key | `backend/detection/integrity.py` |
| **Authentication** | **CRITICAL** | Loopback clients automatically elevated to `Role.ADMIN` when unauthenticated | Eliminate loopback auto-elevation entirely; mandate bootstrap JWT credentials universally | `backend/auth.py:313-318` |
| **Model Calibration** | **CRITICAL** | Autoencoder receives unscaled raw features, flagging 100% of flows as anomalies | Pass standard scaler projection directly into autoencoder ingestion; re-calibrate $\tau_{\text{AE}}$ | `backend/detection/pipeline.py:175` |
| **Decision Engine** | **CRITICAL** | 40/40 false positives on benign admin traffic due to RAG/Severity/Guard coupling | Introduce cosine cutoff ($\tau_{\text{sim}} \ge 0.65$); decouple severity from top-$k$; restrict guard | `universal_parser.py`, `engine.py` |
| **Packet Sniffer** | **HIGH** | Linux `IPPROTO_TCP` socket captures only inbound TCP; drops UDP, ICMP, and IPv6 | Replace `socket(AF_INET, SOCK_RAW)` with `socket(AF_PACKET, SOCK_RAW)` or libpcap / AF_XDP | `backend/detection/live_sniffer.py` |
| **Suricata Bridge** | **HIGH** | Static window values ($64240/29200$) and duration dimension error (sec vs $\mu\text{s}$) | Extract true window sizes from Suricata TCP flow metadata; correct microsecond scaling | `backend/suricata/tailer.py:98-115` |
| **Safety Verifier** | **HIGH** | SymPy evaluates 4 boolean literals; no authentic SMT solver invoked | Integrate native Z3 Python API (`import z3`); execute formal relational theory over topologies | `backend/safety/formal_verifier.py` |
| **Actuator Security** | **MEDIUM** | PowerShell command assembling uses string formatting vulnerable to injection | Replace string-interpolated `-Command` with direct Win32 API calls via `ctypes` or Netsh | `backend/actuators/firewall.py` |
| **Advisory LLM** | **MEDIUM** | $P_{50} = 27.55$ s latency stalls real-time decision queue during burst attacks | Offload LLM to asynchronous background queue; decouple fast-path mitigation from LLM | `backend/decision/engine.py` |

---

## 10.3 Future Research Directions

Beyond immediate codebase remediation, the findings of this thesis motivate four vital avenues of future research:

### 10.3.1 Kernel-Bypass Packet Ingestion via eBPF and XDP
While Python raw sockets achieved 718 Kpps in user space, carrier-grade 10 Gbps and 100 Gbps interfaces process between 14.88 and 148.8 million packets per second. Future iterations of CyberGuard should migrate the packet filtering and flow state machine into the Linux kernel using **eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)** {{cite:mccanne1993bsd}}. By executing flow aggregation directly within the network interface driver before socket allocation, line-rate throughput can be sustained with zero user-kernel context switching overhead.

### 10.3.2 Non-Stationary Temporal Learning and Conformal Prediction
To overcome the synthetic data trap, future models must be trained on authentic, multi-day benchmark datasets (such as CSE-CIC-IDS2018 or UNSW-NB15) utilizing strict temporal train-test partitioning (the TESSERACT methodology {{cite:pendlebury2019tesseract}}). Furthermore, rather than relying on arbitrary confidence thresholds (e.g., $\tau_{\text{clf}} = 0.90$), models should incorporate **inductive conformal prediction**. Conformal prediction provides mathematically guaranteed coverage error bounds, allowing the detector to output prediction sets rather than point predictions and provably controlling false alarm rates under non-stationary distribution drift.

### 10.3.3 Authentic SMT-Solver Verification Over Dynamic Network Graphs
While the current verifier checks static boolean invariants, true autonomous containment requires reasoning over dynamic, multi-hop network topologies. By embedding an authentic SMT solver such as **Z3** {{cite:demoura2008z3}}, the safety subsystem can express first-order relational constraints:

$$\forall u, v \in \mathcal{V}_{\text{net}}, \quad \text{Connected}(u, v) \land \text{IsCritical}(u) \implies \neg \text{IsolatesPath}(\text{action}, u, v) \tag{10.1}$$

This guarantees that an automated firewall rule isolating an infected host never severs redundant communication paths between critical supervisory controllers and industrial field actuators.

### 10.3.4 Hardware-in-the-Loop Validation for Industrial Mechatronics
Building upon the theoretical framework established in Chapter 9, future work should deploy and benchmark the proposed **RT-M-IDS** architecture on physical mechatronic hardware. Deploying the appliance onto an experimental testbed featuring a 6-DOF industrial manipulator (e.g., KUKA KR-6 or ABB IRB-120) communicating over Modbus TCP and OPC UA will enable empirical measurement of physical deceleration profiles, bus jitter, and real-time fault injection resilience under live kinematic attacks.

---

## 10.4 Conclusion

Autonomous network defense represents the frontier of modern cybersecurity engineering. As attack automation accelerates, human security operations centers (SOCs) can no longer manually triage, investigate, and contain complex volumetric and multi-stage cyber threats within sub-second reaction windows.

However, as demonstrated throughout this thesis, the transition from human analysis to automated artificial intelligence introduces acute architectural hazards. Uncalibrated anomaly thresholds, synthetic dataset overfitting, and brittle heuristic-LLM couplings can transform an autonomous defense system into an engine of self-inflicted denial-of-service. 

The central lesson of the CyberGuard evaluation is that **machine learning classification must never act with unconstrained authority**. True operational resilience requires an uncompromising synthesis: pairing high-throughput statistical pattern recognition with formal symbolic safety gates, rigorous cryptographic integrity boundaries, and fail-safe physical interlocks. Only when machine intelligence is bounded by deterministic mathematical invariants can autonomous systems be safely entrusted with the defense of our critical digital and cyber-physical infrastructures.
