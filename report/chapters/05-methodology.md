# CHAPTER 5: METHODOLOGY AND EXPERIMENTAL DESIGN

## 5.1 Threat Modeling and Security Assumptions

Evaluating an autonomous network intrusion detection and containment system requires a formal definition of adversary capabilities, trust boundaries, and operational operational constraints. In accordance with established security engineering principles {{cite:shostack2014threat}}, we establish a threat model grounded in standard network security formalisms {{cite:dolev1983security}} and modern cyber-physical system threat taxonomies {{cite:cardenas2011attacks,stouffer2015nist80082}}.

### 5.1.1 Adversary Taxonomy and Attack Vectors
We analyze four distinct adversary classes targeting networks monitored by CyberGuard:

1. **Network-Centric External Adversary ($\mathcal{A}_{\text{net}}$):** Operates under the classical Dolev-Yao model {{cite:dolev1983security}}. $\mathcal{A}_{\text{net}}$ can eavesdrop on, intercept, synthesize, and inject arbitrary packets across untrusted network links. $\mathcal{A}_{\text{net}}$ launches high-rate Volumetric Distributed Denial of Service (DDoS) floods (UDP/SYN/ICMP amplification), horizontal/vertical reconnaissance scans (SYN/FIN/XMAS port scanning), and botnet command-and-control (C2) communication.
2. **Host-Level Compromised Entity ($\mathcal{A}_{\text{host}}$):** Represents an adversary who has gained initial user-level execution on a network endpoint. $\mathcal{A}_{\text{host}}$ attempts lateral movement, ARP spoofing, service exploitation, and exfiltration.
3. **Evasive Machine Learning Adversary ($\mathcal{A}_{\text{adv}}$):** Possesses knowledge of the statistical feature extraction pipeline (flow duration, inter-arrival times, packet sizes). $\mathcal{A}_{\text{adv}}$ crafts adversarial network flows via packet splitting, timing perturbation (packet padding, artificial inter-arrival delay), or mimicry attacks designed to evade XGBoost and Autoencoder anomaly boundaries while preserving exploit payload semantics {{cite:pierazzi2020intriguing,sommer2010outside}}.
4. **Advisory LLM Prompt Injection Adversary ($\mathcal{A}_{\text{llm}}$):** Controls untrusted input ingested by the incident response engine (e.g., DNS reverse lookup strings, HTTP User-Agent headers, Suricata signature message text). $\mathcal{A}_{\text{llm}}$ attempts indirect prompt injection {{cite:greshake2023not,liu2023prompt}} to hijack the advisory LLM's system instructions, suppress containment alarms, or induce destructive actuator commands.

### 5.1.2 Trust Boundaries and Assumptions
The trust architecture of the CyberGuard ecosystem is partitioned into three formal zones:
- **Untrusted Zone ($\mathcal{Z}_0$):** Ingested network traffic from physical interfaces, external WAN uplinks, and unverified endpoints. All packet headers and payloads are treated as untrusted, potentially malformed input.
- **Semi-Trusted Zone ($\mathcal{Z}_1$):** External integration points, including Suricata EVE-JSON log tailers, webhook receivers, and client API requests originating from web browsers. All requests traversing $\mathcal{Z}_1 \to \mathcal{Z}_2$ require cryptographic authentication (JWT) and schema validation {{cite:shostack2014threat}}.
- **Trusted Zone ($\mathcal{Z}_2$):** The core decision engine, ML inference pipeline, state cache, SQLite database, and the actuator subsystem. We assume the host OS kernel and Python runtime within $\mathcal{Z}_2$ are uncompromised, but the deserialization boundary for pre-trained model loading (`.pkl` artifacts) must enforce cryptographic integrity verification prior to execution [CE-11].

<div id="fig14-container" class="figure-container" style="width: 100%; max-width: 760px; margin: 16px auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
<svg viewBox="0 0 760 380" width="100%" height="auto" xmlns="http://www.w3.org/2000/svg" style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
  <defs>
    <linearGradient id="headerGrad14" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#334155" />
    </linearGradient>
    <marker id="arr14Blue" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#0284c7" />
    </marker>
    <marker id="arr14Red" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#ef4444" />
    </marker>
    <marker id="arr14Amber" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,1 L7,4 L0,7 Z" fill="#d97706" />
    </marker>
  </defs>

  <!-- Banner Header -->
  <rect x="0" y="0" width="760" height="34" rx="8" fill="url(#headerGrad14)" />
  <rect x="0" y="24" width="760" height="10" fill="url(#headerGrad14)" />
  <text x="380" y="22" text-anchor="middle" font-size="12" font-weight="700" fill="#ffffff" letter-spacing="0.5">
    MULTI-ZONE TRUST ARCHITECTURE &amp; DATAFLOW PIPELINE (Z0 -> Z1 -> Z2)
  </text>

  <!-- Zone 0: Untrusted -->
  <rect x="15" y="46" width="200" height="320" rx="6" fill="#fef2f2" stroke="#ef4444" stroke-width="1.5" />
  <rect x="25" y="54" width="180" height="20" rx="3" fill="#fee2e2" />
  <text x="115" y="68" text-anchor="middle" font-size="9.5" font-weight="700" fill="#991b1b">UNTRUSTED ZONE (Z0)</text>

  <g transform="translate(25, 82)">
    <rect width="180" height="60" rx="4" fill="#ffffff" stroke="#ef4444" stroke-width="1" />
    <text x="90" y="20" text-anchor="middle" font-size="9.5" font-weight="700" fill="#991b1b">Raw Network Traffic</text>
    <text x="90" y="34" text-anchor="middle" font-size="8" fill="#475569">Physical NIC / Promiscuous</text>
    <text x="90" y="46" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#dc2626">Untrusted packet stream</text>
  </g>

  <g transform="translate(25, 154)">
    <rect width="180" height="60" rx="4" fill="#ffffff" stroke="#ef4444" stroke-width="1" />
    <text x="90" y="20" text-anchor="middle" font-size="9.5" font-weight="700" fill="#991b1b">External Adversary</text>
    <text x="90" y="34" text-anchor="middle" font-size="8" fill="#475569">Volumetric DDoS / Scans</text>
    <text x="90" y="46" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#dc2626">SYN flood / Malicious payload</text>
  </g>

  <g transform="translate(25, 230)">
    <rect width="180" height="70" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
    <text x="90" y="18" text-anchor="middle" font-size="8.5" font-weight="700" fill="#475569">Security Assumption:</text>
    <text x="90" y="32" text-anchor="middle" font-size="7.5" fill="#64748b">All payloads &amp; headers</text>
    <text x="90" y="44" text-anchor="middle" font-size="7.5" fill="#64748b">are strictly untrusted and</text>
    <text x="90" y="56" text-anchor="middle" font-size="7.5" fill="#64748b">potentially adversarial.</text>
  </g>

  <!-- Connection Z0 -> Z2 Sniffer -->
  <path d="M205, 112 L225, 112 L225, 112 L435, 112" fill="none" stroke="#ef4444" stroke-width="1.8" stroke-dasharray="3,3" marker-end="url(#arr14Red)" />
  <rect x="208" y="102" width="22" height="18" rx="2" fill="#ffffff" stroke="#ef4444" stroke-width="1" />
  <text x="219" y="114" text-anchor="middle" font-size="7" font-weight="700" fill="#dc2626">Raw</text>

  <!-- Zone 1: Semi-Trusted -->
  <rect x="230" y="46" width="195" height="320" rx="6" fill="#fffbeb" stroke="#f59e0b" stroke-width="1.5" />
  <rect x="240" y="54" width="175" height="20" rx="3" fill="#fef3c7" />
  <text x="327" y="68" text-anchor="middle" font-size="9.5" font-weight="700" fill="#92400e">SEMI-TRUSTED ZONE (Z1)</text>

  <g transform="translate(240, 82)">
    <rect width="175" height="60" rx="4" fill="#ffffff" stroke="#f59e0b" stroke-width="1" />
    <text x="87" y="20" text-anchor="middle" font-size="9.5" font-weight="700" fill="#92400e">Suricata EVE-JSON</text>
    <text x="87" y="34" text-anchor="middle" font-size="8" font-family="monospace" fill="#b45309">/var/log/suricata/eve.json</text>
    <text x="87" y="46" text-anchor="middle" font-size="7.5" fill="#475569">External daemon stream</text>
  </g>

  <g transform="translate(240, 154)">
    <rect width="175" height="60" rx="4" fill="#ffffff" stroke="#f59e0b" stroke-width="1" />
    <text x="87" y="20" text-anchor="middle" font-size="9.5" font-weight="700" fill="#92400e">Web Client &amp; API</text>
    <text x="87" y="34" text-anchor="middle" font-size="8" fill="#475569">Operator browser / REST</text>
    <text x="87" y="46" text-anchor="middle" font-size="7.5" font-family="monospace" fill="#b45309">HTTP Bearer JWT</text>
  </g>

  <g transform="translate(240, 230)">
    <rect width="175" height="70" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" />
    <text x="87" y="18" text-anchor="middle" font-size="8.5" font-weight="700" fill="#475569">Security Boundary:</text>
    <text x="87" y="32" text-anchor="middle" font-size="7.5" fill="#64748b">Traversing Z1 -> Z2 requires</text>
    <text x="87" y="44" text-anchor="middle" font-size="7.5" fill="#64748b">JWT auth &amp; strict Pydantic</text>
    <text x="87" y="56" text-anchor="middle" font-size="7.5" fill="#64748b">InputContract validation.</text>
  </g>

  <!-- Connection Z1 -> Z2 Ingestion -->
  <path d="M415, 112 L435, 112" fill="none" stroke="#d97706" stroke-width="1.8" marker-end="url(#arr14Amber)" />
  <path d="M415, 184 L435, 184" fill="none" stroke="#d97706" stroke-width="1.8" marker-end="url(#arr14Amber)" />

  <!-- Zone 2: Trusted Execution Core -->
  <rect x="440" y="46" width="305" height="320" rx="6" fill="#f0f9ff" stroke="#0284c7" stroke-width="1.5" />
  <rect x="450" y="54" width="285" height="20" rx="3" fill="#e0f2fe" />
  <text x="592" y="68" text-anchor="middle" font-size="9.5" font-weight="700" fill="#0369a1">TRUSTED CORE EXECUTION ZONE (Z2)</text>

  <!-- Block 1: Ingestion & Contracts -->
  <g transform="translate(450, 80)">
    <rect width="285" height="70" rx="4" fill="#ffffff" stroke="#0284c7" stroke-width="1.2" />
    <text x="142" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#0369a1">Ingestion &amp; Normalization Layer</text>
    
    <rect x="8" y="24" width="85" height="38" rx="3" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
    <text x="50" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#0f172a">LiveFlowSniffer</text>
    <text x="50" y="50" text-anchor="middle" font-size="6.5" font-family="monospace" fill="#0284c7">Raw 5-tuple</text>

    <rect x="100" y="24" width="85" height="38" rx="3" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
    <text x="142" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#0f172a">SuricataTailer</text>
    <text x="142" y="50" text-anchor="middle" font-size="6.5" font-family="monospace" fill="#0284c7">EVE Adapter</text>

    <rect x="192" y="24" width="85" height="38" rx="3" fill="#f8fafc" stroke="#94a3b8" stroke-width="1" />
    <text x="234" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#0f172a">InputContract</text>
    <text x="234" y="50" text-anchor="middle" font-size="6.5" font-family="monospace" fill="#0284c7">Pydantic Gate</text>
  </g>

  <path d="M592, 150 L592, 164" stroke="#0284c7" stroke-width="1.5" marker-end="url(#arr14Blue)" />

  <!-- Block 2: Detection Triad -->
  <g transform="translate(450, 166)">
    <rect width="285" height="74" rx="4" fill="#ffffff" stroke="#0284c7" stroke-width="1.2" />
    <text x="142" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#0369a1">Multi-Stage Detection Engine (Pipeline v2)</text>
    
    <rect x="8" y="24" width="85" height="42" rx="3" fill="#eff6ff" stroke="#3b82f6" stroke-width="1" />
    <text x="50" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#1e3a8a">XGBoost (32-F)</text>
    <text x="50" y="50" text-anchor="middle" font-size="7" fill="#2563eb">Known-attack clf</text>
    <text x="50" y="60" text-anchor="middle" font-size="6.5" fill="#475569">[CE-08]</text>

    <rect x="100" y="24" width="85" height="42" rx="3" fill="#eff6ff" stroke="#3b82f6" stroke-width="1" />
    <text x="142" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#1e3a8a">Autoencoder</text>
    <text x="142" y="50" text-anchor="middle" font-size="7" fill="#2563eb">PyTorch MSE Loss</text>
    <text x="142" y="60" text-anchor="middle" font-size="6.5" fill="#475569">[CE-10]</text>

    <rect x="192" y="24" width="85" height="42" rx="3" fill="#eff6ff" stroke="#3b82f6" stroke-width="1" />
    <text x="234" y="38" text-anchor="middle" font-size="7.5" font-weight="700" fill="#1e3a8a">Risk Router</text>
    <text x="234" y="50" text-anchor="middle" font-size="7" fill="#2563eb">Deterministic</text>
    <text x="234" y="60" text-anchor="middle" font-size="6.5" fill="#475569">[CE-11]</text>
  </g>

  <path d="M592, 240 L592, 254" stroke="#0284c7" stroke-width="1.5" marker-end="url(#arr14Blue)" />

  <!-- Block 3: Safety Interlocks -->
  <g transform="translate(450, 256)">
    <rect width="285" height="98" rx="4" fill="#ffffff" stroke="#16a34a" stroke-width="1.5" />
    <text x="142" y="16" text-anchor="middle" font-size="9" font-weight="700" fill="#14532d">Safety Interlocks &amp; Autonomous Actuation</text>
    
    <rect x="8" y="24" width="130" height="66" rx="3" fill="#f0fdf4" stroke="#86efac" stroke-width="1" />
    <text x="73" y="38" text-anchor="middle" font-size="8" font-weight="700" fill="#166534">Formal Safety Verifier</text>
    <text x="73" y="50" text-anchor="middle" font-size="7" fill="#475569">SymPy Invariants I1 - I4</text>
    <text x="73" y="62" text-anchor="middle" font-size="7" fill="#475569">Advisory LLM SmartDecision</text>
    <text x="73" y="74" text-anchor="middle" font-size="7" font-weight="600" fill="#15803d">[CE-18] Gatekeeper</text>

    <rect x="146" y="24" width="131" height="66" rx="3" fill="#f0fdf4" stroke="#86efac" stroke-width="1" />
    <text x="211" y="38" text-anchor="middle" font-size="8" font-weight="700" fill="#166534">System Actuators</text>
    <text x="211" y="50" text-anchor="middle" font-size="7" fill="#475569">Host Firewall (Netsh/iptables)</text>
    <text x="211" y="62" text-anchor="middle" font-size="7" fill="#475569">SIGSTOP Process Freeze</text>
    <text x="211" y="74" text-anchor="middle" font-size="7" font-weight="600" fill="#15803d">[CE-48] Two-Person Rule</text>
  </g>
</svg>
</div>
<div class="figure-caption"><strong>Fig. 14.</strong> Multi-zone trust architecture and dataflow pipeline across untrusted network inputs, semi-trusted perimeter ingestion, and the trusted execution core.</div>

---

## 5.2 Dataset Provenance, Dual-Model Architecture, and Ground Truth

A critical challenge in modern network intrusion detection research is the acquisition, verification, and calibration of realistic, unbiased training and benchmark data {{cite:ring2019survey,sommer2010outside,arp2022dos}}. In our technical audit of CyberGuard, we identify and rigorously separate two distinct model pipelines present within the repository:
1. **The Bundled Synthetic Model (`data/models/trained/`):** Shipped with the initial repository release, trained on an artificial parametric 4-class sample fixture and retained exclusively as an in-tree evaluation fixture.
2. **The Real-Data Candidate Pipeline (`data/models/candidate_cicids2017/`):** Introduced via `scripts/train_cicids2017.py`, trained on the canonical CICIDS2017 benchmark dataset spanning 8 classes, and retained strictly in shadow evaluation mode (`shadow_only_not_promoted, production_approved=false`).

### 5.2.1 Provenance of Bundled Synthetic Fixture Artifacts
The pre-trained model weights under `data/models/trained/` operate alongside a deterministic evaluation fixture (`data/samples/sample_flows.csv`). We audited the model metadata manifest [`data/models/trained/artifacts.json`](data/models/trained/artifacts.json#L1-L38) [CE-01]:

```json
{
  "production_approved": false,
  "evaluation_only": true,
  "independent_test_split": false,
  "classes": ["Benign", "Bot", "DDoS", "PortScan"],
  "feature_count": 32,
  "normalization_method": "standard_scaler"
}
```

The manifest explicitly declares `production_approved = false` and `independent_test_split = false`. Inspection of [`cyberguard/datasets/generate_sample.py`](cyberguard/datasets/generate_sample.py#L34-L65) [CE-02] confirms that the underlying fixture was generated via synthetic parametric statistical distributions initialized with a hardcoded pseudorandom seed:

$$\text{Seed} = 42 \quad (\text{numpy.random.seed(42)})$$

The synthetic generator produces 2,000 flows structured as follows:
- **Benign Traffic ($N=1,600$, 80.0%):** Flow durations sampled uniformly over $[0.5, 30.0]$ s, packet rates drawn from $\mathcal{N}(50, 15^2)$ pkts/s, inter-arrival times sampled log-normally.
- **DDoS Floods ($N=200$, 10.0%):** Packet rates drawn from high-intensity distributions $\mathcal{U}(1000, 50000)$ pkts/s, forward inter-arrival time mean $< 100\ \mu\text{s}$, backward packet count collapsed to zero (unidirectional SYN/UDP floods).
- **PortScan Probing ($N=100$, 5.0%):** Flow durations clamped to micro-windows $[0.001, 0.05]$ s, packet count fixed to $1 \le N_{\text{pkt}} \le 3$, SYN flag set, ACK/FIN absent.
- **Botnet C2 ($N=100$, 5.0%):** Regularized periodic beaconing flows characterized by low inter-arrival variance ($\sigma_{\text{IAT}} \approx 0$) and fixed byte payloads.

### 5.2.2 Provenance of Real-World CICIDS2017 Dataset Artifacts
The candidate model pipeline relies on the Canadian Institute for Cybersecurity CICIDS2017 benchmark dataset {{cite:sharafaldin2018toward}}. To establish empirical provenance, we audited the dataset ingestion manifest [`cyberguard/datasets/cicids2017_real_manifest.json`](cyberguard/datasets/cicids2017_real_manifest.json#L1-L125) and executed an independent byte-and-hash audit across all constituent CSV files via `report/experiments/exp_provenance_audit.py`:

1. **Third-Party Mirror Origin:** The manifest declares that all 8 CSV files were retrieved from a Hugging Face mirror repository (`https://huggingface.co/datasets/bencorn/CICIDS2017`). 
2. **Provenance Meaning of `observed_unb_archive_checksum`:** The manifest records the field `checksum_provenance: "observed_unb_archive_checksum"`. In the repository's download script, this string denotes the SHA-256 digest observed directly from the extracted archive on the Hugging Face mirror. Crucially, the official University of New Brunswick (UNB) repository web portal does not provide direct, machine-verifiable single-file HTTPS SHA-256 manifests for these specific extracted CSV tables without human form interactions. Consequently, cryptographic integrity between this third-party mirror and the original 2017 UNB generation is formally unverified. We state plainly that the experimental data originates from a third-party mirror.
3. **Recomputed Volume and Integrity Verification:** Our audit verified that all 8 local CSV files match the manifest's expected SHA-256 hashes and byte counts exactly (100.0% match), encompassing 2,830,743 raw rows (2,830,555 non-null rows; 529,918 Monday, 445,909 Tuesday, 692,703 Wednesday, 458,968 Thursday, and 703,245 Friday flows).
4. **Known Flaws in CICIDS2017:** As documented extensively by Engelen et al. {{cite:engelen2021troubleshooting}}, CICIDS2017 contains severe structural flaws: erroneous flow volume calculations within `CICFlowMeter`, negative flow durations, inverted flow directions, mislabeled attack windows (particularly Web Attacks), and massive feature duplication. These documented deficiencies directly impact downstream model training and evaluation.

### 5.2.3 Dataset Label Mapping and Sanitization
Raw network captures in CICIDS2017 contain 15 distinct textual labels, several of which exhibit UTF-8 encoding corruption or microscopic sample representation. In [`backend/detection/trainer.py:53-73`](backend/detection/trainer.py#L53-L73) [CE-05], the candidate ingestion engine applies a deterministic label normalization map:
- **DoS Variants & Heartbleed $\to$ `DoS`:** Combines `DoS slowloris`, `DoS Slowhttptest`, `DoS Hulk`, `DoS GoldenEye`, and `Heartbleed` into a unified `DoS` class.
- **Web Attack Variants $\to$ `WebAttack`:** Normalizes UTF-8 encoding anomalies (specifically non-breaking hyphen glitches such as `Web Attack \x96 Brute Force`, `Web Attack \x96 XSS`, and `Web Attack \x96 Sql Injection`) into a single `WebAttack` class.
- **Brute Force & Infiltration:** Combines `FTP-Patator` and `SSH-Patator` into `BruteForce`, and retains `Infiltration`, `Bot`, and `PortScan`.
- **Target Taxonomy:** The resulting candidate taxonomy comprises exactly 8 discrete classes: `Benign`, `Bot`, `BruteForce`, `DoS`, `Infiltration`, `PortScan`, `WebAttack`, and `Other`.

### 5.2.4 Methodological Decisions in the Candidate Workflow
Our static code audit of `backend/detection/trainer.py` and `backend/detection/candidate_workflow.py` uncovered four central methodological decisions governing model training and validation:

1. **Decision D1: Silent Resolution of Conflicting Duplicates and Relaxed Promotion Gate:**
   In earlier iterations of the codebase, `backend/detection/trainer.py` raised an `IntegrityError` if duplicate feature vectors possessed conflicting ground-truth labels. In the current implementation ([`backend/detection/trainer.py:221-254`](backend/detection/trainer.py#L221-L254) [CE-05]), this error check was removed. Conflicting duplicate rows are now silently resolved by first-seen CSV row order. In the real dataset, our re-audit identified 6,132 exact duplicate feature groups with conflicting labels (14,484 rows) and 3,228 near-duplicate groups with conflicting labels (7,688 rows), dropping 733,947 total duplicate rows. Concurrently, the candidate promotion gate `no_exact_or_near_conflicting_label_duplicates` in [`backend/detection/candidate_workflow.py:766-768`](backend/detection/candidate_workflow.py#L766-L768) [CE-43] was relaxed to check only that the train and test row-hash sets are mutually disjoint, rather than verifying the absence of label contradictions in the dataset.
2. **Decision D2: Within-Session "capture_group" Split Optimism:**
   Rather than employing a temporal or day-disjoint split, the candidate training pipeline ([`backend/detection/trainer.py:192-195`](backend/detection/trainer.py#L192-L195) [CE-05]) partitions each `(capture_file, class)` stratum into 5 contiguous row-order blocks, holding out the final 20% block for evaluation. This creates a within-session interleaved holdout where the model tests on flows from the same capture sessions on which it was trained. Furthermore, this partitioning assumes that CSV row order corresponds strictly to chronological time, despite `time_range = null` in the manifest.
3. **Decision D3: Autoencoder Truncation to First 100,000 Benign Rows:**
   The unsupervised deep PyTorch autoencoder is trained strictly on the first 100,000 benign rows encountered in row order ([`backend/detection/trainer.py:410-415`](backend/detection/trainer.py#L410-L415) [CE-05]), rather than a uniform or stratified sample across the full capture timeline. Because traffic patterns drift across days, this truncation introduces severe temporal bias.
4. **Decision D4: Train/Serve Feature Skew:**
   The 32 statistical serving features include `active_mean`, `idle_mean`, and initial TCP window parameters (`init_win_bytes_fwd`, `init_win_bytes_bwd`). In live serving, the project's own packet sniffer ([`cyberguard/detection/live_sniffer.py:234-235`](cyberguard/detection/live_sniffer.py#L234-L235) [CE-04]) hardcodes `active_mean` and `idle_mean` to `0.0`. In the Suricata EVE bridge ([`cyberguard/suricata/tailer.py:111-124`](cyberguard/suricata/tailer.py#L111-L124) [CE-06]), initial window sizes are defaulted to synthetic constants (`64240.0` and `29200.0`), while `active_mean` is approximated as the total flow duration.

---

## 5.3 Metric Formulations and Mathematical Foundations

To eliminate ambiguity and ensure reproducibility across heterogeneous test harnesses, we define all evaluation metrics using standard statistical formulations.

### 5.3.1 Classification Performance Metrics
Let $\mathcal{C}$ denote the evaluated class taxonomy: for the bundled fixture model, $K = |\mathcal{C}_{\text{synth}}| = 4$ ($\mathcal{C}_{\text{synth}} = \{\text{Benign}, \text{Bot}, \text{DDoS}, \text{PortScan}\}$); for the candidate real-data pipeline, $K = |\mathcal{C}_{\text{real}}| = 8$ ($\mathcal{C}_{\text{real}} = \{\text{Benign}, \text{Bot}, \text{BruteForce}, \text{DoS}, \text{Infiltration}, \text{PortScan}, \text{WebAttack}, \text{Other}\}$). For any class $c \in \mathcal{C}$, let $TP_c, FP_c, TN_c, FN_c$ represent true positives, false positives, true negatives, and false negatives, respectively, calculated via one-vs-rest reduction:

```mermaid
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
```
<div style="text-align: center; margin-top: 8px; margin-bottom: 24px;">
<b>Fig. 15.</b> Mathematical confusion matrix mapping and metric derivation topology for multi-class flow classification.
</div>

The classification metrics are defined as follows:

- **Per-Class Precision ($P_c$):** The proportion of positive identifications that were correct:
  $$P_c = \frac{TP_c}{TP_c + FP_c} \tag{5.1}$$

- **Per-Class Recall / True Positive Rate ($R_c$ / $\text{TPR}_c$):** The proportion of actual positives correctly identified:
  $$R_c = \frac{TP_c}{TP_c + FN_c} \tag{5.2}$$

- **False Positive Rate ($\text{FPR}_c$):** The probability of falsely rejecting a benign condition (critical for preventing operator alert fatigue {{cite:axelsson2000base}}):
  $$\text{FPR}_c = \frac{FP_c}{FP_c + TN_c} \tag{5.3}$$

- **Per-Class $F_1$-Score ($F_{1,c}$):** The harmonic mean of precision and recall:
  $$F_{1,c} = 2 \cdot \frac{P_c \cdot R_c}{P_c + R_c} = \frac{2 \cdot TP_c}{2 \cdot TP_c + FP_c + FN_c} \tag{5.4}$$

- **Macro-Averaged $F_1$-Score ($F_{1,\text{macro}}$):** Evaluates overall balance across all classes, giving equal weight to minority and majority attack vectors:
  $$F_{1,\text{macro}} = \frac{1}{K} \sum_{c \in \mathcal{C}} F_{1,c} \tag{5.5}$$

- **Weighted-Averaged $F_1$-Score ($F_{1,\text{weighted}}$):** Weights per-class scores by their empirical class support $N_c$:
  $$F_{1,\text{weighted}} = \sum_{c \in \mathcal{C}} \frac{N_c}{N} F_{1,c} \tag{5.6}$$
  *Critical Methodological Caveat:* In highly imbalanced network datasets where Benign flows account for >80% of all observations, $F_{1,\text{weighted}}$ is dominated by the Benign class. A model that completely fails to detect critical minority attacks can still post a deceptively high Weighted-$F_1$ (>0.98). Therefore, Macro-$F_1$ and Weighted-$F_1$ must be evaluated side-by-side.

- **Attack Miss Rate ($\text{AMR}$):** The fraction of malicious flows falsely classified as Benign:
  $$\text{AMR} = \frac{\sum_{c \in \text{Attacks}} N_{c \to \text{Benign}}}{\sum_{c \in \text{Attacks}} N_c} \tag{5.7}$$

- **Benign False Alarm Rate ($\text{BFAR}$):** The fraction of benign flows falsely flagged as attacks:
  $$\text{BFAR} = \frac{\sum_{c \in \text{Attacks}} N_{\text{Benign} \to c}}{N_{\text{Benign}}} \tag{5.8}$$

- **Expected Calibration Error ($\text{ECE}$):** Partitions confidence predictions $\hat{p} \in [0, 1]$ into $M = 10$ equi-width bins $B_m$:
  $$\text{ECE} = \sum_{m=1}^{M} \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right| \tag{5.9}$$

- **Overall Accuracy ($\text{Acc}$):**
  $$\text{Acc} = \frac{\sum_{c \in \mathcal{C}} TP_c}{N} \tag{5.10}$$

### 5.3.2 Latency Percentiles and Throughput
Network intrusion detection requires strict sub-millisecond to low-millisecond response guarantees to avert buffer overflows and maintain line-rate inspection:

- **Empirical Latency Percentile ($P_k$):** For an ordered sequence of measured latency samples $L = \{l_{(1)}, l_{(2)}, \dots, l_{(N)}\}$ where $l_{(i)} \le l_{(i+1)}$, the $k$-th percentile latency $P_k$ is calculated using linear interpolation:
  $$q = \frac{k}{100} \cdot (N - 1) + 1, \quad i = \lfloor q \rfloor, \quad \theta = q - i \tag{5.11}$$
  $$P_k = (1 - \theta) \cdot l_{(i)} + \theta \cdot l_{(i+1)} \tag{5.12}$$
  We evaluate $P_{50}$ (median), $P_{90}$, $P_{95}$, and $P_{99}$ (tail latency).

- **Inspection Throughput:** Expressed in processed flows per second ($\text{FPS}$) and raw packets per second ($\text{PPS}$):
  $$\text{FPS} = \frac{N_{\text{flows}}}{\Delta t_{\text{total}}}, \quad \text{PPS} = \frac{N_{\text{packets}}}{\Delta t_{\text{sniff}}} \tag{5.13}$$

### 5.3.3 Autoencoder Anomaly Scoring
The deep autoencoder comprises an encoder $f_{\theta}: \mathbb{R}^{32} \to \mathbb{R}^8$ and a symmetric decoder $g_{\phi}: \mathbb{R}^8 \to \mathbb{R}^{32}$. For a standardized input vector $\mathbf{x} \in \mathbb{R}^{32}$, the reconstructed vector is:

$$\hat{\mathbf{x}} = g_{\phi}(f_{\theta}(\mathbf{x})) \tag{5.14}$$

The anomaly score $E(\mathbf{x})$ is defined as the Mean Squared Error (MSE) across the 32 normalized feature dimensions:

$$E(\mathbf{x}) = \frac{1}{32} \sum_{i=1}^{32} (x_i - \hat{x}_i)^2 \tag{5.15}$$

A flow is flagged as an anomaly if its reconstruction error exceeds the calibrated threshold $\tau_{\text{AE}}$:

$$\text{Anomaly}(\mathbf{x}) = \begin{cases} 1, & \text{if } E(\mathbf{x}) > \tau_{\text{AE}} \\ 0, & \text{otherwise} \end{cases} \tag{5.16}$$

In the committed model metadata, $\tau_{\text{AE}}$ is set to $0.004597$ [CE-01].

---

## 5.4 Empirical Experimental Setup and Harness Architecture

All empirical evaluations were executed on a dedicated local testbed. Table VI summarizes the hardware configuration and software dependency environment.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE VI.</b> SYSTEM TESTBED SPECIFICATIONS AND DEPENDENCY MATRIX
</div>

| Subsystem | Specification / Parameter | Version / Value | Verifiable Source |
|:---|:---|:---|:---|
| **Host Processor** | AMD64 Family 25 Model 117 Stepping 2 (12 cores) | Base 2.4 GHz, Boost 5.0 GHz | Host Architecture |
| **System Memory** | DDR5 Synchronous RAM | 16,384 MB (16 GB) | Host Architecture |
| **Operating System** | Microsoft Windows 11 Enterprise (x86_64) | NT Build 26300 | OS Information |
| **Kernel Subsystem** | Win32 Sockets & WSL2 Linux Subsystem | WinSock2 / Linux 5.15 | OS Architecture |
| **Python Runtime** | CPython Interpreter (64-bit) | 3.12.10 | `python --version` |
| **Node.js Runtime** | Node.js JavaScript Engine | v22.13.1 (npm 10.9.2) | `node --version` |
| **Machine Learning Core** | PyTorch (PyTorch-CUDA / CPU) | 2.6.0+cu126 | PyTorch Manifest |
| **Gradient Boosting** | XGBoost C++ Optimized Library | 2.1.4 | Python Package Index |
| **Statistical Framework** | Scikit-Learn | 1.6.1 | `sklearn.__version__` |
| **Symbolic Mathematics** | SymPy (Propositional Logic) | 1.13.3 | `sympy.__version__` |
| **Data Processing** | NumPy / Pandas DataFrames | 2.1.3 / 2.2.3 | Python Package Index |
| **Web Framework** | FastAPI / Uvicorn ASGI Server | 0.115.0 / 0.30.6 | Python Package Index |

### 5.4.1 Dedicated Experimental Scripts
To guarantee complete reproducibility without modifying production source code, eleven independent test harness scripts were engineered under `report/experiments/`:

1. **`exp_p3a_pytest.py`:** Collects test items via AST static parsing and executes the full dynamic test suite using `pytest -v --json-report`. Records passed, failed, skipped, and total test counts. Output saved to `report/results/pytest_run.json`.
2. **`exp_p3b_sniffer.py`:** Unit and behavioral benchmark harness for `LiveFlowSniffer` and `FlowRecord`. Synthesizes TCP handshakes, teardown sequences, RST injections, idle timeouts (5.0 s), micro-window interim evaluations, UDP packet flows, and IPv6 dropping. Benchmarks `process_packet()` across 1,000,000 synthetic frames to measure maximum ingestion throughput (PPS). Output saved to `report/results/sniffer_experiments.json`.
3. **`exp_p3c_pipeline.py`:** Measures end-to-end inference latency and memory utilization of `CyberGuardPipelineV2` on 2,000 fixture rows across varied batch sizes ($B \in [1, 10, 50, 100, 500, 1000, 2000]$). Computes $P_{50}, P_{90}, P_{95}, P_{99}$ latency, memory deltas via `tracemalloc`, and evaluates the multi-class risk routing contingency matrix. Output saved to `report/results/pipeline_benchmarks.json`.
4. **`exp_p3d_model_eval.py`:** Evaluates the serialized bundled XGBoost classifier, standard normalizer, statistical detector, and PyTorch autoencoder. Computes multi-class precision, recall, F1, accuracy, and isolates the reconstruction error distributions across all 4 traffic categories to quantify train/serve threshold skew. Output saved to `report/results/model_evaluation_bundled.json`.
5. **`exp_p3e_robustness.py`:** Evaluates system behavior under out-of-distribution (OOD) attack labels, malformed input vectors (NaN, Inf, negative durations, out-of-bounds flag counts), formal safety verification rejection gates (blocking localhost/gateways, command injection, critical process kills), and measures classifier sensitivity curves under volumetric DDoS packet rate perturbation ($50,000 \to 100$ pkts/s). Output saved to `report/results/robustness_experiments.json`.
6. **`exp_provenance_audit.py`:** Validates byte sizes and SHA-256 cryptographic digests of all 8 raw CICIDS2017 CSV files against `cicids2017_real_manifest.json`, recomputes per-file row counts and label distributions, and verifies citation metadata. Output saved to `report/results/dataset_provenance_audit.json`.
7. **`exp_candidate_reeval.py`:** Re-derives the full evaluation battery for the real-data candidate model (`data/models/candidate_cicids2017/`) using 1,000 non-parametric bootstrap iterations for 95% confidence intervals, 10-bin expected calibration error (ECE), PR curves, abstention analysis, and three baselines (majority class, Isolation Forest, Z-score anomaly detector). Output saved to `report/results/candidate_reevaluation.json`.
8. **`exp_synthetic_real_gap.py`:** Evaluates the bundled synthetic-trained model on real CICIDS2017 network traffic under aligned label taxonomy to quantify domain transfer degradation. Output saved to `report/results/synthetic_to_real_gap.json`.
9. **`exp_day_disjoint_split.py`:** Evaluates temporal domain generalization under a strict day-disjoint protocol: models trained on Monday–Wednesday captures are tested against Thursday–Friday captures, isolating known-class accuracy from out-of-distribution unseen attack miss rates. Output saved to `report/results/day_disjoint_experiment.json`.
10. **`exp_dedup_sensitivity.py`:** Evaluates model sensitivity across three conflicting-label duplicate policies: (i) repository first-wins policy, (ii) dropping all conflicting duplicate groups, and (iii) order-shuffled first-wins across 3 seeds. Output saved to `report/results/dedup_sensitivity_experiment.json`.
11. **`exp_skew_ablation.py`:** Quantifies train/serve feature skew by evaluating candidate classifier degradation when serving features (`init_win_bytes_fwd/bwd`, `active_mean`, `idle_mean`) are forced to live sniffer defaults (0.0) or Suricata EVE bridge constants, benchmarks retrained models with zeroed features across 3 seeds, and compiles a 32-feature equivalence matrix. Output saved to `report/results/skew_ablation_experiment.json`.

---

## 5.5 Reproducibility and Statistical Protocol

To maintain scientific integrity and prevent experimental variance from biasing conclusions:

1. **Deterministic Execution:** Random seeds for all synthetic packet generators, perturbation steps, and test splits were locked to `seed = 42`.
2. **Warm-Up Iterations:** In all latency and throughput micro-benchmarks, 100 warm-up iterations were executed prior to metric collection to allow JIT compilation, CPU cache warming, and Python module lazy-import stabilization.
3. **Garbage Collection Suppression:** Python automatic garbage collection (`gc.disable()`) was temporarily disabled during tight benchmark timing loops to isolate pure algorithmic execution time from runtime collection pauses.
4. **Statistical Significance and Bootstrapping:** In addition to Wilson score intervals for proportion metrics, all multi-class classification and ablation experiments report 95% bootstrap confidence intervals ($B = 1,000$ iterations) and stochastic runs are repeated across $\ge 3$ distinct seeds reporting mean $\pm$ standard deviation. Output artifacts explicitly flag low-support classes ($N \le 100$) whose metrics lack statistical power.
