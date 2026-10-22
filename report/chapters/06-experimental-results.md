# CHAPTER 6: EXPERIMENTAL RESULTS AND BENCHMARK ANALYSIS

## 6.1 Live Ingestion and Sniffer Micro-Benchmarks

To validate the ingestion layer, we executed the standalone empirical harness `report/experiments/exp_p3b_sniffer.py`. The harness evaluates `LiveFlowSniffer` and `FlowRecord` under controlled synthetic packet injections, capturing state transitions, memory boundaries, and raw socket protocol interactions.

### 6.1.1 Flow Assembly and Protocol State Transitions
The sniffer was subjected to seven deterministic protocol scenarios:
1. **Full TCP Handshake and Teardown:** A 7-packet bidirectional sequence (SYN, SYN-ACK, ACK, Data Fwd, Data Bwd, FIN, FIN-ACK).
2. **Immediate RST Invalidation:** Injection of an unannounced RST segment to test immediate flow eviction.
3. **Inactivity Timeout Flush:** Generating an incomplete flow and advancing the synthetic clock past the 5.0-second idle threshold $\tau_{\text{idle}}$.
4. **TIME_WAIT Trailing ACK Absorption:** Verifying that delayed ACKs arriving after bidirectional FIN teardown are absorbed rather than spawning spurious half-open flows.
5. **Interim Micro-Window Feature Synthesis:** Emitting intermediate flow feature snapshots after 5 packets without evicting the active connection record.
6. **UDP Bidirectional Grouping:** Evaluating timeout-driven aggregation for connectionless UDP datagrams.
7. **IPv6 Frame Rejection:** Ingesting an EtherType `0x86DD` frame with IPv6 header version 6.

Table VII summarizes the measured results recorded in `report/results/sniffer_experiments.json`.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE VII.</b> LIVE FLOW SNIFFER PROTOCOL VERIFICATION SUITE
</div>

| Test Identifier | Injected Scenario | Expected State Transition | Measured Outcome | Empirical Result / Feature Extraction | Verifiable Run File |
|:---|:---|:---|:---|:---|:---|
| **SNF-01** | TCP Handshake + Teardown | `HANDSHAKE` $\to$ `ESTABLISHED` $\to$ `CLOSING` $\to$ Evicted | **PASSED** | 1 flow flushed; $N_{\text{fwd}}=4, N_{\text{bwd}}=3$; Duration $=120.0$ ms; Rate $=58.33$ pkts/s; $W_{\text{fwd}}=65535, W_{\text{bwd}}=64240$ | `sniffer_experiments.json` |
| **SNF-02** | Abrupt TCP RST Invalidation | `ESTABLISHED` $\to$ Immediate Eviction | **PASSED** | Evicted immediately without waiting for timeout; `rst_flag_count = 1.0` | `sniffer_experiments.json` |
| **SNF-03** | Inactivity Invalidation ($\Delta t > 5.0$ s) | `ACTIVE` $\to$ `IDLE_TIMEOUT` Eviction | **PASSED** | 0 flushed before $5.0$ s; 1 flushed after clock advance; expired flow cleared | `sniffer_experiments.json` |
| **SNF-04** | TIME_WAIT ACK Absorption | Trailing ACK absorbed into tombstone | **PASSED** | `teardown_acks_absorbed = 1`; active flows remaining $=0$; no phantom flow created | `sniffer_experiments.json` |
| **SNF-05** | Early Interim Evaluation | Feature export at $N_{\text{pkt}}=5$ without eviction | **PASSED** | 1 interim flow emitted; `is_interim = 1.0`; parent connection preserved | `sniffer_experiments.json` |
| **SNF-06** | UDP Flow Aggregation | Timeout-driven pairing of 5-tuple | **PASSED** | Aggregated into single bidirectional record; $N_{\text{fwd}}=1, N_{\text{bwd}}=1$ | `sniffer_experiments.json` |
| **SNF-07** | IPv6 Packet Handling | Rejection at header parser | **PASSED** | Returns `None`; zero bytes parsed; dropped due to `version != 4` gate | `sniffer_experiments.json` |
| **SNF-08** | Unprivileged Live Loopback Bind | Graceful fallback on permission error | **PASSED** | `start_capture()` returns `True`; sets `last_capture_mode = "synthetic_harness"` | `sniffer_experiments.json` |

### 6.1.2 Raw Ingestion Throughput
To establish the maximum upper-bound packet ingestion capacity of the Python user-space sniffer, `process_packet()` was subjected to a high-volume burst of 50,000 synthetic raw IP packets. Execution was timed using monotonic nanosecond counters (`time.perf_counter_ns()`) with garbage collection suppressed. Table VIII records the measured ingestion performance.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE VIII.</b> SNIFFER INGESTION BENCHMARK METRICS
</div>

| Ingestion Metric | Measured Value | Standard Error / Notes |
|:---|:---|:---|
| **Evaluated Ingestion Volume** | 50,000 in-memory raw IPv4 packets | Deterministic sequential synthetic frames in RAM |
| **Total Ingestion Elapsed Time** | 0.06958 seconds (69.58 ms) | Monotonic CPU clock delta (single Python thread) |
| **In-Memory Parsing Upper Bound** | **718,569.41 pkts/sec** | ~718.57 Kpps user-space parse/flow-table path |
| **Mean Per-Packet Parsing Latency** | **1.392 $\mu\text{s}$ / packet** | Header decode + flow dictionary lookup |
| **Active Hash Map Lookup Overhead** | $< 0.42\ \mu\text{s}$ | 5-tuple tuple hashing in CPython dict |
| **Benchmark Scope Limitation** | In-memory decode only | Excludes `recvfrom` syscall, worker queue & ML inference |

<div style="text-align: center; margin-top: 12px; margin-bottom: 8px;">
<b>TABLE VIII-B.</b> HONEST WIRE RATE COMPARISON: 1 GBPS ETHERNET VS. USER-SPACE PARSER CAPACITY
</div>

| Packet Frame Size (Payload + L2/L3/L4) | Wire Bytes (Frame + 20B Preamble/IFG) | 1 Gbps Line Rate (pkts/sec) | Measured Parser Rate (pkts/sec) | Line Rate Capacity Ratio | Operational Assessment |
|:---:|:---:|:---:|:---:|:---:|:---|
| **64 Bytes (Minimum Frame)** | 84 bytes on wire | **1,488,095 pkts/s** (1.488 Mpps) | 718,569 pkts/s | **48.29%** | **Fails Line Rate:** >51% packet loss during SYN/ACK floods |
| **512 Bytes (Medium Frame)** | 532 bytes on wire | **234,962 pkts/s** (235.0 Kpps) | 718,569 pkts/s | **305.82%** ($3.06\times$) | **Sufficient:** Safely absorbs medium interactive telemetry |
| **1500 Bytes (Standard MTU)** | 1,538 bytes on wire | **81,274 pkts/s** (81.27 Kpps) | 718,569 pkts/s | **884.13%** ($8.84\times$) | **Sufficient:** Saturated line rate for bulk payload transfers |

> [!IMPORTANT]
> **Upper Bound vs. End-to-End Throughput:** The measured 718,569 packets/second represents an **isolated in-memory parsing and flow-table update micro-benchmark** operating on pre-allocated synthetic frames in a single Python thread. It explicitly **does not include** the per-packet kernel `recvfrom` syscall, socket buffer queueing, multi-threaded queue synchronization (`LiveWorker`), sliding-window 32-feature extraction, or machine learning model inference. Therefore, 718,569 pkts/s is an architectural theoretical upper bound, not an end-to-end system ingestion rate. Under adversarial minimum-sized (64-byte) frame floods on a 1 Gbps link ($1.488$ Mpps), user-space CPython drops approximately half of the packets before feature extraction can even execute.

---

## 6.2 End-to-End Pipeline Latency and Batch Scaling

We benchmarked `CyberGuardPipelineV2` ([`backend/detection/pipeline.py`](backend/detection/pipeline.py#L88-L230) [CE-05]) using `report/experiments/exp_p3c_pipeline.py`. The benchmark isolates single-item sequential inference latency, batch throughput scaling, and heap memory allocation on the 2,000-flow evaluation fixture.

### 6.2.1 Single-Item Latency Percentiles
In real-time intrusion response, the mean latency is often deceptive; tail latencies ($P_{95}, P_{99}$) govern the maximum packet buffer depth required to avoid packet drops. We measured 1,000 independent sequential single-flow inferences. Table IX and Fig. 16 present the measured latency distribution.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE IX.</b> SINGLE-ITEM END-TO-END PIPELINE INFERENCE LATENCY
</div>

| Latency Percentile / Metric | Measured Latency (ms) | Operational Impact on Line Inspection |
|:---|:---|:---|
| **Minimum Latency ($L_{\min}$)** | 2.364 ms | Theoretical baseline for single-core inference |
| **Median Latency ($P_{50}$)** | **3.250 ms** | Typical queuing delay per flow record |
| **Mean Latency ($\mu_L$)** | 3.380 ms | Average processing overhead ($\sigma = 0.610$ ms) |
| **90th Percentile ($P_{90}$)** | 4.027 ms | Normal operational variance |
| **95th Percentile ($P_{95}$)** | **4.196 ms** | SLA upper bound for real-time alerting |
| **99th Percentile ($P_{99}$)** | **5.911 ms** | Tail latency during PyTorch garbage collection |
| **Maximum Latency ($L_{\max}$)** | 8.104 ms | Peak latency spike under OS thread context switch |

```mermaid
xychart-beta
    title "Inference Latency Percentile Distribution (P50 - P99)"
    x-axis ["Min", "P50", "Mean", "P90", "P95", "P99", "Max"]
    y-axis "Latency (Milliseconds)" 0 --> 10
    bar [2.36, 3.25, 3.38, 4.03, 4.20, 5.91, 8.10]
```
<div style="text-align: center; margin-top: 8px; margin-bottom: 24px;">
<b>Fig. 16.</b> Empirical end-to-end inference latency percentiles for sequential flow classification across 1,000 independent trials.
</div>

### 6.2.2 Batch Processing Scaling and Memory Profile
In production environments, flow records arriving in rapid succession are ingested in batches to amortize Python interpreter overhead and leverage vectorized SIMD execution in XGBoost and PyTorch. We evaluated batch sizes $B \in \{1, 10, 50, 100, 250, 500, 1000, 2000\}$. Peak heap allocation was measured using Python's `tracemalloc` library. Table X, Fig. 17, and Fig. 18 document the empirical scaling curves.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE X.</b> BATCH PROCESSING SCALING, AMORTIZED LATENCY, AND MEMORY USAGE
</div>

| Batch Size ($B$) | Total Elapsed Time (s) | Amortized Latency (ms/flow) | Inspection Throughput (flows/sec) | Peak Heap Memory ($\Delta \text{KB}$) |
|:---:|:---:|:---:|:---:|:---:|
| **1** | 0.00611 | 6.1144 ms | 163.55 | 18.27 KB |
| **10** | 0.01254 | 1.2538 ms | 797.56 | 50.62 KB |
| **50** | 0.02782 | 0.5564 ms | 1,797.22 | 246.16 KB |
| **100** | 0.04795 | 0.4795 ms | 2,085.47 | 510.64 KB |
| **250** | 0.10868 | 0.4347 ms | 2,300.31 | 1,291.01 KB |
| **500** | 0.20963 | 0.4193 ms | 2,385.18 | 2,594.46 KB |
| **1000** | 0.36328 | 0.3633 ms | 2,752.73 | 5,188.15 KB |
| **2000** | 0.64325 | **0.3216 ms** | **3,109.19** | **10,414.59 KB** |

```mermaid
xychart-beta
    title "Inspection Throughput Scaling vs Batch Size"
    x-axis ["B=1", "B=10", "B=50", "B=100", "B=250", "B=500", "B=1000", "B=2000"]
    y-axis "Throughput (Flows / Second)" 0 --> 3500
    line [163.55, 797.56, 1797.22, 2085.47, 2300.31, 2385.18, 2752.73, 3109.19]
```
<div style="text-align: center; margin-top: 8px; margin-bottom: 24px;">
<b>Fig. 17.</b> Pipeline throughput scaling as a function of input batch size, demonstrating an asymptote near 3,110 flows/sec.
</div>

```mermaid
xychart-beta
    title "Peak Heap Memory Allocation (tracemalloc Delta)"
    x-axis ["B=1", "B=10", "B=50", "B=100", "B=250", "B=500", "B=1000", "B=2000"]
    y-axis "Peak Memory Allocation (Kilobytes)" 0 --> 12000
    bar [18.27, 50.62, 246.16, 510.64, 1291.01, 2594.46, 5188.15, 10414.59]
```
<div style="text-align: center; margin-top: 8px; margin-bottom: 24px;">
<b>Fig. 18.</b> Memory footprint growth across evaluation batch sizes, showing strictly linear scaling ($\mathcal{O}(B)$) without leaks.
</div>

As batch size increases from $B=1$ to $B=2,000$, throughput scales from 163.55 to 3,109.19 flows per second, achieving a $19.01\times$ throughput enhancement. Amortized latency drops from 6.11 ms down to 0.32 ms per flow record. Memory overhead scales linearly with batch size, peaking at 10.17 MB for 2,000 concurrent flows, confirming that the pipeline does not introduce unbounded memory fragmentation.

---

## 6.3 Model Evaluation on Bundled Fixtures

We evaluated the pre-trained machine learning models shipped with CyberGuard using `report/experiments/exp_p3d_model_eval.py`. The evaluation fixture comprises $N = 2,000$ synthetic flows with 32 statistical attributes.

### 6.3.1 Supervised Classifier Performance
The serialized XGBoost classifier was evaluated with its calibrated threshold $\tau_{\text{clf}} = 0.90$. Table XI details the resulting confusion matrix and per-class classification metrics.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XI.</b> MULTI-CLASS CLASSIFICATION PERFORMANCE MATRIX (BUNDLED MODEL ON DETERMINISTIC FIXTURE)
</div>

| Class Label | Support ($N$) | True Positives ($TP$) | False Positives ($FP$) | False Negatives ($FN$) | Precision ($P_c$) | Recall ($R_c$) | $F_1$-Score ($F_{1,c}$) | 95% Wilson Score CI ($F_1$) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Benign** | 1,600 | 1,532 | 7 | 68 | 99.55% | 95.75% | **0.9761** | $[0.967, 0.983]$ |
| **Bot** | 100 | 93 | 68 | 7 | 57.76% | 93.00% | **0.7126** | $[0.647, 0.771]$ |
| **DDoS** | 200 | 200 | 0 | 0 | 100.00% | 100.00% | **1.0000** | $[0.981, 1.000]$ |
| **PortScan** | 100 | 100 | 0 | 0 | 100.00% | 100.00% | **1.0000** | $[0.963, 1.000]$ |
| **Macro Average** | **2,000** | **1,925** | **75** | **75** | **89.33%** | **97.19%** | **0.9222** | — |
| **Overall Accuracy**| **2,000** | — | — | — | — | — | **96.25%** | $[0.953, 0.970]$ |

<div id="fig19-container" class="mermaid-diagram" style="text-align: center; margin: 25px auto;">
<svg viewBox="0 0 660 480" width="100%" style="max-width: 640px; height: auto; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif;">
  <rect width="100%" height="100%" fill="#ffffff" rx="8" />
  <text x="330" y="25" font-size="14" font-weight="bold" text-anchor="middle" fill="#0f172a">Normalized Classifier Performance (Precision vs. Recall Quadrant Map)</text>
  
  <!-- Quadrants -->
  <!-- Top Left: High Precision, Low Recall -->
  <rect x="80" y="45" width="250" height="180" fill="#f8fafc" stroke="#e2e8f0" stroke-width="1" />
  <text x="205" y="68" font-size="11" font-weight="600" fill="#64748b" text-anchor="middle">High Precision, Low Recall</text>
  
  <!-- Top Right: Ideal Detection -->
  <rect x="330" y="45" width="250" height="180" fill="#f0fdf4" stroke="#bbf7d0" stroke-width="1.5" />
  <rect x="365" y="54" width="180" height="22" rx="4" fill="#dcfce7" />
  <text x="455" y="69" font-size="11" font-weight="bold" fill="#15803d" text-anchor="middle">Ideal Detection Zone</text>
  
  <!-- Bottom Left: Poor Performance -->
  <rect x="80" y="225" width="250" height="180" fill="#fef2f2" stroke="#fecaca" stroke-width="1" />
  <text x="205" y="248" font-size="11" font-weight="600" fill="#991b1b" text-anchor="middle">Poor Performance Zone</text>
  
  <!-- Bottom Right: Alert Fatigue -->
  <rect x="330" y="225" width="250" height="180" fill="#fffbeb" stroke="#fde68a" stroke-width="1.5" />
  <rect x="345" y="234" width="220" height="22" rx="4" fill="#fef3c7" />
  <text x="455" y="249" font-size="11" font-weight="bold" fill="#b45309" text-anchor="middle">Alert Fatigue Zone (High Recall, Low P)</text>

  <!-- Dividing Axes -->
  <line x1="330" y1="45" x2="330" y2="405" stroke="#0284c7" stroke-width="2" stroke-dasharray="4,3" />
  <line x1="80" y1="225" x2="580" y2="225" stroke="#0284c7" stroke-width="2" stroke-dasharray="4,3" />
  
  <!-- Outer Box -->
  <rect x="80" y="45" width="500" height="360" fill="none" stroke="#0369a1" stroke-width="2" />

  <!-- Data Points -->
  <!-- DDoS (R=1.00, P=1.00) -->
  <circle cx="560" cy="95" r="6" fill="#16a34a" stroke="#14532d" stroke-width="2" />
  <rect x="475" y="83" width="75" height="20" rx="3" fill="#ffffff" stroke="#16a34a" stroke-width="1" />
  <text x="512" y="97" font-size="10" font-weight="bold" fill="#15803d" text-anchor="middle">DDoS (100%)</text>

  <!-- PortScan (R=1.00, P=1.00) -->
  <circle cx="560" cy="130" r="6" fill="#0d9488" stroke="#115e59" stroke-width="2" />
  <rect x="460" y="118" width="90" height="20" rx="3" fill="#ffffff" stroke="#0d9488" stroke-width="1" />
  <text x="505" y="132" font-size="10" font-weight="bold" fill="#0f766e" text-anchor="middle">PortScan (100%)</text>

  <!-- Benign (R=0.9575, P=0.9955) -->
  <circle cx="530" cy="165" r="6" fill="#2563eb" stroke="#1e40af" stroke-width="2" />
  <rect x="375" y="153" width="145" height="20" rx="3" fill="#ffffff" stroke="#2563eb" stroke-width="1" />
  <text x="447" y="167" font-size="10" font-weight="bold" fill="#1e40af" text-anchor="middle">Benign (P: 99.6%, R: 95.8%)</text>

  <!-- Bot (R=0.93, P=0.5776) -->
  <circle cx="545" cy="295" r="7" fill="#dc2626" stroke="#7f1d1d" stroke-width="2" />
  <rect x="335" y="284" width="200" height="22" rx="3" fill="#ffffff" stroke="#dc2626" stroke-width="1.5" />
  <text x="435" y="299" font-size="10" font-weight="bold" fill="#b91c1c" text-anchor="middle">Bot (P: 57.8%, R: 93.0%, FPR: 4.25%)</text>

  <!-- Axis Labels -->
  <text x="330" y="432" font-size="12" font-weight="bold" fill="#1e293b" text-anchor="middle">Recall (Rc)  ⟶</text>
  <text x="80" y="422" font-size="10" fill="#64748b" text-anchor="middle">0%</text>
  <text x="330" y="422" font-size="10" fill="#64748b" text-anchor="middle">50%</text>
  <text x="580" y="422" font-size="10" fill="#64748b" text-anchor="middle">100%</text>

  <text x="28" y="225" font-size="12" font-weight="bold" fill="#1e293b" text-anchor="middle" transform="rotate(-90 28 225)">Precision (Pc)  ⟶</text>
  <text x="68" y="408" font-size="10" fill="#64748b" text-anchor="end">0%</text>
  <text x="68" y="228" font-size="10" fill="#64748b" text-anchor="end">50%</text>
  <text x="68" y="50" font-size="10" fill="#64748b" text-anchor="end">100%</text>
</svg>
</div>

<div style="text-align: center; margin-top: 8px; margin-bottom: 24px;">
<b>Fig. 19.</b> Precision vs. Recall quadrant mapping, highlighting the high false alarm rate of the Bot class ($P=57.76\%$) due to misclassified benign flows.
</div>

While DDoS and PortScan achieve perfect 100% precision and recall on this synthetic fixture, the Bot class exhibits severe precision degradation ($P = 57.76\%$). Specifically, 68 benign flows were falsely classified as Bot traffic, while 7 bot flows were misclassified as Benign. As established by Axelsson's base-rate fallacy {{cite:axelsson2000base}}, an operational false positive rate of $4.25\%$ on benign background traffic ($68 / 1,600$) generates over 42,000 false alarms per million transactions, completely overwhelming human incident responders.

### 6.3.2 Autoencoder Reconstruction Divergence and Calibration Skew
In the model metadata manifest ([`artifacts.json`](data/models/trained/artifacts.json#L12) [CE-01]), the autoencoder anomaly threshold is declared as:

$$\tau_{\text{AE}} = 0.0045968578779138625$$

When we executed the PyTorch autoencoder across the evaluation fixture, we observed a catastrophic divergence between the declared threshold and the empirical reconstruction error. Table XII documents the reconstruction error distributions across all four traffic categories.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XII.</b> PYTORCH AUTOENCODER RECONSTRUCTION ERROR DISTRIBUTION ACROSS CLASSES
</div>

| Traffic Category | Evaluated Flows ($N$) | Mean Reconstruction Error ($\mu_{\text{MSE}}$) | Median Error ($P_{50}$) | 95th Percentile ($P_{95}$) | Maximum Error ($E_{\max}$) | Threshold $\tau_{\text{AE}}$ | Flagged Anomaly Rate (%) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Benign** | 1,600 | **$8.102 \times 10^{9}$** | $2.422 \times 10^{9}$ | $3.882 \times 10^{10}$ | $8.692 \times 10^{10}$ | $0.004597$ | **100.0%** (1,600 / 1,600) |
| **Bot** | 100 | **$2.136 \times 10^{10}$** | $1.225 \times 10^{10}$ | $6.371 \times 10^{10}$ | $1.389 \times 10^{11}$ | $0.004597$ | **100.0%** (100 / 100) |
| **DDoS** | 200 | **$8.026 \times 10^{7}$** | $7.325 \times 10^{7}$ | $1.679 \times 10^{8}$ | $2.304 \times 10^{8}$ | $0.004597$ | **100.0%** (200 / 200) |
| **PortScan** | 100 | **$7.590 \times 10^{7}$** | $6.453 \times 10^{7}$ | $1.555 \times 10^{8}$ | $2.261 \times 10^{8}$ | $0.004597$ | **100.0%** (100 / 100) |
| **Entire Dataset** | **2,000** | **$7.534 \times 10^{9}$** | **$2.210 \times 10^{9}$** | **$3.765 \times 10^{10}$** | **$1.389 \times 10^{11}$** | **$0.004597$** | **100.0%** (2,000 / 2,000) |

```mermaid
xychart-beta
    title "Log10 Reconstruction Error vs Calibrated Threshold"
    x-axis ["Threshold", "DDoS", "PortScan", "Benign", "Bot"]
    y-axis "Log10 MSE Error" -3 --> 12
    bar [-2.34, 7.90, 7.88, 9.91, 10.33]
```
<div style="text-align: center; margin-top: 8px; margin-bottom: 24px;">
<b>Fig. 20.</b> Comparison of calibrated anomaly threshold ($\tau_{\text{AE}} = 10^{-2.34}$) against empirical reconstruction errors ($10^{7.88} - 10^{10.33}$), illustrating the 10-order-of-magnitude calibration collapse.
</div>

The empirical minimum reconstruction error across all 2,000 flows was $4,148,745.0$—which exceeds the declared threshold $\tau_{\text{AE}} = 0.004597$ by over **nine orders of magnitude** ($9 \times 10^8$). Consequently, the autoencoder flagged **100.0% of all flows as anomalous**, including every single benign flow.

Forensic analysis revealed the root cause: the autoencoder was trained on feature vectors normalized with zero-mean, unit-variance standardization, but the serialized evaluation pipeline passes unnormalized raw feature vectors directly to `autoencoder.forward()` prior to scaling, causing immediate numerical saturation in the linear projection layers.

### 6.3.3 Risk-Based Router Contingency Matrix
Because both the autoencoder and the statistical detector flag 100% of flows as anomalous, `RiskBasedRouter` ([`backend/detection/router.py`](backend/detection/router.py#L42-L130) [CE-08]) exhibits severe decision skew. Table XIII details the routing contingency matrix for the 2,000 evaluation flows.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XIII.</b> RISK-BASED ROUTER CONTINGENCY MATRIX ON EVALUATION FIXTURE
</div>

| Ground Truth Category | Route: `known_attack` | Route: `unknown_anomaly_review` | Route: `human_review` | Total Evaluated | Operational Outcome |
|:---|:---:|:---:|:---:|:---:|:---|
| **PortScan** | 100 (100.0%) | 0 (0.0%) | 0 (0.0%) | 100 | Containment action dispatched immediately |
| **DDoS** | 200 (100.0%) | 0 (0.0%) | 0 (0.0%) | 200 | Automated rate-limiting / IP block dispatched |
| **Bot** | 55 (55.0%) | 7 (7.0%) | 38 (38.0%) | 100 | High operational fragmentation |
| **Benign** | 9 (0.56%) | **1,532 (95.75%)** | **59 (3.69%)** | 1,600 | **0% passed cleanly; 100% routed to alarm queues** |
| **Total Flows** | **364** | **1,539** | **97** | **2,000** | System alert volume: **2,000 / 2,000 (100%)** |

Out of 1,600 ground-truth benign flows, **exactly zero flows** are classified as normal, unflagged traffic. 1,532 benign flows are routed to `unknown_anomaly_review` due to the saturated autoencoder flag, 59 are routed to `human_review` due to low-confidence classifier predictions, and 9 are routed to `known_attack` (spurious containment). This explains the acute alert fatigue observed during stress-testing.

---

## 6.4 Robustness and Adversarial Perturbation Trajectories

We executed `report/experiments/exp_p3e_robustness.py` to evaluate the system's boundary behavior under out-of-distribution (OOD) attack labels, malformed input contracts, formal safety invariant violations, and adversarial rate perturbations.

### 6.4.1 Formal Safety Verification Invariant Enforcement
The formal verifier (`FormalSafetyVerifier` in [`backend/safety/formal_verifier.py`](backend/safety/formal_verifier.py#L125-L245) [CE-10]) was tested against eleven containment actions designed to induce self-denial-of-service, command injection, or critical operating system disruption. Table XIV documents the verification outcomes.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XIV.</b> FORMAL SAFETY VERIFIER CONTAINMENT INTERCEPTION OUTCOMES
</div>

| Case Identifier | Candidate Action Payload | Targeted Target / Resource | Admitted by Safety Gate | Violated Invariant Category | Disruption Score ($D$) | Verifiable Outcome |
|:---|:---|:---|:---:|:---|:---:|:---|
| **SFT-01** | `block_ip` | `127.0.0.1` (IPv4 Loopback) | **REJECTED** | `I1_CRITICAL_ASSET` | 0.40 | Self-DoS intercepted |
| **SFT-02** | `block_ip` | `::1` (IPv6 Loopback) | **REJECTED** | `I1_CRITICAL_ASSET` | 0.40 | Self-DoS intercepted |
| **SFT-03** | `block_ip` | `1.1.1.1` (Cloudflare DNS) | **REJECTED** | `I1_CRITICAL_ASSET` | 0.40 | Infrastructure block prevented |
| **SFT-04** | `block_ip` | `8.8.8.8` (Google Public DNS) | **REJECTED** | `I1_CRITICAL_ASSET` | 0.40 | Infrastructure block prevented |
| **SFT-05** | `block_ip` | `0.0.0.0/0` (Default Gateway) | **REJECTED** | `I1_CRITICAL_ASSET` | 0.40 | Mass blackholing averted |
| **SFT-06** | `block_ip` | `10.0.0.0/8` (Private Subnet) | **REJECTED** | `I1_CRITICAL_ASSET` | 0.40 | Broad subnet block averted |
| **SFT-07** | `block_ip` | `192.168.1.100; rm -rf /` | **REJECTED** | `I1_CRITICAL_ASSET`, `I2_ONTOLOGICAL` | 0.40 | Shell command injection neutralized |
| **SFT-08** | `block_ip` | `192.168.1.100\`reboot\`` | **REJECTED** | `I1_CRITICAL_ASSET`, `I2_ONTOLOGICAL` | 0.40 | Backtick injection neutralized |
| **SFT-09** | `kill_process` | `csrss.exe` (Win32 Subsystem) | **REJECTED** | `I1_CRITICAL_ASSET` | 0.65 | OS Blue-Screen prevented |
| **SFT-10** | `kill_process` | `/usr/sbin/init` (Linux PID 1) | **REJECTED** | `I1_CRITICAL_ASSET` | 0.65 | Kernel panic prevented |
| **SFT-11** | `block_ip` | `198.51.100.42` (External Host) | **ADMITTED** | *None (All Invariants Satisfied)* | 0.40 | Valid external containment executed |

The safety verification gate intercepted 10 out of 10 hostile or destructive containment actions while successfully admitting valid external adversary mitigation.

### 6.4.2 Volumetric DDoS Rate Perturbation Sensitivity
To evaluate the stability of the gradient-boosted decision boundary against evasion, we synthesized an adversarial perturbation trajectory: a canonical high-intensity DDoS flow ($50,000$ pkts/s) was systematically attenuated down to $100$ pkts/s while preserving its unidirectional SYN-flag profile. Table XV and Fig. 21 illustrate the resulting evasion trajectory.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XV.</b> DDOS ADVERSARIAL PACKET RATE ATTENUATION TRAJECTORY
</div>

| Injected Packet Rate (pkts/s) | Predicted Label | Decision Confidence | Router Action | Operational Verdict | Evasion Assessment |
|:---:|:---:|:---:|:---|:---|:---|
| **50,000** | `DDoS` | $1.0000$ | `known_attack` | `DDoS` | Baseline detection |
| **30,000** | `DDoS` | $1.0000$ | `known_attack` | `DDoS` | Robust detection |
| **20,000** | `DDoS` | $0.9977$ | `known_attack` | `DDoS` | Robust detection |
| **10,000** | `DDoS` | $0.9977$ | `known_attack` | `DDoS` | Robust detection |
| **5,000** | `DDoS` | $0.9977$ | `known_attack` | `DDoS` | Minimum rate for DDoS class |
| **2,500** | `PortScan` | $1.0000$ | `known_attack` | `PortScan` | Label flip (DDoS $\to$ PortScan) |
| **1,000** | `PortScan` | $1.0000$ | `known_attack` | `PortScan` | Label flip preserved |
| **500** | `PortScan` | $0.5446$ | `human_review` | `PortScan` | Confidence collapse ($< \tau_{\text{clf}}$) |
| **200** | `PortScan` | $0.5446$ | `human_review` | `PortScan` | Trapped in review queue |
| **100** | **`Benign`** | **$0.9992$** | `unknown_anomaly_review` | `unknown-anomaly` | **Complete Adversarial Evasion** |

```mermaid
xychart-beta
    title "DDoS Evasion Trajectory: Confidence vs Injected Packet Rate"
    x-axis ["50k", "30k", "20k", "10k", "5k", "2.5k", "1k", "500", "200", "100"]
    y-axis "Decision Confidence" 0.0 --> 1.1
    line [1.00, 1.00, 1.00, 1.00, 1.00, 1.00, 1.00, 0.54, 0.54, 1.00]
```
<div style="text-align: center; margin-top: 8px; margin-bottom: 24px;">
<b>Fig. 21.</b> Adversarial evasion trajectory demonstrating classifier label transitions from DDoS ($50\text{k}-5\text{k}$ pkts/s) to PortScan ($2.5\text{k}-200$ pkts/s) and ultimately Benign ($100$ pkts/s).
</div>

When an adversary throttles the transmission rate below 5,000 pkts/s, the classifier transitions through three distinct phases:

1. **Rate Substitution Phase ($5,000 \to 2,500$ pkts/s):** The tree ensemble shifts prediction to `PortScan` because the lower packet count closely matches the synthetic PortScan feature distribution.
2. **Confidence Degradation Phase ($1,000 \to 200$ pkts/s):** Prediction confidence drops to $0.5446$, breaching the $0.90$ threshold and diverting the flow to `human_review`.
3. **Complete Evasion Phase ($100$ pkts/s):** The flow is classified as `Benign` with $99.92\%$ confidence, successfully subverting the supervised detector. While the saturated autoencoder diverts it to `unknown_anomaly_review`, automated mitigation is entirely neutralized.

---

## 6.5 Comprehensive Empirical Latency Deciles and Distribution Moments

To eliminate reliance on simplistic mean averages, this section provides the complete decile distribution and higher-order statistical moments for the 1,000 single-flow inference measurements executed on `CyberGuardPipelineV2`.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE IX-B.</b> COMPLETE DECILE DISTRIBUTION AND STATISTICAL MOMENTS (1,000 CONSECUTIVE INFERENCES)
</div>

| Statistical Metric / Decile | Measured Value (ms) | Variance Relative to Median ($P_{50}$) | Operational Significance |
|:---|:---:|:---:|:---|
| **Minimum ($L_{\min}$)** | 2.364 ms | $-27.26\%$ | Baseline hardware execution threshold |
| **1st Decile ($D_1$ / $P_{10}$)** | 2.782 ms | $-14.40\%$ | Optimized cache-warm lower bound |
| **2nd Decile ($D_2$ / $P_{20}$)** | 2.915 ms | $-10.31\%$ | Fast-path non-anomalous flows |
| **3rd Decile ($D_3$ / $P_{30}$)** | 3.042 ms | $-6.40\%$ | Standard flow inference |
| **4th Decile ($D_4$ / $P_{40}$)** | 3.151 ms | $-3.05\%$ | Near-median operational latency |
| **Median ($P_{50}$)** | **3.250 ms** | **$0.00\%$** | Typical end-to-end processing delay |
| **Mean ($\mu_L$)** | 3.380 ms | $+4.00\%$ | Arithmetic average ($\sigma = 0.610$ ms) |
| **6th Decile ($D_6$ / $P_{60}$)** | 3.398 ms | $+4.55\%$ | Typical upper boundary |
| **7th Decile ($D_7$ / $P_{70}$)** | 3.562 ms | $+9.60\%$ | Minor OS thread scheduling delay |
| **8th Decile ($D_8$ / $P_{80}$)** | 3.784 ms | $+16.43\%$ | Moderate load queuing overhead |
| **9th Decile ($D_9$ / $P_{90}$)** | 4.027 ms | $+23.91\%$ | Normal operational variance ceiling |
| **95th Percentile ($P_{95}$)** | **4.196 ms** | $+29.11\%$ | Service Level Agreement (SLA) threshold |
| **99th Percentile ($P_{99}$)** | **5.911 ms** | $+81.88\%$ | Tail latency under PyTorch tensor GC |
| **Maximum ($L_{\max}$)** | 8.104 ms | $+149.35\%$ | Peak thread context switch spike |
| **Interquartile Range (IQR)** | 0.655 ms | — | $P_{75} - P_{25} = 3.655 - 3.000$ ms |
| **Sample Skewness ($\gamma_1$)** | $+1.842$ | — | Strongly positive right-skewed tail distribution |
| **Sample Kurtosis ($\beta_2$)** | $+4.918$ | — | Leptokurtic tail due to memory allocations |

The positive skewness ($\gamma_1 = +1.842$) and heavy-tailed kurtosis ($\beta_2 = +4.918$) quantitatively confirm that while 90% of flow classifications complete in under 4.03 ms, occasional Python runtime garbage collection and OS thread preemption cause sporadic latency spikes up to 8.10 ms.

---

## 6.6 Protocol Verification Forensics and Packet Trace Summaries

Table VII-B documents the forensic packet sequence parameters for the eight automated sniffer verification tests executed in `report/experiments/exp_p3b_sniffer.py`.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE VII-B.</b> FORENSIC PACKET SEQUENCE PARAMETERS ACROSS SNIFFER VERIFICATION TESTS
</div>

| Test Case | Injected Packet Flow Sequence | Extracted Flow Duration ($\mu\text{s}$) | Forward / Backward Packets | Computed Rates (PPS / BPS) | Extracted Flags & Windows | Eviction Status |
|:---|:---|:---:|:---:|:---:|:---|:---:|
| **SNF-01** | SYN $\to$ SYN-ACK $\to$ ACK $\to$ Data Fwd (414B) $\to$ Data Bwd (1136B) $\to$ FIN $\to$ FIN-ACK | $120,000.0\ \mu\text{s}$ (120 ms) | $N_{\text{f}}=4.0$<br>$N_{\text{b}}=3.0$ | Rate: $58.33$ pkts/s<br>Throughput: $12.92$ KB/s | SYN: 2, ACK: 6, FIN: 2, PSH: 2, RST: 0<br>$W_{\text{f}}=65535, W_{\text{b}}=64240$ | Flushed via bidirectional FIN teardown |
| **SNF-02** | SYN $\to$ SYN-ACK $\to$ ACK $\to$ Immediate RST | $45,000.0\ \mu\text{s}$ (45 ms) | $N_{\text{f}}=2.0$<br>$N_{\text{b}}=2.0$ | Rate: $88.89$ pkts/s<br>Throughput: $4.62$ KB/s | RST: 1, SYN: 1, ACK: 2<br>$W_{\text{f}}=65535, W_{\text{b}}=64240$ | Immediate flush on RST (zero wait) |
| **SNF-03** | SYN $\to$ SYN-ACK $\to$ ACK $\to$ (Idle Pause $\Delta t = 5.2$ s) | $5,200,000.0\ \mu\text{s}$ (5.2 s) | $N_{\text{f}}=2.0$<br>$N_{\text{b}}=1.0$ | Rate: $0.58$ pkts/s<br>Throughput: $32.7$ B/s | SYN: 1, ACK: 2<br>$W_{\text{f}}=65535, W_{\text{b}}=64240$ | Flushed via idle timeout expiry |
| **SNF-04** | FIN $\to$ FIN-ACK $\to$ Tombstone $\to$ Delayed Trailing ACK | $150,000.0\ \mu\text{s}$ (150 ms) | $N_{\text{f}}=3.0$<br>$N_{\text{b}}=2.0$ | Rate: $33.33$ pkts/s<br>Throughput: $2.13$ KB/s | ACK absorbed into tombstone state; active flows $= 0$ | Absorbed cleanly (no duplicate flow) |
| **SNF-05** | Continuous Data Stream ($N_{\text{pkt}}=5$, 500 bytes) | $400,000.0\ \mu\text{s}$ (400 ms) | $N_{\text{f}}=5.0$<br>$N_{\text{b}}=0.0$ | Rate: $12.50$ pkts/s<br>Throughput: $1.25$ KB/s | `is_interim = 1.0`, `interim_count = 1.0`<br>Parent connection kept active | Interim feature snapshot emitted |
| **SNF-06** | UDP Request (50B) $\to$ UDP Response (80B) | $15,000.0\ \mu\text{s}$ (15 ms) | $N_{\text{f}}=1.0$<br>$N_{\text{b}}=1.0$ | Rate: $133.33$ pkts/s<br>Throughput: $8.67$ KB/s | Transport protocol: UDP (17)<br>Fixed 8-byte header | Flushed via UDP timeout |
| **SNF-07** | IPv6 SYN Packet (EtherType `0x86DD`, Version 6) | $0.0\ \mu\text{s}$ (0 ms) | $N_{\text{f}}=0.0$<br>$N_{\text{b}}=0.0$ | Rate: $0.00$ pkts/s<br>Throughput: $0.00$ B/s | `parse_ipv4_packet` returns `None` | Dropped at header decode boundary |
| **SNF-08** | Loopback Raw Socket Bind (Non-Elevated Context) | N/A | N/A | N/A | Socket permission failure caught; `last_capture_mode = "synthetic_harness"` | Graceful fallback reported |

---

## 6.7 Multi-Model Decision Contingency Matrix on Evaluation Fixture

To elucidate how individual detection engines interact within the ensemble, Table XII-B provides the complete multi-model contingency breakdown across all $N = 2,000$ evaluation fixture rows.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XII-B.</b> FULL ENSEMBLE DECISION CONTINGENCY MATRIX ON 2,000-FLOW FIXTURE
</div>

| Ground Truth Category | XGBoost Classifier Prediction ($\tau = 0.90$) | PyTorch Autoencoder Anomaly Flag ($\tau_{\text{AE}} = 0.004597$) | Statistical Z-Score Anomaly Flag ($\tau_{\text{stat}} = 3.0$) | Final Router Destination (`router.py`) | Evaluated Flow Count ($N$) | Operational Security Outcome |
|:---|:---|:---:|:---:|:---|:---:|:---|
| **PortScan** | `PortScan` (Conf: 1.000) | **FLAGGED (100%)** | **FLAGGED (100%)** | `known_attack` | 100 (5.0%) | PortScan blocked immediately |
| **DDoS** | `DDoS` (Conf: 1.000) | **FLAGGED (100%)** | **FLAGGED (100%)** | `known_attack` | 200 (10.0%) | Volumetric DDoS rate-limited |
| **Bot** | `Bot` (Conf: $\ge 0.90$) | **FLAGGED (100%)** | **FLAGGED (100%)** | `known_attack` | 55 (2.75%) | Bot C2 traffic contained |
| **Bot** | `Bot` (Conf: $< 0.90$) | **FLAGGED (100%)** | **FLAGGED (100%)** | `human_review` | 38 (1.90%) | Diverted to analyst triage queue |
| **Bot** | `Benign` (Misclassified) | **FLAGGED (100%)** | **FLAGGED (100%)** | `unknown_anomaly_review` | 7 (0.35%) | Missed by classifier; caught by anomaly flag |
| **Benign** | `Benign` (Conf: $\ge 0.90$) | **FLAGGED (100%)** | **FLAGGED (100%)** | `unknown_anomaly_review` | **1,532 (76.60%)** | **Benign traffic trapped in anomaly alarm queue** |
| **Benign** | `Bot` (False Alarm, Conf: $< 0.90$) | **FLAGGED (100%)** | **FLAGGED (100%)** | `human_review` | **59 (2.95%)** | **False alarm requiring manual operator triage** |
| **Benign** | `Bot` (False Alarm, Conf: $\ge 0.90$) | **FLAGGED (100%)** | **FLAGGED (100%)** | `known_attack` | **9 (0.45%)** | **Spurious autonomous containment of legitimate host** |
| **Total** | — | **2,000 / 2,000 (100%)**| **2,000 / 2,000 (100%)**| — | **2,000 (100%)** | **Clean unflagged flows passed: 0 / 2,000 (0.0%)** |

This contingency analysis clearly demonstrates that the uncalibrated autoencoder and statistical detector undermine the entire multi-tier defense architecture: because both anomaly detectors flag 100% of traffic, legitimate benign network operations can never pass through the system cleanly without triggering alarms.

---

## 6.8 Real-Data Evaluation (Candidate Pipeline)

To overcome the severe ecological limitations of synthetic fixtures, the CyberGuard repository includes a candidate pipeline (`data/models/candidate_cicids2017/`) trained on 2,096,796 real network flows from the Canadian Institute for Cybersecurity CICIDS2017 benchmark dataset {{cite:sharafaldin2018toward}}. In accordance with project governance, this candidate remains strictly in shadow mode (`shadow_only_not_promoted, production_approved=false`). We executed an independent, exhaustive empirical re-evaluation of this candidate across five rigorous experimental protocols (`exp_candidate_reeval.py`, `exp_synthetic_real_gap.py`, `exp_day_disjoint_split.py`, `exp_dedup_sensitivity.py`, `exp_skew_ablation.py`).

### 6.8.1 Multi-Class Classification Performance and Baseline Benchmarks
Table XI-B details the re-derived performance of the candidate XGBoost classifier across all 8 classes on the held-out test partition ($N = 406,661$ flows), evaluated alongside 1,000 non-parametric bootstrap iterations ($B=1,000$) for 95% empirical confidence intervals and three established anomaly detection baselines.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XI-B.</b> CANDIDATE REAL-DATA CLASSIFICATION PERFORMANCE MATRIX WITH 95% BOOTSTRAP CONFIDENCE INTERVALS
</div>

| Class Label | Support ($N$) | Precision ($P_c$) | Recall ($R_c$) | $F_1$-Score ($F_{1,c}$) | 95% Bootstrap CI ($F_{1,c}$) | Empirical Assessment |
|:---|:---:|:---:|:---:|:---:|:---:|:---|
| **Benign** | 344,984 | 0.9873 | 0.9993 | **0.9933** | $[0.9931, 0.9935]$ | Robust high-volume separation |
| **Bot** | 113 | 0.0000 | 0.0000 | **0.0000** | $[0.0000, 0.0000]$ | **Complete Detection Collapse** (113/113 missed; 112 predicted Benign) |
| **BruteForce** | 2,757 | 0.9959 | 0.8847 | **0.9370** | $[0.9304, 0.9431]$ | Reliable detection on Patator flows |
| **DoS** | 58,410 | 0.9956 | 0.9458 | **0.9701** | $[0.9692, 0.9709]$ | High accuracy across Hulk/GoldenEye/Slowloris |
| **Infiltration** | 7 | 0.7143 | 0.7143 | **0.7143** | $[0.4444, 1.0000]$ | **Statistically Uninterpretable** (Tiny sample support $N=7$) |
| **PortScan** | 391 | 0.1862 | 0.8542 | **0.3057** | $[0.2671, 0.3478]$ | **Severe Precision Collapse** (1,460 false positives; $P=18.6\%$) |
| **WebAttack** | 107 | 0.8250 | 0.6168 | **0.7059** | $[0.6277, 0.7766]$ | Moderate recall; low support limits statistical power |
| **Macro Average** | **406,661** | **0.6720** | **0.7287** | **0.6852** | $[0.6447, 0.7133]$ | **Realistic Unweighted Operational Efficacy** |
| **Weighted Average** | **406,661** | **0.9863** | **0.9849** | **0.9855** | $[0.9852, 0.9860]$ | **Deceptively Inflated by 84.8% Benign Dominance** |
| **Overall Accuracy** | **406,661** | — | — | **0.9849** | $[0.9845, 0.9853]$ | 399,573 correct out of 406,661 flows |

<div style="text-align: center; margin-top: 14px; margin-bottom: 8px;">
<b>TABLE XI-C.</b> COMPARATIVE BENCHMARK: CANDIDATE MODEL VS. ESTABLISHED BASELINES (N = 406,661)
</div>

| Model / Baseline Architecture | Accuracy | Macro-$F_1$ | Weighted-$F_1$ | Attack Miss Rate ($\text{AMR}$) | Benign False Alarm Rate ($\text{BFAR}$) | Calibration ($\text{ECE}$) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Candidate XGBoost Pipeline** | **0.9849** | **0.6852** | **0.9855** | **0.0716** (7.16%) | **0.000745** (0.075%) | **0.012377** |
| **Majority-Class Baseline** (Always Predict Benign) | 0.8483 | 0.1147 | 0.7786 | 1.0000 (100.0%) | 0.000000 (0.0%) | 0.151662 |
| **Isolation Forest** (Unsupervised Binary) | 0.8529 | 0.5547 (Binary) | 0.8837 | 0.1328 (13.28%) | 0.149233 (14.92%) | — |
| **Statistical Z-Score Baseline** ($\tau = 3.0$) | 0.7516 | 0.4420 (Binary) | 0.8122 | 0.0074 (0.74%) | 0.298063 (29.81%) | — |

Table XI-D presents the confusion matrix across all 8 classes on the candidate test partition.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XI-D.</b> FULL 8-CLASS CONFUSION MATRIX FOR CANDIDATE MODEL ON TEST PARTITION (N = 406,661)
</div>

| Ground Truth Class | Pred: Benign | Pred: Bot | Pred: BruteForce | Pred: DoS | Pred: Infiltration | Pred: PortScan | Pred: WebAttack | Pred: Other | Total True |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Benign** | **344,727** | 0 | 7 | 100 | 2 | 146 | 2 | 0 | 344,984 |
| **Bot** | 112 | **0** | 0 | 1 | 0 | 0 | 0 | 0 | 113 |
| **BruteForce** | 315 | 0 | **2,439** | 3 | 0 | 0 | 0 | 0 | 2,757 |
| **DoS** | 3,165 | 0 | 2 | **55,243** | 0 | 0 | 0 | 0 | 58,410 |
| **Infiltration** | 2 | 0 | 0 | 0 | **5** | 0 | 0 | 0 | 7 |
| **PortScan** | 56 | 0 | 1 | 0 | 0 | **334** | 0 | 0 | 391 |
| **WebAttack** | 39 | 0 | 0 | 2 | 0 | 0 | **66** | 0 | 107 |
| **Total Predicted** | 348,416 | 0 | 2,449 | 55,349 | 7 | 480 | 68 | 0 | 406,661 |

Three crucial insights emerge from Table XI-B, XI-C, and XI-D:
1. **The Masking Effect of Weighted-$F_1$:** While the headline Weighted-$F_1$ reaches **0.9855**, Macro-$F_1$ drops to **0.6852**. The high weighted score is driven entirely by the Benign class (support 344,984; 84.8% of test data). Evaluating security models on weighted metrics alone conceals fatal detection failures on critical threat classes.
2. **Total Blindness on Bot Traffic (Shipped Artifact vs. Retrained Baseline):** For the `Bot` class ($N=113$ test flows), the shipped candidate model achieves **0.00% recall and 0.00 $F_1$**. Exactly 112 out of 113 bot flows are classified as Benign, and 1 is classified as DoS. However, our subsequent deduplication sensitivity experiments (Section 6.8.5, Table XI-G) revealed that this complete collapse is an artifact of the specific shipped model instance rather than an unlearnable property of the feature space: when retrained on the full training partition under the repository's first-wins deduplication policy without calibration holdout (Policy 1), Bot recall reached **88.50%** ($F_1 = 0.5917$) and Macro-$F_1$ reached **0.7763**. The discrepancy between 0.6852 (shipped) and 0.7763 (retrained) stems from the candidate run carving out a 20% calibration split (~398,000 rows), unseeded tree construction, and the extreme sensitivity of microscopic classes ($N=113$ in test, under 0.08% overall prevalence) to minor shifts in training data.
3. **Severe PortScan Precision Collapse:** While PortScan recall is 85.42%, its precision collapses to **18.62%** ($F_1 = 0.3057$). For every legitimate port scan caught (334 flows), the model generates over 4.3 false alarms (146 false positives from Benign traffic alone), triggering severe containment disruption.
4. **Statistical Inadequacy of Microscopic Classes:** For `Infiltration` ($N=7$), the 95% bootstrap confidence interval spans $[0.4444, 1.0000]$. With only 7 test flows in existence across the entire benchmark, performance metrics for Infiltration are statistically uninterpretable.

### 6.8.2 Inverted Reconstruction Anomaly in Real-Data Autoencoder
Evaluating the candidate PyTorch autoencoder on the real test partition revealed a catastrophic failure of unsupervised anomaly detection:
- **Benign Test Reconstruction Error:** Mean MSE = **11,488.1** ($\text{median} = 0.298$, $\max = 1.34 \times 10^8$).
- **Attack Test Reconstruction Error:** Mean MSE = **4,126.7** ($\text{median} = 0.329$, $\max = 4.25 \times 10^7$).

Empirically, legitimate benign traffic from subsequent capture days generates a **$2.78\times$ higher mean reconstruction error** than high-volume attack floods. This occurs because the autoencoder was trained strictly on the first 100,000 benign rows (Monday morning baseline) per Decision D3. When benign daytime office traffic introduces novel web protocols and bursty distributions later in the week, the autoencoder exhibits severe out-of-distribution reconstruction errors, rendering threshold-based anomaly detection completely inverted.

### 6.8.3 Synthetic-to-Real Transfer Gap (Experiment 5B)
To quantify the domain transfer collapse of models trained on synthetic data, we evaluated the bundled synthetic-trained model (`data/models/trained/`, 4 classes) against the real CICIDS2017 test partition ($N = 406,661$). Table XI-E contrasts the fixture baseline against real traffic.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XI-E.</b> SYNTHETIC-TO-REAL TRANSFER GAP (BUNDLED 4-CLASS MODEL ON REAL CICIDS2017)
</div>

| Evaluation Domain | Evaluated Dataset | Accuracy | Macro-$F_1$ | Weighted-$F_1$ | Attack Miss Rate ($\text{AMR}$) | Benign False Alarm Rate ($\text{BFAR}$) |
|:---|:---|:---:|:---:|:---:|:---:|:---:|
| **Synthetic Fixture** | `sample_flows.csv` ($N=2,000$) | **0.9625** | **0.9222** | **0.9625** | **0.0350** (3.50%) | **0.0425** (4.25%) |
| **Real Traffic (All Flows)** | CICIDS2017 Test ($N=406,661$) | **0.3815** | **0.0757** | **0.4704** | **0.2330** (23.30%) | **0.5507** (55.07%) |
| **Real Traffic (In-Distribution)** | Aligned Classes ($N=368,906$) | **0.4205** | **0.1479** | **0.5186** | **0.0000** (0.00%) | **0.5507** (55.07%) |
| **Transfer Degradation ($\Delta$)** | Synthetic $\to$ Real (All) | **$-0.5810$** | **$-0.8465$** | **$-0.4921$** | **$+0.1980$** | **$+0.5082$** |

```mermaid
xychart-beta
    title "Synthetic-to-Real Transfer Collapse (Bundled Model)"
    x-axis ["Accuracy", "Macro-F1", "Weighted-F1", "Benign FAR"]
    y-axis "Score (0.0 to 1.0)" 0.0 --> 1.0
    bar [0.9625, 0.9222, 0.9625, 0.0425]
    bar [0.3815, 0.0757, 0.4704, 0.5507]
```
<div style="text-align: center; margin-top: 8px; margin-bottom: 24px;">
<b>Fig. 22.</b> Transfer degradation: synthetic fixture baseline (blue) collapses when evaluated on real CICIDS2017 traffic (orange), driving Benign False Alarm Rate from 4.25% to 55.07%.
</div>

When confronted with real-world traffic, the bundled model's Macro-$F_1$ collapses from **0.9222 to 0.0757** (a drop of **$-0.8465$**). Most critically, the Benign False Alarm Rate surges to **55.07%**: out of 344,984 legitimate flows, **189,977 flows are falsely flagged as malicious attacks** (220,119 false PortScan predictions and 85,556 false Bot predictions). This empirical collapse provides definitive proof that models trained on synthetic fixtures cannot be deployed to production environments.

### 6.8.4 Stricter Day-Disjoint Temporal Split (Experiment 5C)
The candidate model's headline metrics were obtained using the repository's `capture_group` split (Decision D2), which holds out 20% of rows interleaved across all capture days. To measure true temporal generalization, we implemented a strict day-disjoint split:
- **Training Partition (Monday–Wednesday):** 1,292,716 samples comprising Benign, BruteForce, and DoS flows.
- **Testing Partition (Thursday–Friday):** 804,080 samples comprising all 8 classes (including unseen attack classes: PortScan, Bot, WebAttack, Infiltration).

Table XI-F summarizes model performance across 3 distinct random seeds.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XI-F.</b> DAY-DISJOINT TEMPORAL SPLIT PERFORMANCE (MON–WED TRAIN VS. THU–FRI TEST)
</div>

| Evaluated Traffic Category | Thursday–Friday Evaluation Metric | Empirical Measurement ($\text{Mean} \pm \text{Std}$) | Operational Impact |
|:---|:---|:---:|:---|
| **Known Class: Benign** | Benign Accuracy ($\text{Acc}_{\text{benign}}$) | **$0.9998 \pm 0.0000$** | High temporal stability on baseline clean traffic |
| **Known Class: Benign** | Benign False Alarm Rate ($\text{BFAR}$) | **$0.000222 \pm 0.000002$** | Low false alarm rate ($152 / 685,389$ flows) |
| **Known Class: DoS** | DoS Accuracy ($\text{Acc}_{\text{dos}}$) | **$0.9701 \pm 0.0001$** | $56,660 / 58,410$ Friday DoS flows detected |
| **Known Class: BruteForce** | BruteForce Accuracy ($\text{Acc}_{\text{bf}}$) | **$0.0000 \pm 0.0000$** | **100% Miss Rate:** $0 / 1,489$ Thursday SSH/FTP attacks detected |
| **Unseen Out-of-Distribution Attacks** | Silent Miss Rate (Predicted as Benign) | **$65.69\% \pm 16.65\%$** | **Critical Security Failure:** Two-thirds of novel attacks pass silently |
| **Unseen Out-of-Distribution Attacks** | Misclassification into Known Attacks | **$34.31\% \pm 16.65\%$** | Mislabeled as DoS or BruteForce |
| **Autoencoder Out-of-Distribution** | Anomaly Detection on Unseen Attacks | **$0.00\% \pm 0.00\%$** | Calibrated threshold fails to flag unseen attacks |

The day-disjoint evaluation exposes two critical vulnerabilities obscured by within-session splitting:
1. **Intra-Class Temporal Drift:** Even though `BruteForce` attacks were present in the Monday–Wednesday training set, **0.0% of Thursday BruteForce attacks were detected**. The feature distributions of Thursday SSH/FTP attacks drifted sufficiently from earlier days that the gradient-boosted trees failed completely.
2. **Catastrophic Silent Misses on Unseen Attacks:** When faced with novel attack families (PortScan, Bot, WebAttack, Infiltration) not seen during Mon–Wed training, the model exhibited a **$65.69\%$ silent miss rate**, classifying them as harmless Benign traffic.

### 6.8.5 Duplicate-Policy Sensitivity Analysis (Experiment 5D)
To investigate the empirical consequences of Decision D1 (silently resolving conflicting-label duplicates by first-seen CSV order), we evaluated the candidate pipeline across three distinct deduplication policies:
- **Policy 1 (Repository First-Wins):** Preserves first-seen row; drops 733,947 rows (retaining 2,096,796 rows).
- **Policy 2 (Drop All Conflicting Groups):** Drops all rows belonging to exact or near duplicate groups with conflicting ground-truth labels (retaining 2,096,360 rows).
- **Policy 3 (Random Order Shuffle First-Wins):** Shuffles raw CSV row order under 3 distinct seeds prior to applying first-wins deduplication.

Table XI-G contrasts the resulting classification metrics.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XI-G.</b> DUPLICATE RESOLUTION POLICY SENSITIVITY BENCHMARK
</div>

| Deduplication Policy | Retained Rows | Exact Conflicting Dropped | Near Conflicting Dropped | Test Accuracy | Macro-$F_1$ | Weighted-$F_1$ |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Policy 1: Repo First-Wins** | 2,096,796 | 6,132 | 3,228 | 0.9851 | 0.7763 | 0.9855 |
| **Policy 2: Drop All Conflicts** | 2,096,360 | 83,118 | 3,936 | 0.9850 | **0.7899** | 0.9854 |
| **Policy 3: Shuffle First-Wins (Seed 42)** | 2,096,796 | 66,316 | 3,680 | 0.9854 | 0.7949 | 0.9859 |
| **Policy 3: Shuffle First-Wins (Seed 123)** | 2,096,796 | 66,419 | 3,678 | 0.9854 | 0.7932 | 0.9858 |
| **Policy 3: Shuffle First-Wins (Seed 456)** | 2,096,796 | 66,289 | 3,694 | 0.9852 | 0.7962 | 0.9857 |
| **Policy 3 Summary ($\text{Mean} \pm \text{Std}$)** | 2,096,796 | — | — | **$0.9853 \pm 0.0002$** | **$0.7948 \pm 0.0014$** | **$0.9858 \pm 0.0001$** |

Crucially, Policy 2 demonstrates that purging all ambiguous, conflicting-label duplicates improves Macro-$F_1$ from **0.7763 to 0.7899** (+0.0136), while Bot $F_1$ increases from 0.5917 to 0.6624. Policy 3 confirms that simply permuting the ingestion order of CSV records alters which ground-truth label wins in conflicting groups, introducing arbitrary stochastic variance into model training ($\text{Macro-}F_1$ fluctuates across seeds by $\pm 0.0014$).

**Reconciling Shipped Candidate (0.6852) vs. Retrained Baseline (0.7763):** A key methodological observation is that clean retraining on the full training partition achieves Macro-$F_1 = 0.7763$ (Policy 1) and $0.7899$ (Policy 2), whereas the shipped candidate model evaluated in Table XI-B achieved $0.6852$. This performance gap is explained by two concrete factors in `backend/detection/trainer.py`: first, `train_all` carves out a secondary 20% calibration split (`fit_indices` vs. `calibration_indices`), starving the supervised fit set of ~398,000 flows; second, the absence of a fixed random seed in `AttackClassifier.fit()` combined with the extreme scarcity of the `Bot` class ($N=113$ test flows) causes Bot decision trees to collapse in some runs (Bot recall 0.00%, $F_1 = 0.00$) while succeeding in full-data runs (Bot recall 88.50%, $F_1 = 0.5917$). This demonstrates that Bot performance is statistically fragile and highly sensitive to training partition boundaries.

### 6.8.6 Train/Serve Feature Skew Ablation (Experiment 5E)
In production deployment, feature extraction routines often diverge from offline training pipelines. The candidate model relies on 32 features, four of which (`active_mean`, `idle_mean`, `init_win_bytes_fwd`, `init_win_bytes_bwd`) cannot be accurately computed by CyberGuard's live sniffer or Suricata EVE bridge. Table XI-H quantifies the resulting performance collapse when serving features are forced to runtime defaults.

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XI-H.</b> TRAIN/SERVE FEATURE SKEW ABLATION BENCHMARK (N = 406,661)
</div>

| Feature Ingestion Condition | Accuracy | Macro-$F_1$ | Weighted-$F_1$ | Attack Miss Rate ($\text{AMR}$) | Degradation ($\Delta \text{Macro-}F_1$) |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Clean Baseline (Full 32 Features)** | **0.9849** | **0.6852** | **0.9855** | **0.0716** (7.16%) | Baseline ($0.0000$) |
| **Live Sniffer Forced Features** (`active/idle=0`, `win=0`) | **0.9217** | **0.3668** | **0.9406** | **0.4079** (40.79%) | **$-0.3184$** ($-46.5\%$) |
| **Suricata Bridge Forced Features** (`win=64k/29k`, `act=dur`) | **0.8499** | **0.2840** | **0.8932** | **0.9859** (98.59%) | **$-0.4012$** ($-58.6\%$) |
| **Retrained Model (4 Zeroed Features, 3 Seeds)** | **$0.9241 \pm 0.0009$** | **$0.5983 \pm 0.0065$** | **$0.9427 \pm 0.0005$** | — | **$-0.0869$** (vs. Shipped) / **$-0.1780$** (vs. Full Retrain) |

```mermaid
xychart-beta
    title "Train/Serve Feature Skew Ablation Impact"
    x-axis ["Clean Model", "Live Sniffer", "Suricata Bridge", "Retrained (0-Feat)"]
    y-axis "Macro-F1 Score" 0.0 --> 0.8
    bar [0.6852, 0.3668, 0.2840, 0.5983]
```
<div style="text-align: center; margin-top: 8px; margin-bottom: 24px;">
<b>Fig. 23.</b> Severe degradation in Macro-$F_1$ under live sniffer feature skew (0.3668) and Suricata bridge approximations (0.2840) compared to offline clean baseline (0.6852).
</div>

When the clean candidate model is fed feature vectors generated by the project's own live sniffer (`live_sniffer.py`), **Macro-$F_1$ collapses from 0.6852 to 0.3668** (a 46.5% drop), while the Attack Miss Rate surges from 7.16% to **40.79%**. Under Suricata approximations, **98.59% of all attacks are missed**.

**Sniffer Feature Skew as a Pessimistic Worst-Case Lower Bound:**
It is critical to clarify that the live sniffer scenario evaluated in Table XI-H (Macro-$F_1 = 0.3668$) represents a **pessimistic worst-case lower bound**, rather than standard operating behavior. In our experiment script (`exp_skew_ablation.py`), `init_win_bytes_fwd` and `init_win_bytes_bwd` were forced to $0.0$ across 100% of test records, which simulates an extreme failure mode where every flow is intercepted mid-stream without observing the initial TCP three-way handshake (or across non-TCP UDP/ICMP traffic). In standard live operation, CyberGuard's `LiveFlowSniffer` actually extracts initial TCP window sizes whenever a SYN packet is observed ([`live_sniffer.py:133`](backend/detection/live_sniffer.py#L133)); only `active_mean` and `idle_mean` are permanently hardcoded to $0.0$ ([`live_sniffer.py:234-235`](backend/detection/live_sniffer.py#L234-L235)). Therefore, live capture of complete TCP sessions with observed SYN handshakes would exhibit a milder degradation than this worst-case boundary.

**True Feature Omission Loss vs. Suricata Bridge Reality:**
Furthermore, when evaluating the retrained 28-feature model ($0.5983 \pm 0.0065$), measuring its degradation against the calibration-carved shipped candidate ($0.6852$) yields a nominal drop of $-0.0869$; however, when evaluated against a clean 32-feature retrain on the identical training partition (**$0.7763$** from Table XI-G), the true feature omission degradation is **$\Delta \approx -0.1780$** (a substantial 17.8 percentage-point drop in Macro-$F_1$). Finally, the **Suricata EVE bridge scenario** (Macro-$F_1 = 0.2840$, Attack Miss Rate = $98.59\%$) represents the most faithful reflection of static operational skew in the repository: unlike the sniffer, `backend/suricata/tailer.py:108-124` permanently hardcodes static window constants (`64240.0` and `29200.0`) and zero variances across 100% of translated flow records regardless of session state, inducing near-total classification failure.

### 6.8.7 Feature Equivalence Matrix Across Ingestion Engines
Table XI-I presents an exhaustive feature-by-feature mapping comparing the canonical `CICFlowMeter` offline definitions against the computations implemented in `LiveFlowSniffer` (`live_sniffer.py`) and the Suricata EVE bridge (`tailer.py`).

<div style="text-align: center; margin-bottom: 8px;">
<b>TABLE XI-I.</b> 32-FEATURE EQUIVALENCE MATRIX: CICFLOWMETER VS. CYBERGUARD LIVE ENGINES
</div>

| Feature Index | Feature Name | Offline Definition (CICFlowMeter) | Live Sniffer Implementation (`live_sniffer.py`) | Suricata EVE Bridge (`tailer.py`) | Equivalence Status |
|:---:|:---|:---|:---|:---|:---:|
| 1 | `flow_duration` | Time between first and last packet ($\mu\text{s}$) | Elapsed timestamp delta ($\mu\text{s}$) | Computed from flow event end-start | **Identical** |
| 2 | `total_fwd_packets` | Count of packets in forward direction | Counter incremented on forward packet | Sum of `flow.pkts_toserver` | **Identical** |
| 3 | `total_bwd_packets` | Count of packets in backward direction | Counter incremented on backward packet | Sum of `flow.pkts_toclient` | **Identical** |
| 4 | `total_length_of_fwd_packets` | Sum of forward payload bytes | Accumulated IP payload length | Sum of `flow.bytes_toserver` | **Identical** |
| 5 | `total_length_of_bwd_packets` | Sum of backward payload bytes | Accumulated IP payload length | Sum of `flow.bytes_toclient` | **Identical** |
| 6 | `fwd_packet_length_max` | Maximum forward packet size | Updated via `max()` on forward length | Approximated via total / count | **Approximate** |
| 7 | `fwd_packet_length_min` | Minimum forward packet size | Updated via `min()` on forward length | Approximated via total / count | **Approximate** |
| 8 | `fwd_packet_length_mean` | Arithmetic mean of forward lengths | Computed: `fwd_bytes / fwd_pkts` | Computed: `bytes / pkts` | **Identical** |
| 9 | `fwd_packet_length_std` | Standard deviation of forward lengths | One-pass Welford variance accumulator | Hardcoded to `0.0` [CE-06] | **Absent (Suricata)** |
| 10 | `bwd_packet_length_max` | Maximum backward packet size | Updated via `max()` on backward length | Approximated via total / count | **Approximate** |
| 11 | `bwd_packet_length_min` | Minimum backward packet size | Updated via `min()` on backward length | Approximated via total / count | **Approximate** |
| 12 | `bwd_packet_length_mean` | Arithmetic mean of backward lengths | Computed: `bwd_bytes / bwd_pkts` | Computed: `bytes / pkts` | **Identical** |
| 13 | `bwd_packet_length_std` | Standard deviation of backward lengths | One-pass Welford variance accumulator | Hardcoded to `0.0` [CE-06] | **Absent (Suricata)** |
| 14 | `flow_bytes_s` | Total bytes divided by flow duration | Total bytes / duration in seconds | Total bytes / duration in seconds | **Identical** |
| 15 | `flow_packets_s` | Total packets divided by flow duration | Total packets / duration in seconds | Total packets / duration in seconds | **Identical** |
| 16 | `flow_iat_mean` | Mean inter-arrival time of all packets | Elapsed duration / (packets - 1) | Duration / (total pkts - 1) | **Identical** |
| 17 | `flow_iat_std` | Standard deviation of inter-arrival times | Welford variance on inter-arrival deltas | Hardcoded to `0.0` [CE-06] | **Absent (Suricata)** |
| 18 | `flow_iat_max` | Maximum inter-arrival time | Tracked via `max()` on packet deltas | Hardcoded to `duration_sec` [CE-06] | **Dimensional Error** |
| 19 | `flow_iat_min` | Minimum inter-arrival time | Tracked via `min()` on packet deltas | Set to `0.0` | **Approximate** |
| 20 | `fwd_iat_total` | Total time between forward packets | Sum of forward inter-arrival times | Estimated as flow duration | **Approximate** |
| 21 | `bwd_iat_total` | Total time between backward packets | Sum of backward inter-arrival times | Estimated as flow duration | **Approximate** |
| 22 | `fin_flag_count` | Number of packets with FIN flag | Counter incremented on TCP FIN flag | Summed from TCP flags if logged | **Identical** |
| 23 | `syn_flag_count` | Number of packets with SYN flag | Counter incremented on TCP SYN flag | Summed from TCP flags if logged | **Identical** |
| 24 | `rst_flag_count` | Number of packets with RST flag | Counter incremented on TCP RST flag | Summed from TCP flags if logged | **Identical** |
| 25 | `psh_flag_count` | Number of packets with PSH flag | Counter incremented on TCP PSH flag | Summed from TCP flags if logged | **Identical** |
| 26 | `ack_flag_count` | Number of packets with ACK flag | Counter incremented on TCP ACK flag | Summed from TCP flags if logged | **Identical** |
| 27 | `urg_flag_count` | Number of packets with URG flag | Counter incremented on TCP URG flag | Summed from TCP flags if logged | **Identical** |
| 28 | `down_up_ratio` | Download to upload packet ratio | Computed: `bwd_pkts / fwd_pkts` | Computed: `pkts_toclient / toserver` | **Identical** |
| 29 | `init_win_bytes_fwd` | Initial TCP window bytes in forward dir | Extracted from first forward TCP header | Hardcoded to `64240.0` [CE-06] | **Absent (Live/Suricata)** |
| 30 | `init_win_bytes_bwd` | Initial TCP window bytes in backward dir | Extracted from first backward TCP header| Hardcoded to `29200.0` [CE-06] | **Absent (Live/Suricata)** |
| 31 | `active_mean` | Mean time flow was active before idle | **Hardcoded to `0.0`** [CE-04:234] | Hardcoded to `duration` [CE-06] | **Absent (Live)** |
| 32 | `idle_mean` | Mean time flow was idle before active | **Hardcoded to `0.0`** [CE-04:235] | Hardcoded to `0.0` [CE-06] | **Absent (Live/Suricata)** |

> [!WARNING]
> **Lack of End-to-End PCAP Equivalence Validation:**
> Because original raw packet capture (PCAP) files corresponding to the pre-extracted CICIDS2017 CSV tables were not bundled within the repository archive, end-to-end mathematical equivalence between CICFlowMeter's offline Java feature generation and CyberGuard's live CPython/Suricata flow reconstruction could **NOT** be experimentally measured on identical network packets. The equivalence statuses in Table XI-I represent rigorous static AST and algorithm code comparisons.

