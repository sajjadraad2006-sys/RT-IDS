# CyberGuard: Doctoral & Master's-Grade Technical Audit Report

This repository contains the complete master's-thesis-grade technical audit, empirical benchmark battery, architectural analysis, and print-ready dissertation artifacts evaluating the **CyberGuard** Real-Time Intrusion Detection and Autonomous Containment System (`c:\Users\wwwsa\OneDrive\Desktop\sec`).

---

## 1. Primary Deliverables

| Artifact Path | Format | Description / Scope | Verification Status |
|:---|:---:|:---|:---:|
| [`report/dist/report.pdf`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/report/dist/report.pdf) | PDF (A4) | Master's Thesis Technical Report (**90 A4 Pages**, 4.16 MB), paginated with running headers/footers, clickable IEEE citations, 31 tables, 26 Mermaid architecture diagrams, and fully rendered KaTeX equations. | **Verified (90 Pages)** |
| [`report/dist/report.html`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/report/dist/report.html) | HTML5 | Standalone, interactive single-file thesis (1.76 MB) with embedded KaTeX fonts, CSS Paged Media styling, and deep internal navigation. | **Verified (1.76 MB)** |
| [`report/CLAIMS_LEDGER.md`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/report/CLAIMS_LEDGER.md) | Markdown | Master Claims Ledger tracking 55 factual claims mapped directly to workspace source files (`file:line`), empirical runs, or verified literature keys. | **55/55 Audited** |
| [`report/SKILLS_DECISION_LOG.md`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/report/SKILLS_DECISION_LOG.md) | Markdown | Formal protocol log of 26 catalog queries and 6 strategically installed agent skills from the Antigravity catalog. | **Complete** |
| [`report/PROGRESS.md`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/report/PROGRESS.md) | Markdown | Phased milestone log tracking completion across Recon (P0) through Finalization (P9). | **All Phases Complete** |
| [`report/references.json`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/report/references.json) | JSON | 47 peer-reviewed and official standards references verified via digital object identifiers (DOIs) or standards registries. | **47 Verified** |
| [`report/results/`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/report/results/) | Directory | Complete raw empirical benchmark logs (JSON) capturing all measurements, timings, decile distributions, and model scores. | **Archived** |
| [`report/experiments/`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/report/experiments/) | Directory | Reproducible Python empirical benchmark scripts for sniffer, pipeline, model evaluation, and robustness testing. | **All Runnable** |
| [`report/build.mjs`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/report/build.mjs) | Node.js | Automated compiler pipeline performing IEEE citation numbering, range compression, KaTeX math stashing, and Edge Chromium PDF generation. | **Passing** |
| [`report/tests/test_citations.py`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/report/tests/test_citations.py) | Pytest | TDD test suite validating the citation resolution engine and link integrity. | **5/5 Passed** |

---

## 2. Executive Summary of Audit Findings & Hypotheses ($H_1 - H_7$)

In accordance with strict evidence-only truth rules, every architectural claim made in marketing materials, README, and prior test reports was audited against the physical code and executed benchmarks:

| Hypothesis | Investigated System Component | Audited Reality & Evidence | Final Verdict |
|:---:|:---|:---|:---:|
| **$H_1$** | Bundled ML Model Provenance | `data/models/trained/artifacts.json` declares `evaluation_only=true`, `production_approved=false`, and `seed=42`. The 2,000-flow dataset is synthetically generated via `cyberguard/datasets/generate_sample.py` over 4 hand-picked classes. | **CONFIRMED** |
| **$H_2$** | Live Packet Sniffer Socket Behavior | `live_sniffer.py:532` uses Linux `SOCK_RAW + IPPROTO_TCP` (capturing TCP only, inbound only); on Windows binds `127.0.0.1` when `0.0.0.0` is passed; silently drops IPv6 (`version != 4`); falls back to synthetic harness returning `True` on unprivileged socket failures; `active_mean` and `idle_mean` are hardcoded `0.0`. | **CONFIRMED** |
| **$H_3$** | Suricata Bridge Feature Fabrication | `backend/suricata/tailer.py:168-235` fabricates constant TCP window sizes (64,240 / 29,200), forces `packet_length_std = 0.0`, and suffers from a dimensional unit error multiplying microsecond durations by $10^6$. | **CONFIRMED** |
| **$H_4$** | Application Status Contradictions | `backend/main.py:59-65` OpenAPI description explicitly documents live ingestion and automated response as "not implemented", contradicting marketing claims. `CG_AUTOSTART_LIVE_WORKER` defaults to `"false"`. | **CONFIRMED** |
| **$H_5$** | Formal SMT Safety Verification | `backend/safety/formal_verifier.py` invokes SymPy's propositional `satisfiable()` over 4 boolean variables. It formats an inert SMT-LIB2 string; **no external SMT solver (such as Z3) is invoked**. | **CONFIRMED** |
| **$H_6$** | Test Suite Counts & Latency Flaws | Stress test report documents 40/40 false alarms on benign traffic due to unconditional RAG coupling, and $P_{50} = 27.55$ s latency on the LLM path. The AST contains 425 test functions, which expand via `@pytest.mark.parametrize` to **exactly 536 collected and passing tests** (53.84 s). | **PARTIALLY CONFIRMED / RECONCILED** |
| **$H_7$** | Pickle Deserialization Risk | Models are stored as pickle/joblib files (`classifier.pkl`, `normalizer.pkl`, `statistical.pkl`). While mitigated by pre-deserialization SHA-256 validation in `integrity.py:402-439`, `artifacts.json` itself is unsigned, leaving local integrity vulnerable. | **CONFIRMED** |

---

## 3. Measured Empirical Benchmarks

All metrics trace directly to structured JSON execution logs saved under `report/results/`:

1. **Pytest Verification (`results/pytest_run.json`):**
   - Collected test items: **536**
   - Passing test items: **536 (100.0%)**
   - Failures / Skips: **0 / 0**
   - Execution duration: **53.84 seconds**
2. **Sniffer Micro-Benchmarks (`results/sniffer_experiments.json`):**
   - Single-threaded user-space packet parsing: **718,569 packets/second**
   - Mean processing latency: **1.392 $\mu\text{s}$ per packet**
   - State transition verification: **8/8 protocol scenarios verified** (TCP 3-way handshake, graceful teardown, immediate RST flush, 5.0 s idle timeout, TIME_WAIT ACK absorption, interim micro-window evaluation, UDP bi-directional aggregation, IPv6 frame dropping).
3. **Pipeline Ingestion Latencies (`results/pipeline_benchmarks.json`):**
   - Single-flow inference percentiles: $P_{50} = 3.250$ ms, $P_{90} = 4.027$ ms, $P_{95} = 4.196$ ms, $P_{99} = 5.911$ ms ($\mu = 3.380$ ms, $\sigma = 0.610$ ms)
   - Batch scaling throughput: scales from **163.55 flows/s** ($B=1$) to **3,109.19 flows/s** ($B=2,000$)
   - Peak heap memory growth: strictly linear $\mathcal{O}(B)$ scaling from 18.27 KB ($B=1$) to 10,414.59 KB ($B=2,000$).
4. **Bundled Model Evaluation (`results/model_evaluation_bundled.json`):**
   - Bundled XGBoost accuracy: **96.25%** (1,925 / 2,000 correct)
   - Macro-averaged $F_1$: **0.9222**
   - Per-class metrics: Benign ($F_1 = 0.9761$), Bot ($F_1 = 0.7126$, 68 false alarms), DDoS ($F_1 = 1.0000$), PortScan ($F_1 = 1.0000$)
   - Autoencoder Anomaly Scoring Failure: Bundled threshold $\tau_{\text{AE}} = 0.004597$; test set mean MSE is $8.102 \times 10^9$. **100.0% of all flows are flagged as anomalies**, proving catastrophic model-scaler feature scale divergence.
5. **Robustness & Adversarial Perturbations (`results/robustness_experiments.json`):**
   - Out-of-distribution external attack labels: **5/5 safely diverted to human review**
   - Malformed inputs (NaN, Inf, strings, empty payloads): **6/6 handled without unhandled crashes**
   - Destructive safety interlocks: **10/10 hostile containment actions intercepted** (loopback self-DoS, default gateway isolation, DNS quarantine, command injection, PID 1 termination).

---

## 4. What Could Not Be Measured and Why

- **Live External CIC-IDS2017 Dataset Download:** Attempting to download the 50 GB official CIC-IDS2017 PCAP/CSV archives from the University of New Brunswick repository during automated runs timed out due to institutional bandwidth quotas and corporate SSL inspection proxy boundaries. Per **Truth Rule 2 and Rule 3**, no synthetic or unverified external accuracy numbers were manufactured; the report clearly documents this constraint and evaluates the bundled model strictly on verifiable local fixtures while detailing the theoretical transfer gap.

---

## 5. How to Rebuild Everything From Scratch

### Step 1: Environment Setup
Ensure Node.js v20+ and Python 3.12 are installed:
```powershell
cd c:\Users\wwwsa\OneDrive\Desktop\sec

# Create and activate Python virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install required Python dependencies
pip install fastapi uvicorn scikit-learn xgboost torch sympy pandas numpy pytest pytest-json-report
```

### Step 2: Run All Empirical Verification Experiments
```powershell
# Run full 536-item pytest battery
pytest -q

# Run sniffer throughput & state transition experiments
python report/experiments/exp_p3b_sniffer.py

# Run end-to-end pipeline latency and batch scaling benchmarks
python report/experiments/exp_p3c_pipeline.py

# Run model evaluation and autoencoder anomaly scoring
python report/experiments/exp_p3d_model_eval.py

# Run adversarial robustness, input contracts, and safety interlocks
python report/experiments/exp_p3e_robustness.py
```

### Step 3: Run Build-Time Citation TDD Tests
```powershell
pytest report/tests/test_citations.py -v
```

### Step 4: Compile HTML and PDF Dissertation Report
```powershell
# From the workspace root
node report/build.mjs
```
The build process compiles all 12 chapters, stashes and restores LaTeX math expressions, numbers 44 distinct academic citations in order of appearance, generates clickable cross-references, renders 26 Mermaid diagrams, formats 31 data tables, and exports the final dissertation to:
- `report/dist/report.html` (Standalone interactive web report)
- `report/dist/report.pdf` (Print-ready A4 PDF document, **90 pages**)

### Step 5: Validate Quality Gates
```powershell
python report/scratch/verify_quality_gates.py
```
Expected output:
```
Unresolved {{cite}}: []
Unresolved [?]: []
Total clickable IEEE reference links: 147
Arabic abstract present: True
KaTeX rendering errors: 0
HTML tables count: 31
Mermaid diagram blocks: 26
ALL AUTOMATED QUALITY GATES PASSED!
```
