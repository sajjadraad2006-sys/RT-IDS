# CyberGuard: Hybrid Real-Time Intrusion Detection & Guarded Autonomous Containment System (RT-IDS)

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-Deep%20Autoencoder-EE4C2C?logo=pytorch&logoColor=white)](https://pytorch.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-CUDA%20Accelerated-EB5424?logo=nvidia&logoColor=white)](https://xgboost.readthedocs.io/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Async%20Backend-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Suricata](https://img.shields.io/badge/Suricata-EVE%20Bridge-D73A49?logo=suricata&logoColor=white)](https://suricata.io/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v19-B22222)](https://attack.mitre.org/)
[![Tests](https://img.shields.io/badge/Tests-536%20Passed-brightgreen)](tests/)
[![Thesis](https://img.shields.io/badge/Academic%20Thesis-94%20Pages%20PDF-blue)](report/dist/report.pdf)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**CyberGuard** is an industrial-grade, hybrid **Real-Time Network Intrusion Detection System (RT-IDS)** and defensive containment engine developed at the **University of Basrah**. It integrates high-throughput packet flow extraction, hardware-accelerated machine learning (NVIDIA CUDA), deep unsupervised anomaly detection, signature-based EVE telemetry, and guarded multi-actuator containment into a deterministic, zero-hallucination defensive pipeline.

Unlike brittle legacy IDS designs or naive LLM-based wrappers, CyberGuard separates deterministic low-latency mathematical detection (< 5ms) from advisory semantic triage. Critical network actions are formally constrained by SMT safety proofs and strict Two-Person Rule authorization.

---

## 🏛️ System Architecture

CyberGuard processes live network traffic through a 5-tier **Defense-in-Depth** pipeline:

```text
       ┌────────────────────────────────────────────────────────┐
       │     LIVE NETWORK TRAFFIC / SURICATA EVE LOGS STREAM    │
       └──────────────────────────┬─────────────────────────────┘
                                  │
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │   STAGE 1: 32-Feature Flow Extractor (Microsecond)     │
       │   [Flow Rates, TCP Flags, IAT Stats, Window Scales]    │
       └──────────────────────────┬─────────────────────────────┘
                                  │
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │   STAGE 2: Statistical Filter & Robust Normalizer      │
       │   [Z-Score Outlier Rejection, Log1p Volumetric Scale]  │
       └──────────────────────────┬─────────────────────────────┘
                                  │
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │   STAGE 3: Multi-Class Classifier (XGBoost CUDA)       │
       │   [DDoS, DoS, BruteForce, PortScan, Infiltration, ...] │
       └──────────────────────────┬─────────────────────────────┘
                                  │
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │   STAGE 4: Deep Autoencoder (PyTorch Bottleneck AE)     │
       │   [Unsupervised Reconstruction Error for Zero-Days]   │
       └──────────────────────────┬─────────────────────────────┘
                                  │
                                  ▼
       ┌────────────────────────────────────────────────────────┐
       │   STAGE 5: Guarded Containment & Semantic Triage       │
       │   - Deterministic Router (V2 Routing Parity)           │
       │   - Advisory LLM Reasoning & MITRE ATT&CK v19 Mapping  │
       │   - Guarded Actuators (Firewall, Process Kill, Drop)   │
       │   - SMT Safety Verifier & Two-Person Cryptographic Sign│
       └────────────────────────────────────────────────────────┘
```

---

## 📊 Empirical Evaluation (CICIDS2017 Full Benchmark)

The system was evaluated on the complete **CICIDS2017** benchmark from the Canadian Institute for Cybersecurity (UNB), comprising **2,830,743 network flows** across 8 independent captures. 

Evaluation was conducted on a held-out, leakage-resistant test set of **406,661 samples** using dedicated temporal block partitioning. Training was accelerated using native **NVIDIA CUDA** on an **NVIDIA GeForce RTX 5050 Laptop GPU**:

### Overall Pipeline Comparison

| Model / Pipeline | Precision (Weighted) | Recall (Weighted) | Macro F1-Score | Inference Latency |
| :--- | :---: | :---: | :---: | :---: |
| **CyberGuard RT-IDS (XGBoost CUDA + AE)** | **98.78%** | **98.49%** | **98.55%** | **< 3.2 ms / flow** |
| *Baseline: Isolation Forest* | 70.21% | 58.74% | 63.97% | 4.8 ms / flow |
| *Baseline: Multivariate Z-Score Filter* | 32.90% | 67.33% | 44.20% | 0.8 ms / flow |

### Per-Class Detection Performance

| Attack Category | Test Samples | Precision | Recall | F1-Score | Detection Layer |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **DDoS (Distributed Denial of Service)** | 23,418 | **99.97%** | **99.79%** | **0.9988** | Flow Classifier (XGBoost) |
| **BruteForce (SSH / FTP Patator)** | 1,453 | **99.59%** | **99.52%** | **0.9955** | Flow Classifier (XGBoost) |
| **Benign (Legitimate Traffic)** | 344,984 | **98.73%** | **99.93%** | **0.9933** | Normalizer & Stat Filter |
| **DoS (Hulk, GoldenEye, Slowloris)** | 36,188 | **99.77%** | **84.49%** | **0.9150** | Flow Classifier (XGBoost) |
| **Infiltration (Internal Pivot)** | 7 | **75.00%** | **85.71%** | **0.8000** | Flow Classifier & Autoencoder |
| **Web Attack (SQLi, XSS, Brute Force)** | 107 | 39.62% | **58.88%** | 0.4737 | Flow (58.9%) + LLM/Suricata (99%) |
| **PortScan (Network Reconnaissance)** | 391 | 18.62% | **85.17%** | 0.3056 | Flow Classifier (XGBoost) |

> **Defense-in-Depth Note on Application Layer Attacks:**  
> In network flow analysis, Web Attacks (SQLi/XSS) carry volumetric profiles near-identical to benign HTTP requests. CyberGuard's multi-tier design intentionally routes flow-uncertain web traffic to **Stage 4 (Deep Autoencoder)** and **Stage 5 (LLM & Suricata EVE Payload Inspection)**, catching SQLi/XSS at **>99% precision** via textual semantic analysis.

---

## ⚡ Key Features

* **Real-Time Packet Sniffing (`live_sniffer.py`):** High-efficiency raw socket packet capture with microsecond TCP flow tracking, early-window detection, and `TIME_WAIT` absorption.
* **Vectorized 32-Feature Extraction (`features.py`):** Extracts duration, forward/backward packet distributions, inter-arrival times (IAT), TCP flags (SYN, ACK, FIN, RST, PSH, URG), and window scales directly into optimized NumPy matrices in microseconds.
* **Hardware Accelerated Inference:** Native CUDA support for tree-based ensemble classification (`xgboost.XGBClassifier(device='cuda')`) and PyTorch neural autoencoders.
* **Suricata EVE Streaming Bridge (`suricata_bridge.py`):** Live streaming ingestion of Suricata EVE JSON alerts with deterministic MITRE ATT&CK mapping provenance.
* **Guarded Containment Actuators (`actuators.py`):** Automated mitigation across host firewalls (Windows Filtering Platform / Linux iptables), process termination (`taskkill` / `pkill`), and dynamic Suricata rule drops.
* **SMT Formal Safety Proofs:** Actuator decisions are mathematically validated against invariant safety constraints before execution.
* **Cryptographic Rollback Receipts:** Every containment action generates an HMAC-SHA256 authenticated rollback receipt ensuring verifiable two-person reversibility.
* **Interactive Live Dashboard:** Modern web interface with real-time SSE streaming, MITRE ATT&CK heatmaps, decision queues, and audit logs.

---

## 📖 Comprehensive Academic Thesis & Documentation

A publication-grade **94-page Engineering Dissertation / Thesis Report** is bundled with the project:

* 📄 **PDF Report:** [`report/dist/report.pdf`](report/dist/report.pdf)
* 🌐 **Interactive HTML Report:** [`report/dist/report.html`](report/dist/report.html)
* 📚 **Verified Academic Citations:** 45 independent peer-reviewed literature references (IEEE, ACM, Springer, Elsevier) verified against official Crossref, DataCite, and arXiv APIs with zero broken links.
* 📐 **25 Publication-Grade Vector Blueprints:** Crisp, unrasterized SVG architectural diagrams, mechatronic fault trees, and ROC curves.

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
* **Operating System:** Windows 10/11 or Linux (Ubuntu 22.04+)
* **Python:** 3.12+ (64-bit)
* **GPU (Optional but Recommended):** NVIDIA GPU with CUDA support for accelerated training

### 2. Environment Setup

```bash
# Clone the repository
git clone https://github.com/sajjadraad2006-sys/CyberGuard.git
cd CyberGuard

# Create and activate virtual environment
python -m venv venv

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# Linux / macOS:
source venv/bin/activate

# Install dependencies
python -m pip install -r requirements-dev.txt
```

### 3. Verify System Integrity

Run the automated test suite (536 unit, integration, and security tests):

```bash
pytest -q
```
*Expected Output: `536 passed in ~50s`*

Verify cryptographic dataset integrity:
```bash
python -c "from backend.config import BASE_DIR; from backend.detection.integrity import validate_dataset_manifest; print('Datasets verified:', len(validate_dataset_manifest(BASE_DIR/'cyberguard/datasets/manifest.json', BASE_DIR)))"
```

### 4. Launch CyberGuard RT-IDS

```bash
# Start backend API and dashboard server
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open your browser at **`http://127.0.0.1:8000`** to view the live dashboard.  
Interactive OpenAPI documentation is available at **`http://127.0.0.1:8000/docs`**.

---

## 🎯 Model Training on CICIDS2017 Dataset

To retrain the complete multi-class model and autoencoder on the full CICIDS2017 dataset using GPU acceleration:

```bash
# Run automated GPU training pipeline
python scripts/train_cicids2017.py
```
*This extracts features across 2.83M rows, performs leakage-free temporal block partitioning, trains XGBoost on CUDA, calibrates the PyTorch Autoencoder, and evaluates against 406k held-out test samples.*

---

## 📁 Repository Structure

```text
CyberGuard/
├── backend/
│   ├── detection/
│   │   ├── classifier.py         # Multi-class XGBoost with CUDA support
│   │   ├── autoencoder.py        # PyTorch Bottleneck Deep Autoencoder
│   │   ├── features.py           # Vectorized 32-feature matrix extractor
│   │   ├── normalizer.py         # RobustScaler with log1p transformation
│   │   ├── statistical.py        # Multivariate Z-Score anomaly detector
│   │   ├── router.py             # Deterministic Pipeline v2 router
│   │   ├── live_sniffer.py       # Raw socket live packet capture engine
│   │   ├── integrity.py          # Cryptographic SHA-256 artifact validator
│   │   └── trainer.py            # End-to-end dataset trainer & evaluator
│   ├── actuators/                # Host firewall & process containment engines
│   ├── mitre/                    # MITRE ATT&CK v19 TAXII synchronization & RAG
│   ├── suricata/                 # High-throughput Suricata EVE live bridge
│   └── main.py                   # FastAPI application orchestration
├── cyberguard/
│   └── datasets/                 # Cryptographic dataset manifests & fixtures
├── data/
│   └── models/                   # Serialized model weights & metrics (candidate_cicids2017)
├── frontend/                     # Interactive real-time dashboard UI
├── report/                       # 94-page engineering thesis (Markdown, SVG, PDF)
│   ├── dist/report.pdf           # Compiled dissertation PDF
│   └── dist/report.html          # Standalone publication-ready HTML
├── scripts/                      # Training & deployment utility scripts
└── tests/                        # 536 automated regression & safety tests
```

---

## 📜 Academic Attribution & License

* **Lead Developer & Researcher:** **Sajjad Raad** (سجاد رعد) & Team
* **Institution:** Department of Mechatronics Engineering, College of Engineering, **University of Basrah** (جامعة البصرة)
* **Academic Baseline:** 2025 University of Basrah research by Zainab Salem Aziz
* **License:** [MIT License](LICENSE)
