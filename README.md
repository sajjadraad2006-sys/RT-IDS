# CyberGuard: Hybrid Real-Time Intrusion Detection & Guarded Autonomous Containment System (RT-IDS)

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-Deep%20Autoencoder-EE4C2C?logo=pytorch&logoColor=white)](https://pytorch.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-CUDA%20Accelerated-EB5424?logo=nvidia&logoColor=white)](https://xgboost.readthedocs.io/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Async%20Backend-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Suricata](https://img.shields.io/badge/Suricata-EVE%20Bridge-D73A49?logo=suricata&logoColor=white)](https://suricata.io/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v19-B22222)](https://attack.mitre.org/)
[![Tests](https://img.shields.io/badge/Tests-558%2B%20Passed-brightgreen)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**CyberGuard** is an industrial-grade, hybrid **Real-Time Network Intrusion Detection System (RT-IDS)** and defensive containment engine developed at the **University of Basrah, College of Engineering, Department of Mechatronics Engineering**. It integrates high-throughput packet flow extraction, hardware-accelerated machine learning (NVIDIA CUDA), deep unsupervised anomaly detection, signature-based EVE telemetry, and guarded multi-actuator containment into a deterministic defensive pipeline.

Unlike brittle legacy IDS designs or naive LLM-based wrappers, CyberGuard separates deterministic low-latency mathematical detection (< 5ms) from advisory semantic triage. Critical network actions are formally governed by deterministic policy safety gates with cryptographic proof certificates and strict Two-Person Rule authorization.

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

---

## ⚡ Key Capabilities

* **Real-Time Packet Sniffing (`live_sniffer.py`):** High-efficiency raw socket packet capture with microsecond TCP flow tracking, early-window detection, and `TIME_WAIT` absorption.
* **Vectorized 32-Feature Extraction (`features.py`):** Extracts duration, forward/backward packet distributions, inter-arrival times (IAT), TCP flags (SYN, ACK, FIN, RST, PSH, URG), and window scales directly into optimized NumPy matrices in microseconds.
* **Hardware Accelerated Inference:** Native CUDA support for tree-based ensemble classification (`xgboost.XGBClassifier(device='cuda')`) and PyTorch neural autoencoders.
* **Deterministic Safety Gate & Proof Certificates:** Actuator decisions are validated against invariant safety constraints with exported SMT-LIB2 proof certificates before execution.
* **Cryptographic Rollback Receipts:** Every containment action generates an HMAC-SHA256 authenticated rollback receipt ensuring verifiable two-person reversibility.
* **Interactive Live Dashboard:** Modern web interface with real-time SSE streaming, MITRE ATT&CK heatmaps, decision queues, and audit logs.

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
* **Operating System:** Windows 10/11 (Administrator privileges required for raw socket sniffing)
* **Python:** 3.12+ (64-bit)
* **GPU (Optional but Recommended):** NVIDIA GPU with CUDA support for accelerated training and local LLM inference

### 2. Environment Setup

```bash
# Clone the repository
git clone https://github.com/sajjadraad2006-sys/CyberGuard.git
cd CyberGuard

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
python -m pip install -r requirements-dev.txt
```

### 3. Verify System Integrity

```bash
# Run automated test suite (558 unit, integration, and security tests)
pytest -q

# Run end-to-end cryptographic and module verification
python verify.py
```

### 4. Launch CyberGuard RT-IDS

Right-click and run as Administrator:
```cmd
run_admin.bat
```
This automatically:
1. Configures network adapters and grants raw socket promiscuous capture privileges.
2. Initializes the live sniffer worker thread.
3. Connects the local GPU-accelerated LLM reasoning engine.
4. Starts the FastAPI server and launches the Command Center at **`http://127.0.0.1:8000`**.

Interactive OpenAPI documentation is available at **`http://127.0.0.1:8000/docs`**.

---

## 📁 Repository Structure

```text
CyberGuard/
├── backend/
│   ├── actuators/                # Host firewall & process containment engines
│   ├── api/                      # REST endpoints & Universal Ingestion API
│   ├── db/                       # Database models & SQLite migration
│   ├── decision/                 # Decision engine, smart logs & policy rules
│   ├── detection/                # ML classifier, Autoencoder, sniffer & correlator
│   ├── llm/                      # Local LLM manager & MITRE reasoning
│   ├── mitre/                    # MITRE ATT&CK v19 TAXII synchronization & RAG
│   ├── suricata/                 # High-throughput Suricata EVE live bridge
│   └── main.py                   # FastAPI application orchestration
├── cyberguard/
│   └── datasets/                 # Cryptographic dataset manifests & fixtures
├── data/
│   ├── mitre/                    # MITRE ATT&CK snapshot matrices
│   └── models/                   # Serialized model weights & metrics (candidate_cicids2017)
├── frontend/                     # Interactive real-time dashboard UI
├── scripts/                      # Training, simulation, and local LLM scripts
├── tests/                        # 558+ automated regression & safety tests
├── run_admin.bat                 # One-click Windows Admin launcher (Full sniffer & pipeline)
├── requirements.txt              # Production dependencies
├── requirements-dev.txt          # Development dependencies
└── verify.py                     # Cryptographic module and pipeline integrity check
```

---

## 📜 Academic Attribution & Engineering Team

* **Academic Institution:** Department of Mechatronics Engineering, College of Engineering, **University of Basrah** (جامعة البصرة)
* **Project:** RT-IDS (Real-Time Network Intrusion Detection & Guarded Autonomous Containment System) — Third-Year Engineering Capstone Project (2026–2027)
* **Project Supervisor:** **Prof. Dr. Ali Ahmed** (أ.د. علي احمد)
* **Student Engineering Team:**
  1. **Haidar Dhafir Talib** (حيدر ظافر طالب)
  2. **Sajjad Raad Abdul-Sahib** (سجاد رعد عبد الصاحب)
  3. **Sajjad Laith Abdul-Amir** (سجاد ليث عبد الامير)
* **License:** [MIT License](LICENSE)
