# CyberGuard — AI Cyber Threat Detection System

> **4-stage detection pipeline first, LLM explains. Never the other way around.**

Production evolution of the 2025 thesis by Zainab Salem Aziz (University of Basra).
Fixes all 8 critical weaknesses of the original LLM-first approach.

## Architecture

```
Network Log → [Stage 1: Features] → [Stage 2: Z-Score] → [Stage 3: XGBoost] → [Stage 4: Autoencoder] → Alert
                  30 features         CPU: 100k+/s         97-99% accuracy      Zero-day detection
                                                                                          ↓
                                                                              [LLM explains alert]
                                                                              (10% — optional)
```

## Thesis Fixes

| # | Original Weakness | CyberGuard Fix |
|---|---|---|
| 1 | LLM reads each log (2-5s) | Z-Score filter: 100k+ rec/s on CPU |
| 2 | BERTScore on 40-100 samples | sklearn P/R/F1 on 10,000+ test samples |
| 3 | No baselines compared | Z-Score alone + Isolation Forest baselines |
| 4 | Raw text → LLM, no features | 30 numeric CICIDS2017 features |
| 5 | LLM hallucinates metrics | Numbers only from actual test runs |
| 6 | No zero-day detection | Deep autoencoder (reconstruction error) |
| 7 | No MITRE mapping | Automatic ATT&CK technique mapping |
| 8 | Static MITRE copy | TAXII 2.1 auto-sync with fallback chain |

## Quick Start

```bash
# 1. Setup
cd ~/Desktop/project
source venv/bin/activate
pip install -r requirements.txt

# 2. Download dataset (optional — for training)
python cyberguard/datasets/download_full.py

# 3. Train models (requires dataset)
python -m backend.detection.trainer cyberguard/datasets/cicids2017/ data/models/trained/

# 4. Start server
uvicorn backend.main:app --host 127.0.0.1 --port 8000

# 5. Open dashboard
# http://127.0.0.1:8000
```

## Project Structure

```
project/
├── backend/
│   ├── detection/          # The 90% — 4-stage pipeline
│   │   ├── features.py     # Stage 1: 30 numeric features
│   │   ├── normalizer.py   # Stage 1b: RobustScaler
│   │   ├── statistical.py  # Stage 2: Z-Score filter
│   │   ├── classifier.py   # Stage 3: XGBoost
│   │   ├── autoencoder.py  # Stage 4: Deep AE zero-day
│   │   ├── pipeline.py     # Orchestrator
│   │   └── trainer.py      # Train + evaluate on CICIDS2017
│   ├── mitre/              # MITRE ATT&CK integration
│   │   ├── taxii_sync.py   # TAXII 2.1 + GitHub fallback
│   │   ├── attack_db.py    # SQLite technique browser
│   │   └── mapper.py       # Label → technique mapping
│   ├── llm/                # The 10% — explanation only
│   │   ├── provider.py     # Local/API switch
│   │   ├── local_client.py # llama.cpp (Foundation-Sec / RedSage)
│   │   ├── api_client.py   # DeepSeek / OpenAI
│   │   ├── prompts.py      # Security-specific prompts
│   │   └── rag.py          # ChromaDB MITRE knowledge base
│   ├── api/                # FastAPI routes
│   ├── db/                 # SQLite + encrypted settings
│   ├── config.py           # All thresholds, env vars
│   └── main.py             # Entry point
├── frontend/               # SPA — dark theme, no CDN
│   ├── index.html          # App shell + SVG icons
│   ├── css/style.css       # Design system + glassmorphism
│   └── js/                 # 7 modules: api, app, charts, etc.
├── tests/                  # pytest: features, classifier, AE, pipeline
├── models/                 # GGUF files (Foundation-Sec, RedSage)
├── data/                   # SQLite DB, trained models, uploads
└── cyberguard/             # Legacy layer structure (kept for reference)
```

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `Ctrl+1` | Dashboard |
| `Ctrl+2` | Analyst Chat |
| `Ctrl+3` | MITRE ATT&CK |
| `Ctrl+4` | Models |
| `Ctrl+5` | Settings |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CG_CONFIDENCE` | `0.9` | Classifier confidence gate |
| `CG_AE_K` | `3` | Autoencoder threshold (μ+k·σ) |
| `CG_Z_THRESHOLD` | `3` | Z-Score statistical filter |
| `CG_LLM_PROVIDER` | `local` | `local` or `api` |
| `CG_LLAMA_URL` | `http://127.0.0.1:8080` | llama.cpp server |

## License

Academic research project — University of Basra, 2025.
