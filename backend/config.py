"""CyberGuard central configuration.
All values overridable via environment variables. Local-first: no cloud calls
unless the user explicitly switches the LLM provider to API mode.

Thesis fix: the thesis had no configurable thresholds. Everything here is
tunable without code changes — env vars or the Settings UI.
"""
from __future__ import annotations
import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent          # ~/Desktop/project
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = DATA_DIR / "models"
UPLOADS_DIR = DATA_DIR / "uploads"
MITRE_DIR = DATA_DIR / "mitre"
DB_PATH = DATA_DIR / "cyberguard.db"
TRAINED_DIR = MODELS_DIR / "trained"                       # trained ML artifacts
LLM_MODELS_DIR = BASE_DIR / "models"                       # GGUF files

for d in (DATA_DIR, MODELS_DIR, UPLOADS_DIR, MITRE_DIR, TRAINED_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ── Detection pipeline ────────────────────────────────────────────────────────
CLASSIFIER_CONFIDENCE = float(os.getenv("CG_CONFIDENCE", "0.9"))
AUTOENCODER_K = float(os.getenv("CG_AE_K", "3"))          # threshold = mean + k*std
ZSCORE_THRESHOLD = float(os.getenv("CG_Z_THRESHOLD", "3"))
CLASSES = ["Benign", "DDoS", "DoS", "PortScan", "BruteForce",
           "WebAttack", "Bot", "Infiltration"]

# ── LLM provider ─────────────────────────────────────────────────────────────
LLM_PROVIDER = os.getenv("CG_LLM_PROVIDER", "local")      # "local" | "api"
LLAMA_SERVER_URL = os.getenv("CG_LLAMA_URL", "http://127.0.0.1:8080")
LOCAL_MODEL = os.getenv("CG_LOCAL_MODEL", "foundation-sec-8b-reasoning-q4_k_m.gguf")
API_BASE_URL = os.getenv("CG_API_BASE", "https://api.deepseek.com/v1")
API_MODEL = os.getenv("CG_API_MODEL", "deepseek-chat")

# ── MITRE ATT&CK ─────────────────────────────────────────────────────────────
TAXII_ROOT = "https://attack-taxii.mitre.org"
ATTACK_VERSION = "v19"
GITHUB_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# ── System ────────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("CG_LOG_LEVEL", "INFO")
MAX_UPLOAD_MB = int(os.getenv("CG_MAX_UPLOAD_MB", "500"))
