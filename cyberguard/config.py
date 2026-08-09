# CyberGuard Configuration Module

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent
DATASETS_DIR = BASE_DIR / "datasets"
MODELS_DIR = BASE_DIR.parent / "models"
REPORTS_DIR = BASE_DIR / "reports"

# Create directories if missing
DATASETS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# Detection Thresholds
STATISTICAL_Z_THRESHOLD = 3.0  # Outlier standard deviation threshold
AUTOENCODER_MSE_PERCENTILE = 98.0  # Upper 2% as anomalous

# LLM Providers Configuration
DEFAULT_LLM_PROVIDER = "local" # "local" or "api"
LOCAL_LLM_PATH = str(MODELS_DIR / "foundation-sec-8b-reasoning-q4_k_m.gguf")
API_KEY_ENV_VAR = "DEEPSEEK_API_KEY"

# MITRE TAXII Config
MITRE_TAXII_URL = "https://attack-taxii.mitre.org/api/v21/"
