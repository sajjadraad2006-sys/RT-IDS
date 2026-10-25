"""CyberGuard central configuration.

Operational limits/providers are environment-configurable and local-first.
Serving detector thresholds come from the integrity-checked artifact manifest;
changing legacy environment constants does not recalibrate a model.
"""
from __future__ import annotations
import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
# Tests and verification can place the generated SQLite database/key outside
# the checkout without changing bundled, read-only fixtures or model artifacts.
DATA_DIR = BASE_DIR / "data"
BUNDLED_DATA_DIR = BASE_DIR / "data"
BUNDLED_MITRE_DIR = BUNDLED_DATA_DIR / "mitre"
MODELS_DIR = DATA_DIR / "models"
UPLOADS_DIR = DATA_DIR / "uploads"
MITRE_DIR = DATA_DIR / "mitre"
DB_PATH = Path(os.getenv("CG_DB_PATH", str(DATA_DIR / "cyberguard.db"))).resolve()
TRAINED_DIR = MODELS_DIR / "trained"                       # trained ML artifacts
LLM_MODELS_DIR = BASE_DIR / "models"                       # GGUF files

for d in (DATA_DIR, MODELS_DIR, UPLOADS_DIR, MITRE_DIR, TRAINED_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Alerts, chat history, provider settings, and executable model artifacts are
# private to the service account. Existing permissive modes are tightened too.
for private_dir in (DATA_DIR, MODELS_DIR, UPLOADS_DIR, TRAINED_DIR):
    os.chmod(private_dir, 0o700)
for artifact in TRAINED_DIR.glob("*"):
    if artifact.is_file():
        os.chmod(artifact, 0o600)

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
ATTACK_VERSION = os.getenv("CG_ATTACK_VERSION", "v19.1")
GITHUB_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
MITRE_SYNC_MAX_AGE_HOURS = int(os.getenv("CG_MITRE_SYNC_HOURS", "24"))

# ── System ────────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("CG_LOG_LEVEL", "INFO")
MAX_UPLOAD_MB = int(os.getenv("CG_MAX_UPLOAD_MB", "100"))
MAX_UPLOAD_ROWS = int(os.getenv("CG_MAX_UPLOAD_ROWS", "1000000"))
MAX_REQUEST_BODY_MB = int(os.getenv("CG_MAX_REQUEST_BODY_MB", "1"))
MAX_HEADER_BYTES = int(os.getenv("CG_MAX_HEADER_BYTES", "16384"))
MAX_URL_BYTES = int(os.getenv("CG_MAX_URL_BYTES", "4096"))

# Web/API hardening. The app remains zero-configuration on localhost. To expose
# it remotely, configure both an explicit allowed host and a strong API token.
CG_ENV = os.getenv("CG_ENV", "development").lower()
CG_TRUSTED_PROXIES = [
    net.strip() for net in os.getenv("CG_TRUSTED_PROXIES", "127.0.0.1/32,::1/128").split(",")
    if net.strip()
]
CG_ADMIN_PASSWORD = os.getenv("CG_ADMIN_PASSWORD", "")
CG_ANALYST_PASSWORD = os.getenv("CG_ANALYST_PASSWORD", "")
CG_AUDITOR_PASSWORD = os.getenv("CG_AUDITOR_PASSWORD", "")

SECRET_KEY = os.getenv("CG_SECRET_KEY", "cyberguard-doctoral-defense-hmac-sha256-secret-key-2026")
API_TOKEN = os.getenv("CG_API_TOKEN", "")
ANALYST_ID = os.getenv("CG_ANALYST_ID", "local-analyst")[:64]
SIMULATOR_ALLOWED_ASSETS = {
    asset.strip()[:128] for asset in os.getenv("CG_SIM_ASSETS", "lab-host").split(",")
    if asset.strip()
}
def _get_allowed_hosts() -> list[str]:
    raw = os.getenv("CG_ALLOWED_HOSTS")
    if raw:
        return [h.strip() for h in raw.split(",") if h.strip()]
    hosts = ["127.0.0.1", "localhost", "testserver"]
    try:
        import socket, psutil
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address:
                    if addr.address not in hosts:
                        hosts.append(addr.address)
    except Exception:
        pass
    return hosts

ALLOWED_HOSTS = _get_allowed_hosts()
ALLOWED_ORIGINS = [
    "http://127.0.0.1:8000", "http://localhost:8000",
    "http://127.0.0.1:5500", "http://localhost:5500",
] + [f"http://{h}:8000" for h in ALLOWED_HOSTS if not h.startswith("127.")]

# SSRF allowlists. Local llama.cpp is intentionally restricted to loopback;
# cloud API mode is restricted to known HTTPS providers unless the operator
# explicitly adds another host.
ALLOWED_LOCAL_LLM_PORTS = {
    int(port.strip()) for port in os.getenv("CG_LOCAL_LLM_PORTS", "8080").split(",")
    if port.strip().isdigit()
}
ALLOWED_API_HOSTS = {
    host.strip().lower() for host in os.getenv(
        "CG_ALLOWED_API_HOSTS", "api.deepseek.com,api.openai.com"
    ).split(",") if host.strip()
}
