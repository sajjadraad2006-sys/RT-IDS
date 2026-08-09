"""CyberGuard setup verifier — answers "does it actually work?" with evidence.
Run on your machine (Windows: python verify_setup.py)
Every line prints OK / MISSING / SKIP with the exact fix when something is off.
"""
from __future__ import annotations
import importlib, os, sqlite3, sys, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GREEN, RED, YELLOW, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[0m"


def ok(msg):   print(f"{GREEN}[ OK ]{RESET} {msg}")
def miss(msg, fix): print(f"{RED}[MISS]{RESET} {msg}\n        fix: {fix}")
def skip(msg): print(f"{YELLOW}[SKIP]{RESET} {msg}")


print("=" * 64)
print("  CyberGuard — does it actually work? Check each line.")
print("=" * 64)

# ---------- 1) Python packages ----------
print("\n-- 1. Python packages --")
PACKAGES = {"numpy": "numpy", "pandas": "pandas", "sklearn": "scikit-learn",
            "xgboost": "xgboost", "torch": "torch", "fastapi": "fastapi",
            "uvicorn": "uvicorn", "sqlalchemy": "sqlalchemy",
            "httpx": "httpx", "chromadb": "chromadb", "taxii2client": "taxii2-client",
            "stix2": "stix2", "cryptography": "cryptography"}
all_deps = True
for mod, pip in PACKAGES.items():
    try:
        m = importlib.import_module(mod)
        ok(f"{pip} {getattr(m, '__version__', '')}")
    except ImportError:
        all_deps = False
        miss(f"{pip} not installed", "pip install -r requirements.txt")

# ---------- 2) LLM model files ----------
print("\n-- 2. Local LLM models (GGUF) --")
models_dir = ROOT / "models"
found_model = False
for name in ("foundation-sec-8b-reasoning-q4_k_m.gguf",
             "RedSage-Qwen3-8B-Ins.Q4_K_M.gguf"):
    p = models_dir / name
    if p.exists() and p.stat().st_size > 1_000_000_000:
        ok(f"{name} ({p.stat().st_size/1e9:.1f} GB)"); found_model = True
    else:
        miss(f"{name}", f"place the GGUF in {models_dir}/")
if not found_model:
    skip("no local model — you can still use API provider in Settings")

# ---------- 3) llama.cpp server ----------
print("\n-- 3. llama.cpp server (the chat bot brain) --")
try:
    with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=3) as r:
        ok(f"llama-server responding at 127.0.0.1:8080 (HTTP {r.status})")
except Exception:
    miss("llama-server not running",
         "llama-server.exe -m models\\foundation-sec-8b-reasoning-q4_k_m.gguf "
         "--port 8080 -ngl 99")

# ---------- 4) MITRE ATT&CK local data ----------
print("\n-- 4. MITRE ATT&CK connection (TAXII -> local SQLite) --")
found_mitre = False
for cand in (ROOT / "data" / "cyberguard.db",
             ROOT / "cyberguard" / "mitre" / "attack_knowledge.db"):
    if cand.exists():
        try:
            conn = sqlite3.connect(cand); cur = conn.cursor()
            for table in ("techniques", "attack_techniques"):
                try:
                    cur.execute(f"SELECT COUNT(*) FROM {table}")
                    n = cur.fetchone()[0]
                    if n:
                        ok(f"{cand.name}: {n:,} techniques stored locally "
                           "(works offline from now on)")
                        found_mitre = True
                        cur.execute(f"SELECT * FROM {table} LIMIT 1")
                        row = cur.fetchone()
                        print(f"        sample row: {str(row)[:90]}...")
                        break
                except sqlite3.Error:
                    continue
            conn.close()
        except sqlite3.Error:
            pass
if not found_mitre:
    miss("no MITRE data synced yet",
         "run the app then press 'Sync TAXII' in the MITRE view, or: "
         "python -m cyberguard.tests.test_mitre")

# ---------- 5) trained detection models ----------
print("\n-- 5. Trained detection models --")
mm = ROOT / "data" / "models"
needed = {"normalizer.pkl": "Stage 1 scaler", "statistical.pkl": "Stage 2 Z-filter",
          "classifier.pkl": "Stage 3 XGBoost", "autoencoder.pt": "Stage 4 autoencoder"}
trained = all((mm / f).exists() for f in needed)
for f, desc in needed.items():
    if (mm / f).exists():
        ok(f"{desc}: {f}")
    else:
        miss(f"{desc} missing ({f})",
             "train: python -m backend.detection.trainer <CICIDS2017_csv_dir> data/models")

# ---------- 6) live pipeline smoke test ----------
print("\n-- 6. Live detection smoke test --")
if all_deps and trained:
    try:
        sys.path.insert(0, str(ROOT))
        from backend.detection.normalizer import Normalizer
        from backend.detection.statistical import StatisticalFilter
        from backend.detection.classifier import AttackClassifier
        from backend.detection.autoencoder import AutoencoderDetector
        from backend.detection.pipeline import DetectionPipeline
        from backend.detection.features import FEATURE_NAMES
        norm = Normalizer().load(mm / "normalizer.pkl")
        stat = StatisticalFilter().load(mm / "statistical.pkl")
        clf = AttackClassifier().load(mm / "classifier.pkl")
        ae = AutoencoderDetector(len(FEATURE_NAMES)).load(
            mm / "autoencoder.pt", len(FEATURE_NAMES))
        pipe = DetectionPipeline(norm, stat, clf, ae)
        a1 = pipe.detect({"Flow Duration": "1000", "Total Fwd Packets": "3"})
        a2 = pipe.detect({"Flow Duration": "99999999", "SYN Flag Count": "9000",
                          "Flow Packets/s": "500000"})
        ok(f"benign-looking flow -> {a1.severity}/{a1.type} "
           f"({a1.latency_ms} ms)")
        ok(f"attack-looking flow -> {a2.severity}/{a2.type} "
           f"stage={a2.stage} ({a2.latency_ms} ms)")
    except Exception as e:
        miss(f"pipeline raised {type(e).__name__}: {e}",
             "check the traceback; usually a version mismatch in torch/xgboost")
else:
    skip("needs packages (section 1) and trained models (section 5)")

print("\n" + "=" * 64)
print("  Anything MISS above tells you exactly what to run. No guessing.")
print("=" * 64)
