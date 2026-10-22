"""Train CyberGuard on the real 2.83M row CICIDS2017 dataset using GPU acceleration."""
import logging
import sys
import time
from pathlib import Path

# Configure logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# Add repo root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.detection.trainer import train_all

if __name__ == "__main__":
    t0 = time.time()
    csv_dir = Path("cyberguard/datasets/cicids2017_real")
    manifest_path = Path("cyberguard/datasets/cicids2017_real_manifest.json")
    out_dir = Path("data/models/candidate_cicids2017")
    out_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"=== Starting Training on Full CICIDS2017 Dataset ===")
    print(f"Source Directory: {csv_dir}")
    print(f"Manifest Path:    {manifest_path}")
    print(f"Output Directory:  {out_dir}")
    
    results = train_all(
        csv_dir=csv_dir,
        out_dir=out_dir,
        manifest_path=manifest_path,
        allow_fixture=False,
    )
    
    elapsed = time.time() - t0
    print(f"\n=== Training Complete in {elapsed:.1f}s ===")
    print(f"F1 (weighted): {results.get('classifier', {}).get('f1_weighted', 'N/A')}")
    print(f"Precision:     {results.get('classifier', {}).get('precision_weighted', 'N/A')}")
    print(f"Recall:        {results.get('classifier', {}).get('recall_weighted', 'N/A')}")
    print(f"Classes:       {results.get('classes', [])}")
