#!/bin/bash
# Validate the bundled deterministic fixtures. Production datasets must be
# acquired from the reviewed source catalog or with download_full.py, audited,
# and written under the ignored data/datasets directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PYTHON_BIN="${PROJECT_DIR}/venv/bin/python"
if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="python3"
fi

PYTHONPATH="$PROJECT_DIR" "$PYTHON_BIN" - <<'PY'
from backend.config import BASE_DIR
from backend.detection.integrity import validate_dataset_manifest

items = validate_dataset_manifest(
    BASE_DIR / "cyberguard/datasets/manifest.json", BASE_DIR
)
for item in items:
    mode = "training-approved" if item["training_approved"] else "fixture-only"
    print(f"[✓] {item['id']}: {item['row_count']} rows, {mode}")
print(
    "No network download was attempted. For the reviewed official workflow run: "
    "python -m cyberguard.datasets.acquire_catalog"
)
PY
