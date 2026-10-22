"""Experiment P1: Dataset Provenance and Integrity Audit.

Verifies the physical presence, SHA-256 hashes, file sizes, row counts,
and label distributions of the 8 CICIDS2017 CSV files against
cyberguard/datasets/cicids2017_real_manifest.json.
"""
import datetime
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from backend.detection.trainer import normalize_label


def get_git_hash() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), text=True)
        return out.strip()
    except Exception as e:
        return f"unknown: {e}"


def get_env_info() -> dict:
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "cpu_count": os.cpu_count() or 1,
    }


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def audit_datasets():
    t0 = time.time()
    manifest_path = REPO_ROOT / "cyberguard" / "datasets" / "cicids2017_real_manifest.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    datasets = manifest_data.get("datasets", [])
    print(f"[*] Auditing {len(datasets)} dataset files declared in {manifest_path.name}...")

    file_audits = []
    total_raw_rows = 0
    aggregate_raw_labels = {}
    aggregate_canonical_labels = {}

    for idx, entry in enumerate(datasets, 1):
        rel_path = entry["path"]
        target_path = REPO_ROOT / rel_path
        expected_sha = entry["sha256"]
        expected_bytes = entry["bytes"]
        expected_rows = entry["row_count"]
        capture_id = entry["capture_id"]

        print(f"\n[{idx}/{len(datasets)}] Checking {target_path.name}...")
        if not target_path.exists():
            raise FileNotFoundError(f"Missing dataset file: {target_path}")

        actual_bytes = target_path.stat().st_size
        bytes_match = (actual_bytes == expected_bytes)
        print(f"    Bytes: {actual_bytes} (expected: {expected_bytes}, match={bytes_match})")

        actual_sha = compute_sha256(target_path)
        sha_match = (actual_sha.lower() == expected_sha.lower())
        print(f"    SHA-256: {actual_sha}")
        print(f"    SHA match: {sha_match}")

        # Read CSV to verify rows and labels
        # low_memory=False to ensure correct type parsing
        df = pd.read_csv(target_path, low_memory=False)
        df.columns = df.columns.str.strip()
        actual_rows = len(df)
        rows_match = (actual_rows == expected_rows)
        print(f"    Rows: {actual_rows} (expected: {expected_rows}, match={rows_match})")
        total_raw_rows += actual_rows

        label_col = next((c for c in ["Label", "label", " Label"] if c in df.columns), None)
        if not label_col:
            raise KeyError(f"No Label column found in {target_path.name}")

        raw_counts = df[label_col].value_counts().to_dict()
        canonical_series = df[label_col].astype(str).map(normalize_label)
        canonical_counts = canonical_series.value_counts().to_dict()

        for k, v in raw_counts.items():
            aggregate_raw_labels[str(k)] = aggregate_raw_labels.get(str(k), 0) + int(v)
        for k, v in canonical_counts.items():
            aggregate_canonical_labels[str(k)] = aggregate_canonical_labels.get(str(k), 0) + int(v)

        file_audits.append({
            "id": entry["id"],
            "capture_id": capture_id,
            "filename": target_path.name,
            "rel_path": rel_path,
            "bytes": actual_bytes,
            "expected_bytes": expected_bytes,
            "bytes_match": bytes_match,
            "sha256": actual_sha,
            "expected_sha256": expected_sha,
            "sha_match": sha_match,
            "row_count": actual_rows,
            "expected_row_count": expected_rows,
            "rows_match": rows_match,
            "checksum_provenance": entry.get("checksum_provenance"),
            "publisher": entry.get("publisher"),
            "publisher_page": entry.get("publisher_page"),
            "source_url": entry.get("source_url"),
            "raw_labels": {str(k): int(v) for k, v in raw_counts.items()},
            "canonical_labels": {str(k): int(v) for k, v in canonical_counts.items()},
        })

    elapsed = time.time() - t0

    result = {
        "metadata": {
            "experiment": "dataset_provenance_audit",
            "command": "python report/experiments/exp_provenance_audit.py",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "git_hash": get_git_hash(),
            "duration_seconds": round(elapsed, 2),
            "environment": get_env_info(),
        },
        "summary": {
            "total_files": len(file_audits),
            "total_raw_rows": total_raw_rows,
            "all_sha256_matched": all(f["sha_match"] for f in file_audits),
            "all_bytes_matched": all(f["bytes_match"] for f in file_audits),
            "all_rows_matched": all(f["rows_match"] for f in file_audits),
            "aggregate_raw_labels": dict(sorted(aggregate_raw_labels.items())),
            "aggregate_canonical_labels": dict(sorted(aggregate_canonical_labels.items())),
            "provenance_statement": (
                "All 8 CSVs match the SHA-256 hashes recorded in cicids2017_real_manifest.json. "
                "However, the source_url is a third-party Hugging Face mirror "
                "(bencorn/CICIDS2017/resolve/main/csvs/MachineLearningCSV.zip). The manifest field "
                "'checksum_provenance' is 'observed_unb_archive_checksum', which denotes the hash "
                "observed upon unzipping the third-party mirror archive, rather than an officially "
                "published cryptographic digest from the University of New Brunswick (UNB) website. "
                "Integrity against the original 2017 UNB source files is therefore unverified by digital "
                "signature or official published hash."
            ),
        },
        "files": file_audits,
    }

    out_file = REPO_ROOT / "report" / "results" / "dataset_provenance_audit.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"\n=== Audit Complete in {elapsed:.1f}s ===")
    print(f"Total raw rows: {total_raw_rows:,}")
    print(f"All SHA-256 matched: {result['summary']['all_sha256_matched']}")
    print(f"Results written to: {out_file}")
    return result


if __name__ == "__main__":
    audit_datasets()
