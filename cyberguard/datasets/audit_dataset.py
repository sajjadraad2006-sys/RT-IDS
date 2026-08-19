"""Audit official flow captures and create immutable derived feature arrays."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd

from backend.detection.features import FEATURE_NAMES, _ALIASES, extract_features_dataframe
from backend.detection.integrity import sha256_file
from backend.detection.trainer import normalize_label
from backend.config import CLASSES


AUDIT_VERSION = "cyberguard-dataset-audit-v1"
DERIVATION_VERSION = "cse-cic-ids2018-feature-derivation-v1"
CHUNK_ROWS = 100_000


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _canonical_hashes(X: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    frame = pd.DataFrame(X, columns=FEATURE_NAMES)
    frame["__label"] = labels
    exact = pd.util.hash_pandas_object(
        frame, index=False, hash_key="cyberguard-audit"
    ).to_numpy(dtype=np.uint64)
    near_frame = pd.DataFrame(np.round(np.log1p(np.maximum(X, 0.0)), 3))
    near_frame["__label"] = labels
    near = pd.util.hash_pandas_object(
        near_frame, index=False, hash_key="cyberguard-near1"
    ).to_numpy(dtype=np.uint64)
    return exact, near


def _feature_compatibility(columns: list[str]) -> dict:
    available = {
        _ALIASES.get(name.strip(), name.strip())
        for name in columns
    }
    derived = {"flow_bytes_ratio"}
    missing = sorted(set(FEATURE_NAMES) - available - derived)
    return {
        "compatible": not missing,
        "feature_schema": list(FEATURE_NAMES),
        "matched_or_derived": len(FEATURE_NAMES) - len(missing),
        "derived_features": sorted(derived),
        "missing_features": missing,
    }


def audit_capture(item: dict, raw_dir: Path, derived_dir: Path) -> tuple[dict, dict]:
    path = raw_dir / item["filename"]
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"raw capture is missing or unsafe: {path}")
    if path.stat().st_size != int(item["bytes"]):
        raise ValueError(f"publisher byte-size mismatch: {path}")
    observed_sha = sha256_file(path)
    if item.get("sha256") and observed_sha != item["sha256"]:
        raise ValueError(f"acquisition SHA-256 mismatch: {path}")

    columns = list(pd.read_csv(path, nrows=0).columns.str.strip())
    compatibility = _feature_compatibility(columns)
    if not compatibility["compatible"] or "Label" not in columns or "Timestamp" not in columns:
        raise ValueError(f"capture schema is incompatible: {path}")

    raw_labels: Counter[str] = Counter()
    canonical_labels: Counter[str] = Counter()
    unknown_labels: Counter[str] = Counter()
    missing = np.zeros(len(FEATURE_NAMES), dtype=np.int64)
    nonfinite = np.zeros(len(FEATURE_NAMES), dtype=np.int64)
    negative = np.zeros(len(FEATURE_NAMES), dtype=np.int64)
    extreme = np.zeros(len(FEATURE_NAMES), dtype=np.int64)
    minima = np.full(len(FEATURE_NAMES), np.inf)
    maxima = np.full(len(FEATURE_NAMES), -np.inf)
    X_parts, y_parts, time_parts, hash_parts, near_parts = [], [], [], [], []
    timestamp_valid = 0
    timestamp_total = 0
    excluded_unknown_label_rows = 0
    timestamp_min = None
    timestamp_max = None
    chronological_violations = 0
    previous_ns = None

    for chunk in pd.read_csv(path, chunksize=CHUNK_ROWS, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        raw_y = chunk["Label"].astype(str).str.strip()
        canonical_y = raw_y.map(normalize_label)
        raw_labels.update(raw_y.tolist())
        canonical_labels.update(canonical_y.tolist())
        unknown_labels.update(value for value in canonical_y if value not in CLASSES)
        valid_label = canonical_y.isin(CLASSES).to_numpy()
        excluded_unknown_label_rows += int((~valid_label).sum())

        for index, feature in enumerate(FEATURE_NAMES):
            source_columns = [
                name for name in chunk.columns
                if _ALIASES.get(name.strip(), name.strip()) == feature
            ]
            if not source_columns:
                continue
            numeric = pd.to_numeric(chunk[source_columns[0]], errors="coerce")
            values = numeric.to_numpy(dtype=np.float64)
            missing[index] += int(numeric.isna().sum())
            nonfinite[index] += int((~np.isfinite(values) & ~np.isnan(values)).sum())
            finite = values[np.isfinite(values)]
            if finite.size:
                negative[index] += int((finite < 0).sum())
                extreme[index] += int((np.abs(finite) > 1e12).sum())
                minima[index] = min(minima[index], float(finite.min()))
                maxima[index] = max(maxima[index], float(finite.max()))

        parsed = pd.to_datetime(
            chunk["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce", utc=True
        )
        valid = parsed.notna().to_numpy()
        timestamp_total += len(parsed)
        timestamp_valid += int(valid.sum())
        times = parsed.astype("int64").to_numpy()
        if valid.any():
            valid_times = times[valid]
            timestamp_min = int(valid_times.min()) if timestamp_min is None else min(
                timestamp_min, int(valid_times.min())
            )
            timestamp_max = int(valid_times.max()) if timestamp_max is None else max(
                timestamp_max, int(valid_times.max())
            )
            if previous_ns is not None and valid_times[0] < previous_ns:
                chronological_violations += 1
            chronological_violations += int((np.diff(valid_times) < 0).sum())
            previous_ns = int(valid_times[-1])

        feature_frame = chunk.drop(columns=["Label", "Timestamp"]).loc[valid_label]
        X = extract_features_dataframe(feature_frame)
        labels = canonical_y.loc[valid_label].to_numpy(dtype="U32")
        exact, near = _canonical_hashes(X, labels)
        X_parts.append(X)
        y_parts.append(labels)
        time_parts.append(times[valid_label])
        hash_parts.append(exact)
        near_parts.append(near)

    X_all = np.concatenate(X_parts)
    y_all = np.concatenate(y_parts)
    times_all = np.concatenate(time_parts)
    hashes = np.concatenate(hash_parts)
    near_hashes = np.concatenate(near_parts)
    unique_hashes = np.unique(hashes)
    unique_near = np.unique(near_hashes)
    derived_dir.mkdir(parents=True, exist_ok=True)
    derived_path = derived_dir / (Path(item["filename"]).stem + ".npz")
    temporary = derived_path.with_suffix(".npz.tmp")
    with temporary.open("wb") as handle:
        np.savez_compressed(
            handle,
            X=X_all,
            y=y_all,
            timestamps=times_all,
            row_hashes=hashes,
            near_hashes=near_hashes,
        )
    os.replace(temporary, derived_path)

    def iso(ns):
        return pd.Timestamp(ns, unit="ns", tz="UTC").isoformat() if ns is not None else None

    fields = {}
    for index, name in enumerate(FEATURE_NAMES):
        fields[name] = {
            "missing": int(missing[index]),
            "non_finite": int(nonfinite[index]),
            "negative_impossible_or_sentinel": int(negative[index]),
            "extreme_abs_gt_1e12": int(extreme[index]),
            "constant": bool(np.isfinite(minima[index]) and minima[index] == maxima[index]),
            "min": float(minima[index]) if np.isfinite(minima[index]) else None,
            "max": float(maxima[index]) if np.isfinite(maxima[index]) else None,
        }
    capture_report = {
        "capture_id": item["capture_id"],
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": observed_sha,
        "checksum_provenance": item["checksum_provenance"],
        "publisher_etag": item.get("etag", ""),
        "columns": columns,
        "row_count": int(timestamp_total),
        "derived_row_count": int(len(X_all)),
        "excluded_unknown_label_rows": excluded_unknown_label_rows,
        "raw_labels": dict(sorted(raw_labels.items())),
        "canonical_labels": dict(sorted(canonical_labels.items())),
        "unknown_labels": dict(sorted(unknown_labels.items())),
        "feature_compatibility": compatibility,
        "field_quality": fields,
        "exact_duplicate_rows": int(len(hashes) - len(unique_hashes)),
        "near_duplicate_rows": int(len(near_hashes) - len(unique_near)),
        "near_duplicate_strategy": "round(log1p(nonnegative 32-feature vector), 3) plus canonical label",
        "timestamp": {
            "column": "Timestamp",
            "parsed": timestamp_valid,
            "total": timestamp_total,
            "parse_rate": timestamp_valid / max(timestamp_total, 1),
            "start": iso(timestamp_min),
            "end": iso(timestamp_max),
            "chronological_order_violations": chronological_violations,
        },
        "intended_partition": item["intended_partition"],
        "derived": {
            "path": str(derived_path),
            "bytes": derived_path.stat().st_size,
            "sha256": sha256_file(derived_path),
            "parent_sha256": observed_sha,
            "transform_version": DERIVATION_VERSION,
            "row_hash_algorithm": "pandas_hash_object_uint64_fixed_key",
            "row_count": int(len(X_all)),
        },
    }
    manifest_entry = {
        "id": item["capture_id"],
        "path": str(path),
        "publisher": "Canadian Institute for Cybersecurity, University of New Brunswick",
        "publisher_page": item["publisher_page"],
        "source_url": item["url"],
        "license": item["license"],
        "access_date": item["access_date"],
        "bytes": path.stat().st_size,
        "sha256": observed_sha,
        "checksum_provenance": item["checksum_provenance"],
        "schema_version": "cse-cic-ids2018-cicflowmeter-v3",
        "capture_id": item["capture_id"],
        "time_range": {
            "start": iso(timestamp_min), "end": iso(timestamp_max), "timezone": "UTC"
        },
        "row_count": int(timestamp_total),
        "labels": dict(sorted(raw_labels.items())),
        "columns": columns,
        "label_column": "Label",
        "minimum_bytes": int(item["bytes"]),
        "transformation_lineage": capture_report["derived"],
        "training_approved": True,
        "allowed_uses": ["offline_training", "calibration", "final_test", "ood_test", "shadow"],
        "intended_partition": item["intended_partition"],
    }
    return capture_report, manifest_entry


def run_audit(acquisition_path: Path, output_dir: Path) -> dict:
    acquisition = json.loads(acquisition_path.read_text(encoding="utf-8"))
    raw_dir = acquisition_path.parent
    derived_dir = output_dir / "derived"
    reports, entries = [], []
    for source in acquisition["objects"]:
        enriched = {
            **source,
            "publisher_page": acquisition["publisher_page"],
            "license": acquisition["license"],
            "access_date": acquisition["access_date"],
        }
        report, entry = audit_capture(enriched, raw_dir, derived_dir)
        reports.append(report)
        entries.append(entry)
        print(f"audited {entry['id']}: {entry['row_count']} rows")

    capture_sets = {}
    hash_sets = {}
    near_sets = {}
    for report in reports:
        partition = report["intended_partition"]
        capture_sets.setdefault(partition, set()).add(report["capture_id"])
        with np.load(report["derived"]["path"], allow_pickle=False) as data:
            hash_sets.setdefault(partition, set()).update(map(int, data["row_hashes"]))
            near_sets.setdefault(partition, set()).update(map(int, data["near_hashes"]))
    partitions = sorted(capture_sets)
    overlaps = []
    for left_index, left in enumerate(partitions):
        for right in partitions[left_index + 1:]:
            overlaps.append({
                "left": left,
                "right": right,
                "capture_overlap": sorted(capture_sets[left] & capture_sets[right]),
                "exact_hash_overlap": len(hash_sets[left] & hash_sets[right]),
                "near_hash_overlap": len(near_sets[left] & near_sets[right]),
            })

    result = {
        "schema_version": AUDIT_VERSION,
        "dataset_id": acquisition["dataset_id"],
        "generated_date": date.today().isoformat(),
        "captures": reports,
        "partition_overlap": overlaps,
        "leakage_review": {
            "label_excluded_from_features": True,
            "timestamp_excluded_from_features": True,
            "filename_excluded_from_features": True,
            "network_identifiers_used_as_features": False,
            "deduplicate_before_fit_required": True,
            "unsupported_claims": [
                "The 32 numerical flow features do not inspect SQL or XSS payload text.",
                "An autoencoder reconstruction error does not prove a zero-day exploit.",
                "Capture filenames and timestamps are partition metadata, never model inputs."
            ],
        },
    }
    _atomic_json(output_dir / "dataset_audit.json", result)
    _atomic_json(
        output_dir / "manifest.json",
        {"schema_version": "cyberguard-datasets-v1", "datasets": entries},
    )
    lines = [
        "# تدقيق مجموعة CSE-CIC-IDS2018",
        "",
        f"- المصدر: {acquisition['publisher']}",
        f"- تاريخ الوصول: {acquisition['access_date']}",
        f"- عدد ملفات الالتقاط: {len(reports)}",
        f"- عدد الصفوف: {sum(item['row_count'] for item in reports):,}",
        "- SHA-256 محلي الملاحظة؛ الناشر لم ينشر SHA-256.",
        "- خصائص النموذج رقمية ولا تفحص نصوص SQL/XSS أو payload.",
        "",
        "## الالتقاطات",
        "",
    ]
    for item in reports:
        lines.append(
            f"- {item['capture_id']}: {item['row_count']:,} صف، "
            f"{item['intended_partition']}، labels={item['canonical_labels']}"
        )
    lines.extend(["", "## فحص التسرب", ""])
    for overlap in overlaps:
        lines.append(
            f"- {overlap['left']} / {overlap['right']}: "
            f"capture={len(overlap['capture_overlap'])}, "
            f"exact={overlap['exact_hash_overlap']}, near={overlap['near_hash_overlap']}"
        )
    (output_dir / "DATASET_AUDIT_AR.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--acquisition",
        type=Path,
        default=Path("data/datasets/cse-cic-ids2018/raw/acquisition.json"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/datasets/cse-cic-ids2018"),
    )
    args = parser.parse_args()
    run_audit(args.acquisition, args.output_dir)
