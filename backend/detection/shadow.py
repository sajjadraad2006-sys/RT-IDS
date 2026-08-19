"""Bounded offline active-versus-candidate shadow comparison.

This module never writes decisions, calls an LLM, or changes the active pointer.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter
from pathlib import Path

import numpy as np

from .autoencoder import AutoencoderDetector
from .bundles import resolve_active_bundle_dir
from .classifier import AttackClassifier
from .features import FEATURE_NAMES
from .integrity import ARTIFACT_FILENAMES, sha256_file, validate_artifact_bundle
from .normalizer import Normalizer
from .statistical import StatisticalFilter


def _load_bundle(root: Path):
    metadata = validate_artifact_bundle(root)
    norm = Normalizer().load(root / "normalizer.pkl")
    stat = StatisticalFilter().load(root / "statistical.pkl")
    clf = AttackClassifier(metadata["classifier"]["abstention_threshold"]).load(
        root / "classifier.pkl"
    )
    clf.confidence_threshold = float(metadata["classifier"]["abstention_threshold"])
    ae = AutoencoderDetector(len(FEATURE_NAMES)).load(root / "autoencoder.pt")
    return metadata, norm, stat, clf, ae


def _route(bundle, X_raw):
    _, norm, stat, clf, ae = bundle
    start = time.perf_counter()
    X = norm.transform(X_raw)
    anomalous = stat.filter_batch(X)
    labels, confidences = clf.predict_batch(X)
    errors = ae.score_batch(X)
    accepted = anomalous & (labels != "Benign") & (
        confidences >= clf.confidence_threshold
    )
    ae_flag = anomalous & ~accepted & (errors > ae.threshold)
    ambiguous = anomalous & ~accepted & ~ae_flag & (labels != "Benign")
    routes = np.full(len(X), "none", dtype="U16")
    routes[ambiguous] = "review"
    routes[ae_flag] = "autoencoder"
    routes[accepted] = "classifier"
    verdicts = np.full(len(X), "Benign", dtype="U32")
    verdicts[ambiguous] = labels[ambiguous]
    verdicts[ae_flag] = "unknown-anomaly"
    verdicts[accepted] = labels[accepted]
    elapsed = time.perf_counter() - start
    return {
        "routes": routes,
        "verdicts": verdicts,
        "confidence": confidences,
        "anomaly_score": errors,
        "seconds": elapsed,
    }


def run_shadow(
    candidate_dir: Path,
    audit_path: Path,
    output_path: Path,
    *,
    max_rows: int = 100_000,
) -> dict:
    active_dir = resolve_active_bundle_dir()
    candidate_dir = candidate_dir.resolve()
    before = {
        "active": {name: sha256_file(active_dir / name) for name in ARTIFACT_FILENAMES},
        "candidate": {name: sha256_file(candidate_dir / name) for name in ARTIFACT_FILENAMES},
    }
    active = _load_bundle(active_dir)
    candidate = _load_bundle(candidate_dir)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    final_captures = [
        capture for capture in audit["captures"]
        if capture["intended_partition"] == "final_test"
    ]
    X_parts, y_parts = [], []
    remaining = max_rows
    for capture in sorted(final_captures, key=lambda row: row["capture_id"]):
        if remaining <= 0:
            break
        with np.load(capture["derived"]["path"], allow_pickle=False) as data:
            take = min(remaining, len(data["y"]))
            X_parts.append(data["X"][:take])
            y_parts.append(data["y"][:take].astype("U32"))
            remaining -= take
    X = np.concatenate(X_parts)
    y = np.concatenate(y_parts)
    active_result = _route(active, X)
    candidate_result = _route(candidate, X)

    actual_attack = y != "Benign"
    active_attack = active_result["verdicts"] != "Benign"
    candidate_attack = candidate_result["verdicts"] != "Benign"
    disagreements = active_result["verdicts"] != candidate_result["verdicts"]
    route_disagreements = active_result["routes"] != candidate_result["routes"]
    per_class = {}
    for label in sorted(set(y.tolist())):
        selected = y == label
        per_class[label] = {
            "support": int(selected.sum()),
            "active_correct": int((active_result["verdicts"][selected] == label).sum()),
            "candidate_correct": int((candidate_result["verdicts"][selected] == label).sum()),
        }
    result = {
        "schema_version": "cyberguard-shadow-report-v1",
        "active_bundle": str(active_dir),
        "candidate_bundle": str(candidate_dir),
        "rows": int(len(y)),
        "verdict_disagreements": int(disagreements.sum()),
        "route_disagreements": int(route_disagreements.sum()),
        "confidence_shift": {
            "mean": float(np.mean(candidate_result["confidence"] - active_result["confidence"])),
            "p95_absolute": float(np.quantile(
                np.abs(candidate_result["confidence"] - active_result["confidence"]), 0.95
            )),
        },
        "anomaly_score_shift": {
            "mean": float(np.mean(
                candidate_result["anomaly_score"] - active_result["anomaly_score"]
            )),
        },
        "active": {
            "routes": dict(Counter(active_result["routes"])),
            "false_positives": int((active_attack & ~actual_attack).sum()),
            "false_negatives": int((~active_attack & actual_attack).sum()),
            "seconds": active_result["seconds"],
            "throughput_rows_per_second": len(y) / active_result["seconds"],
        },
        "candidate": {
            "routes": dict(Counter(candidate_result["routes"])),
            "false_positives": int((candidate_attack & ~actual_attack).sum()),
            "false_negatives": int((~candidate_attack & actual_attack).sum()),
            "seconds": candidate_result["seconds"],
            "throughput_rows_per_second": len(y) / candidate_result["seconds"],
        },
        "per_class": per_class,
        "drift": candidate[0].get("metrics", {}).get("drift", {}),
        "smart_log_schema_changed": False,
        "policy_behavior_changed": False,
        "llm_calls": 0,
        "database_mutations": 0,
        "active_pointer_mutations": 0,
    }
    after = {
        "active": {name: sha256_file(active_dir / name) for name in ARTIFACT_FILENAMES},
        "candidate": {name: sha256_file(candidate_dir / name) for name in ARTIFACT_FILENAMES},
    }
    result["artifact_hashes_unchanged"] = before == after
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, output_path)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    parser.add_argument(
        "--audit", type=Path,
        default=Path("data/datasets/cse-cic-ids2018/dataset_audit.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-rows", type=int, default=100_000)
    args = parser.parse_args()
    print(json.dumps(
        run_shadow(args.candidate, args.audit, args.output, max_rows=args.max_rows),
        indent=2, sort_keys=True,
    ))
