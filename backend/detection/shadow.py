"""Bounded offline active-versus-candidate shadow comparison.

This module never writes decisions, calls an LLM, or changes the active pointer.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from .autoencoder import AutoencoderDetector
from .bundles import ACTIVE_POINTER, resolve_active_bundle_dir
from .classifier import AttackClassifier
from .features import FEATURE_NAMES
from .integrity import (
    ARTIFACT_FILENAMES,
    canonical_json_sha256,
    sha256_file,
    validate_artifact_bundle,
    validate_loaded_routing_calibration,
)
from .normalizer import Normalizer
from .router import PIPELINE_VERSION, ROUTING_SCHEMA_VERSION, route_signals
from .statistical import StatisticalFilter
from ..config import DB_PATH


SHADOW_REPORT_VERSION = "cyberguard-shadow-report-v3"


def _file_snapshot(path: Path) -> dict:
    if not path.exists():
        return {"exists": False, "sha256": None, "bytes": 0}
    if not path.is_file() or path.is_symlink():
        return {"exists": True, "sha256": "unsafe-non-regular", "bytes": None}
    return {
        "exists": True,
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _load_bundle(root: Path):
    metadata = validate_artifact_bundle(root)
    norm = Normalizer().load(root / "normalizer.pkl")
    stat = StatisticalFilter().load(root / "statistical.pkl")
    clf = AttackClassifier(metadata["classifier"]["abstention_threshold"]).load(
        root / "classifier.pkl"
    )
    clf.confidence_threshold = float(metadata["classifier"]["abstention_threshold"])
    ae = AutoencoderDetector(len(FEATURE_NAMES)).load(root / "autoencoder.pt")
    validate_loaded_routing_calibration(
        metadata,
        classifier_threshold=clf.confidence_threshold,
        statistical_threshold=stat.threshold,
        autoencoder_threshold=ae.threshold,
    )
    return metadata, norm, stat, clf, ae


def _route(bundle, X_raw):
    metadata, norm, stat, clf, ae = bundle
    start = time.perf_counter()
    X = norm.transform(X_raw)
    # Match serving Pipeline v2: every row reaches the classifier and the two
    # anomaly detectors are independent evidence, never a pre-classifier gate.
    labels, confidences = clf.predict_batch(X)
    z_scores = stat.z_scores_batch(X)
    max_z_scores = z_scores.max(axis=1)
    anomalous = max_z_scores > float(stat.threshold)
    if ae.threshold is None:
        errors = np.zeros(len(X), dtype=float)
        ae_flag = np.zeros(len(X), dtype=bool)
    else:
        errors = ae.score_batch(X)
        ae_flag = errors > float(ae.threshold)
    coverage = metadata.get("coverage_contract")
    coverage = coverage if isinstance(coverage, dict) else {}
    if "trained_supported_labels" in coverage:
        supported_labels = coverage["trained_supported_labels"]
    elif "classes" in metadata:
        supported_labels = metadata["classes"]
    else:
        supported_labels = None
    routed = route_signals(
        labels,
        confidences,
        classifier_threshold=clf.confidence_threshold,
        supported_labels=supported_labels,
        statistical_flags=anomalous,
        statistical_scores=max_z_scores,
        autoencoder_available=np.full(len(X), ae.threshold is not None, dtype=bool),
        autoencoder_flags=ae_flag,
        autoencoder_scores=errors,
        pipeline_version=PIPELINE_VERSION,
        routing_schema_version=ROUTING_SCHEMA_VERSION,
    )
    elapsed = time.perf_counter() - start
    return {
        "routes": routed.routes,
        "verdicts": routed.verdicts,
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
    candidate_manifest_path = candidate_dir / "artifacts.json"
    active_manifest_path = active_dir / "artifacts.json"
    external_before = {
        "active_pointer": _file_snapshot(ACTIVE_POINTER),
        "database": _file_snapshot(DB_PATH),
    }
    before = {
        "active": {name: sha256_file(active_dir / name) for name in ARTIFACT_FILENAMES},
        "candidate": {name: sha256_file(candidate_dir / name) for name in ARTIFACT_FILENAMES},
    }
    manifests_before = {
        "active": sha256_file(active_manifest_path),
        "candidate": sha256_file(candidate_manifest_path),
    }
    active = _load_bundle(active_dir)
    candidate = _load_bundle(candidate_dir)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    final_captures = [
        capture for capture in audit["captures"]
        if capture["intended_partition"] == "final_test"
    ]
    if not final_captures:
        raise ValueError("shadow audit has no final_test captures")
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
    if not X_parts or not sum(len(part) for part in X_parts):
        raise ValueError("shadow audit produced no bounded final_test rows")
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
        "schema_version": SHADOW_REPORT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "active_bundle": str(active_dir),
        "candidate_bundle": str(candidate_dir),
        "candidate_manifest_sha256": manifests_before["candidate"],
        "candidate_artifact_hashes": before["candidate"],
        "active_manifest_sha256": manifests_before["active"],
        "active_artifact_hashes": before["active"],
        "audit_sha256": sha256_file(audit_path),
        "candidate_pipeline_version": candidate[0].get("pipeline_version"),
        "candidate_routing_schema_version": candidate[0].get(
            "routing_schema_version"
        ),
        "candidate_routing_calibration_sha256": canonical_json_sha256(
            candidate[0].get("routing_calibration")
        ),
        "candidate_coverage_contract_sha256": canonical_json_sha256(
            candidate[0].get("coverage_contract")
        ),
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
        # The shadow module contains no LLM/provider import or call path.
        "llm_calls": 0,
    }
    after = {
        "active": {name: sha256_file(active_dir / name) for name in ARTIFACT_FILENAMES},
        "candidate": {name: sha256_file(candidate_dir / name) for name in ARTIFACT_FILENAMES},
    }
    manifests_after = {
        "active": sha256_file(active_manifest_path),
        "candidate": sha256_file(candidate_manifest_path),
    }
    external_after = {
        "active_pointer": _file_snapshot(ACTIVE_POINTER),
        "database": _file_snapshot(DB_PATH),
    }
    result["artifact_hashes_unchanged"] = before == after
    result["manifest_hashes_unchanged"] = manifests_before == manifests_after
    result["database_mutations"] = int(
        external_before["database"] != external_after["database"]
    )
    result["active_pointer_mutations"] = int(
        external_before["active_pointer"] != external_after["active_pointer"]
    )
    result["state_invariants"] = {
        "artifacts_before": before,
        "artifacts_after": after,
        "manifests_before": manifests_before,
        "manifests_after": manifests_after,
        "active_pointer_before": external_before["active_pointer"],
        "active_pointer_after": external_after["active_pointer"],
        "database_before": external_before["database"],
        "database_after": external_after["database"],
    }
    result["shadow_status"] = (
        "passed"
        if result["artifact_hashes_unchanged"]
        and result["manifest_hashes_unchanged"]
        and result["llm_calls"] == 0
        and result["database_mutations"] == 0
        and result["active_pointer_mutations"] == 0
        else "failed_invariants"
    )
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
