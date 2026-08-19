"""Refresh benchmark metadata without retraining or changing decisions."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import numpy as np

from .autoencoder import AutoencoderDetector
from .candidate_workflow import _benchmark
from .classifier import AttackClassifier
from .features import FEATURE_NAMES
from .integrity import validate_artifact_bundle
from .normalizer import Normalizer
from .statistical import StatisticalFilter


def refresh(candidate: Path, audit_path: Path) -> dict:
    metadata = validate_artifact_bundle(candidate)
    norm = Normalizer().load(candidate / "normalizer.pkl")
    stat = StatisticalFilter().load(candidate / "statistical.pkl")
    clf = AttackClassifier(metadata["classifier"]["abstention_threshold"]).load(
        candidate / "classifier.pkl"
    )
    ae = AutoencoderDetector(len(FEATURE_NAMES)).load(candidate / "autoencoder.pt")
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    capture = next(
        row for row in audit["captures"] if row["intended_partition"] == "final_test"
    )
    with np.load(capture["derived"]["path"], allow_pickle=False) as data:
        benchmark = _benchmark(norm, stat, clf, ae, data["X"][:50_000])
    metrics_path = candidate / "metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    metrics["benchmark"] = benchmark
    bins = metrics["classifier"].get("reliability_bins", [])
    total = sum(item["count"] for item in bins)
    curve = []
    for threshold in (0.50, 0.60, 0.70, 0.80, 0.90):
        selected = [
            item for item in bins
            if item["low"] >= threshold and item["count"] > 0
        ]
        count = sum(item["count"] for item in selected)
        correct = sum(
            round(item["accuracy"] * item["count"]) for item in selected
        )
        curve.append({
            "threshold": threshold,
            "coverage": count / max(total, 1),
            "accepted": count,
            "selective_risk": 1.0 - correct / max(count, 1),
        })
    metrics["classifier"]["selective_risk_coverage_curve"] = curve
    per_class = metrics["classifier"]["per_class"]
    valid_pr = [
        value["pr_auc"] for value in per_class.values()
        if value["pr_auc"] is not None
    ]
    metrics["classifier"]["macro_pr_auc"] = sum(valid_pr) / max(len(valid_pr), 1)
    metrics["classifier"]["macro_brier"] = (
        sum(value["brier"] for value in per_class.values()) / max(len(per_class), 1)
    )
    routing = metrics["routing"]
    routing["known_bypass_precision"] = (
        routing["known_attack_correct_classifier_bypass"]
        / max(routing["classifier_accept_rows"], 1)
    )
    routing["known_bypass_recall"] = (
        routing["known_attack_correct_classifier_bypass"]
        / max(routing["known_attack_total"], 1)
    )
    temporary = metrics_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, metrics_path)
    manifest_path = candidate / "artifacts.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metrics"] = metrics
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, manifest_path)
    validate_artifact_bundle(candidate)
    return benchmark


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--audit", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(refresh(args.candidate, args.audit), indent=2, sort_keys=True))
