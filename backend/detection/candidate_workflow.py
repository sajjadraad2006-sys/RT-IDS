"""Reproducible capture-disjoint candidate training and final evaluation."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import resource
import time
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import torch
from scipy.stats import ks_2samp
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.preprocessing import label_binarize

from .autoencoder import AutoencoderDetector
from .classifier import AttackClassifier
from .features import FEATURE_NAMES
from .integrity import sha256_file, write_artifact_manifest
from .normalizer import Normalizer
from .statistical import StatisticalFilter


SEED = 42
BENIGN_FPR_BUDGET = 0.01
CLASSIFIER_BENIGN_FPR_BUDGET = 0.005
OOD_HIGH_CONFIDENCE_BUDGET = 0.10
MIN_FINAL_ROWS = 10_000
MIN_CLASS_SUPPORT = 100
MAX_TRAIN_BENIGN = 300_000
MAX_AE_BENIGN = 200_000
MAX_ISO_BENIGN = 100_000


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _source_snapshot_hash() -> str:
    digest = hashlib.sha256()
    root = Path(__file__).resolve().parents[2]
    for path in sorted(list((root / "backend").rglob("*.py")) + list((root / "cyberguard").rglob("*.py"))):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _load_partitions(audit_path: Path) -> tuple[dict[str, dict], dict]:
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    by_partition: dict[str, list[dict]] = {}
    for capture in audit["captures"]:
        by_partition.setdefault(capture["intended_partition"], []).append(capture)
    required = {"training", "calibration", "final_test", "ood_test"}
    if required - set(by_partition):
        raise ValueError(f"audit lacks required partitions: {sorted(required - set(by_partition))}")

    result = {}
    seen_exact: set[int] = set()
    seen_near: set[int] = set()
    for partition in ("training", "calibration", "final_test", "ood_test"):
        X_parts, y_parts, time_parts, hash_parts, near_parts, capture_parts = [], [], [], [], [], []
        removed_exact = 0
        removed_near = 0
        for capture in sorted(by_partition[partition], key=lambda row: row["capture_id"]):
            with np.load(capture["derived"]["path"], allow_pickle=False) as data:
                X = data["X"]
                y = data["y"].astype("U32")
                timestamps = data["timestamps"]
                hashes = data["row_hashes"]
                near = data["near_hashes"]
                keep = np.ones(len(y), dtype=bool)
                for index, (exact_value, near_value) in enumerate(zip(hashes, near)):
                    exact_int, near_int = int(exact_value), int(near_value)
                    if exact_int in seen_exact:
                        keep[index] = False
                        removed_exact += 1
                    elif near_int in seen_near:
                        keep[index] = False
                        removed_near += 1
                    else:
                        seen_exact.add(exact_int)
                        seen_near.add(near_int)
                X_parts.append(X[keep])
                y_parts.append(y[keep])
                time_parts.append(timestamps[keep])
                hash_parts.append(hashes[keep])
                near_parts.append(near[keep])
                capture_parts.append(np.full(int(keep.sum()), capture["capture_id"], dtype="U40"))
        result[partition] = {
            "X": np.concatenate(X_parts),
            "y": np.concatenate(y_parts),
            "timestamps": np.concatenate(time_parts),
            "row_hashes": np.concatenate(hash_parts),
            "near_hashes": np.concatenate(near_parts),
            "capture_ids": np.concatenate(capture_parts),
            "removed_exact_overlap": removed_exact,
            "removed_near_overlap": removed_near,
        }
    return result, audit


def _sample_training(part: dict) -> np.ndarray:
    benign = np.where(part["y"] == "Benign")[0]
    attacks = np.where(part["y"] != "Benign")[0]
    if len(benign) > MAX_TRAIN_BENIGN:
        order = np.argsort(part["row_hashes"][benign], kind="stable")
        benign = benign[order[:MAX_TRAIN_BENIGN]]
    return np.sort(np.concatenate([benign, attacks]))


def _classification_metrics(y_true, labels, probabilities, classes) -> dict:
    per_p, per_r, per_f1, support = precision_recall_fscore_support(
        y_true, labels, labels=classes, average=None, zero_division=0
    )
    macro = precision_recall_fscore_support(y_true, labels, average="macro", zero_division=0)
    weighted = precision_recall_fscore_support(y_true, labels, average="weighted", zero_division=0)
    targets = label_binarize(y_true, classes=classes)
    if len(classes) == 2:
        targets = np.column_stack([1 - targets[:, 0], targets[:, 0]])
    per_class = {}
    for index, name in enumerate(classes):
        per_class[name] = {
            "precision": float(per_p[index]),
            "recall": float(per_r[index]),
            "f1": float(per_f1[index]),
            "support": int(support[index]),
            "pr_auc": (
                float(average_precision_score(targets[:, index], probabilities[:, index]))
                if targets[:, index].any() else None
            ),
            "brier": float(brier_score_loss(targets[:, index], probabilities[:, index])),
        }
    confidences = probabilities.max(axis=1)
    correct = labels == y_true
    bins = []
    ece = 0.0
    for low, high in zip(np.linspace(0, 1, 11)[:-1], np.linspace(0, 1, 11)[1:]):
        selected = (confidences >= low) & (confidences <= high if high == 1 else confidences < high)
        count = int(selected.sum())
        accuracy = float(correct[selected].mean()) if count else None
        mean_confidence = float(confidences[selected].mean()) if count else None
        if count:
            ece += count / len(y_true) * abs(accuracy - mean_confidence)
        bins.append({
            "low": float(low), "high": float(high), "count": count,
            "accuracy": accuracy, "mean_confidence": mean_confidence,
        })
    return {
        "per_class": per_class,
        "macro": {"precision": float(macro[0]), "recall": float(macro[1]), "f1": float(macro[2])},
        "weighted": {
            "precision": float(weighted[0]), "recall": float(weighted[1]), "f1": float(weighted[2])
        },
        "confusion_matrix_labels": classes,
        "confusion_matrix": confusion_matrix(y_true, labels, labels=classes).tolist(),
        "expected_calibration_error_10_bin": float(ece),
        "reliability_bins": bins,
    }


def _binary_metrics(y_true, predicted_attack) -> dict:
    actual = y_true != "Benign"
    predicted = np.asarray(predicted_attack, dtype=bool)
    tp = int((predicted & actual).sum())
    fp = int((predicted & ~actual).sum())
    fn = int((~predicted & actual).sum())
    tn = int((~predicted & ~actual).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / max(precision + recall, 1e-12),
        "benign_false_positive_rate": fp / max(fp + tn, 1),
        "false_positives_per_10000_benign": fp / max(fp + tn, 1) * 10_000,
    }


def _calibrate_classifier(clf, X, y) -> dict:
    labels, confidences = clf.predict_batch(X)
    benign = y == "Benign"
    heldout = ~np.isin(y, clf.classes_)
    candidates = []
    for threshold in np.linspace(0.50, 0.995, 100):
        accepted = (labels != "Benign") & (confidences >= threshold)
        benign_fpr = float((accepted & benign).sum() / max(benign.sum(), 1))
        heldout_mislabel = float((accepted & heldout).sum() / max(heldout.sum(), 1))
        candidates.append((float(threshold), benign_fpr, heldout_mislabel, int(accepted.sum())))
    eligible = [
        row for row in candidates
        if row[1] <= CLASSIFIER_BENIGN_FPR_BUDGET and row[2] <= OOD_HIGH_CONFIDENCE_BUDGET
    ]
    chosen = min(eligible, key=lambda row: row[0]) if eligible else max(candidates, key=lambda row: row[0])
    return {
        "threshold": chosen[0],
        "benign_false_positive_rate": chosen[1],
        "heldout_family_high_confidence_mislabel_rate": chosen[2],
        "accepted": chosen[3],
        "validation_samples": int(len(y)),
        "method": "capture_disjoint_grid_max_benign_fpr_0.005_max_heldout_mislabel_0.10",
        "eligible_threshold_found": bool(eligible),
    }


def _drift(train: np.ndarray, test: np.ndarray) -> dict:
    rng = np.random.default_rng(SEED)
    train_sample = train[rng.choice(len(train), min(20_000, len(train)), replace=False)]
    test_sample = test[rng.choice(len(test), min(20_000, len(test)), replace=False)]
    result = {}
    for index, name in enumerate(FEATURE_NAMES):
        base = train_sample[:, index]
        current = test_sample[:, index]
        edges = np.unique(np.quantile(base, np.linspace(0, 1, 11)))
        if len(edges) < 3:
            psi = 0.0
        else:
            base_hist = np.histogram(base, bins=edges)[0] / len(base)
            curr_hist = np.histogram(np.clip(current, edges[0], edges[-1]), bins=edges)[0] / len(current)
            base_hist = np.maximum(base_hist, 1e-6)
            curr_hist = np.maximum(curr_hist, 1e-6)
            psi = float(np.sum((curr_hist - base_hist) * np.log(curr_hist / base_hist)))
        ks = ks_2samp(base, current, method="asymp")
        result[name] = {"psi": psi, "ks_statistic": float(ks.statistic), "ks_pvalue": float(ks.pvalue)}
    return result


def _error_distribution(values: np.ndarray) -> dict:
    return {
        "count": int(len(values)),
        "mean": float(values.mean()) if len(values) else None,
        "p50": float(np.quantile(values, 0.50)) if len(values) else None,
        "p95": float(np.quantile(values, 0.95)) if len(values) else None,
        "p99": float(np.quantile(values, 0.99)) if len(values) else None,
    }


def _all_finite(value) -> bool:
    if isinstance(value, dict):
        return all(_all_finite(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return all(_all_finite(item) for item in value)
    if isinstance(value, (float, np.floating)):
        return bool(np.isfinite(value))
    return True


def _benchmark(norm, stat, clf, ae, X_raw) -> dict:
    X_raw = X_raw[: min(50_000, len(X_raw))]
    names = ("normalizer", "statistical", "classifier", "autoencoder", "complete_pipeline")
    durations = {name: [] for name in names}
    processed = {name: 0 for name in names}
    for start_index in range(0, len(X_raw), 5_000):
        raw = X_raw[start_index:start_index + 5_000]
        total_start = time.perf_counter()
        stage_start = time.perf_counter()
        X = norm.transform(raw)
        durations["normalizer"].append(time.perf_counter() - stage_start)
        processed["normalizer"] += len(raw)
        stage_start = time.perf_counter()
        mask = stat.filter_batch(X)
        durations["statistical"].append(time.perf_counter() - stage_start)
        processed["statistical"] += len(raw)
        subset = X[mask]
        stage_start = time.perf_counter()
        if len(subset):
            clf.predict_batch(subset)
        durations["classifier"].append(time.perf_counter() - stage_start)
        processed["classifier"] += len(subset)
        stage_start = time.perf_counter()
        if len(subset):
            ae.score_batch(subset)
        durations["autoencoder"].append(time.perf_counter() - stage_start)
        processed["autoencoder"] += len(subset)
        durations["complete_pipeline"].append(time.perf_counter() - total_start)
        processed["complete_pipeline"] += len(raw)
    result = {}
    for name in names:
        seconds = float(sum(durations[name]))
        denominator = max(processed[name], 1)
        latency = np.array(durations[name]) / np.maximum(
            1,
            np.array([
                processed[name] / max(len(durations[name]), 1)
            ] * len(durations[name])),
        ) * 1000
        result[name] = {
            "seconds": seconds,
            "rows_processed": int(processed[name]),
            "throughput_rows_per_second": processed[name] / max(seconds, 1e-12),
            "mean_ms_per_processed_row": seconds / denominator * 1000,
            "batch_estimated_latency_ms_per_row": {
                "p50": float(np.quantile(latency, 0.50)),
                "p95": float(np.quantile(latency, 0.95)),
                "p99": float(np.quantile(latency, 0.99)),
            },
        }
    return result


def train_candidate(audit_path: Path, output_dir: Path) -> dict:
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(SEED)
        torch.cuda.reset_peak_memory_stats()
    partitions, audit = _load_partitions(audit_path)
    train = partitions["training"]
    calibration = partitions["calibration"]
    final = partitions["final_test"]
    ood = partitions["ood_test"]
    train_indices = _sample_training(train)
    X_train_raw, y_train = train["X"][train_indices], train["y"][train_indices]
    benign_train = y_train == "Benign"
    if not benign_train.any():
        raise ValueError("training partition has no benign rows")

    norm = Normalizer().fit(X_train_raw[benign_train])
    X_train = norm.transform(X_train_raw)
    X_cal = norm.transform(calibration["X"])
    X_final = norm.transform(final["X"])
    X_ood = norm.transform(ood["X"])

    stat = StatisticalFilter().fit(X_train[benign_train])
    calibration_benign = calibration["y"] == "Benign"
    stat.threshold = float(np.quantile(
        stat.max_z_scores(X_cal[calibration_benign]), 1.0 - BENIGN_FPR_BUDGET,
        method="higher",
    ))

    clf = AttackClassifier().fit(X_train, y_train, n_estimators=200, max_depth=7)
    classifier_calibration = _calibrate_classifier(clf, X_cal, calibration["y"])
    clf.confidence_threshold = classifier_calibration["threshold"]

    benign_indices = np.where(benign_train)[0][:MAX_AE_BENIGN]
    cal_benign_indices = np.where(calibration_benign)[0][:100_000]
    ae = AutoencoderDetector(X_train.shape[1]).fit(
        X_train[benign_indices], X_cal[cal_benign_indices], epochs=20
    )
    calibration_errors = ae.score_batch(X_cal[cal_benign_indices])
    ae.threshold = float(np.quantile(calibration_errors, 0.995, method="higher"))

    iso = IsolationForest(contamination="auto", n_jobs=-1, random_state=SEED)
    iso.fit(X_train[benign_indices[:MAX_ISO_BENIGN]])

    final_labels, final_conf = clf.predict_batch(X_final)
    final_prob = clf.model.predict_proba(X_final)
    classifier_metrics = _classification_metrics(
        final["y"], final_labels, final_prob, list(clf.classes_)
    )
    final_stat = stat.filter_batch(X_final)
    final_ae_errors = ae.score_batch(X_final)
    final_iso = iso.predict(X_final) == -1
    accepted = final_stat & (final_labels != "Benign") & (
        final_conf >= clf.confidence_threshold
    )
    review = final_stat & ~accepted & (
        (final_ae_errors > ae.threshold) | (final_labels != "Benign")
    )
    pipeline_attack = accepted | review
    final_binary = {
        "pipeline": _binary_metrics(final["y"], pipeline_attack),
        "statistical": _binary_metrics(final["y"], final_stat),
        "isolation_forest": _binary_metrics(final["y"], final_iso),
        "autoencoder": _binary_metrics(final["y"], final_ae_errors > ae.threshold),
    }

    known_attack = final["y"] != "Benign"
    routing = {
        "known_attack_correct_classifier_bypass": int(
            (accepted & (final_labels == final["y"]) & known_attack).sum()
        ),
        "known_attack_total": int(known_attack.sum()),
        "review_rows": int(review.sum()),
        "classifier_accept_rows": int(accepted.sum()),
        "benign_review_rows": int((review & ~known_attack).sum()),
    }

    ood_labels, ood_conf = clf.predict_batch(X_ood)
    ood_stat = stat.filter_batch(X_ood)
    ood_ae_errors = ae.score_batch(X_ood)
    ood_iso_score = -iso.decision_function(X_ood)
    cal_iso_score = -iso.decision_function(X_cal[calibration_benign])
    cal_z = stat.max_z_scores(X_cal[calibration_benign])
    ood_z = stat.max_z_scores(X_ood)
    high_conf_ood = ood_stat & (ood_labels != "Benign") & (
        ood_conf >= clf.confidence_threshold
    )
    ood_review = ood_stat & ~high_conf_ood & (
        (ood_ae_errors > ae.threshold) | (ood_labels != "Benign")
    )
    negative_ae = final_ae_errors[final["y"] == "Benign"]
    negative_iso = -iso.decision_function(X_final[final["y"] == "Benign"])
    negative_z = stat.max_z_scores(X_final[final["y"] == "Benign"])
    score_components = {
        "autoencoder": (
            negative_ae / max(ae.threshold, 1e-12),
            ood_ae_errors / max(ae.threshold, 1e-12),
        ),
        "isolation_forest": (
            negative_iso / max(float(np.quantile(cal_iso_score, 0.99)), 1e-12),
            ood_iso_score / max(float(np.quantile(cal_iso_score, 0.99)), 1e-12),
        ),
        "statistical": (
            negative_z / max(float(np.quantile(cal_z, 0.99)), 1e-12),
            ood_z / max(float(np.quantile(cal_z, 0.99)), 1e-12),
        ),
    }
    ood_ablation = {}
    truth = np.concatenate([np.zeros(len(negative_ae)), np.ones(len(X_ood))])
    for name, (negative_score, positive_score) in score_components.items():
        scores = np.concatenate([negative_score, positive_score])
        ood_ablation[name] = {
            "auroc": float(roc_auc_score(truth, scores)),
            "pr_auc": float(average_precision_score(truth, scores)),
        }
    ensemble_negative = np.maximum.reduce([row[0] for row in score_components.values()])
    ensemble_positive = np.maximum.reduce([row[1] for row in score_components.values()])
    ensemble_scores = np.concatenate([ensemble_negative, ensemble_positive])
    ood_ablation["max_signal_ensemble"] = {
        "auroc": float(roc_auc_score(truth, ensemble_scores)),
        "pr_auc": float(average_precision_score(truth, ensemble_scores)),
    }
    best_single_auc = max(value["auroc"] for key, value in ood_ablation.items() if key != "max_signal_ensemble")
    ensemble_kept = ood_ablation["max_signal_ensemble"]["auroc"] > best_single_auc + 0.005

    output_dir.mkdir(parents=True, exist_ok=False)
    split_arrays = {}
    split_summary = {}
    for name, part in partitions.items():
        split_arrays[name + "_row_hashes"] = part["row_hashes"]
        split_arrays[name + "_near_hashes"] = part["near_hashes"]
        split_summary[name] = {
            "rows": int(len(part["y"])),
            "captures": sorted(set(part["capture_ids"].tolist())),
            "labels": dict(sorted(Counter(part["y"]).items())),
            "row_hash_sha256": hashlib.sha256(part["row_hashes"].tobytes()).hexdigest(),
            "near_hash_sha256": hashlib.sha256(part["near_hashes"].tobytes()).hexdigest(),
            "removed_exact_overlap": part["removed_exact_overlap"],
            "removed_near_overlap": part["removed_near_overlap"],
        }
    split_path = output_dir / "split_manifest.npz"
    np.savez_compressed(split_path, **split_arrays)
    split_manifest = {
        "schema_version": "cyberguard-split-manifest-v1",
        "seed": SEED,
        "precedence": ["training", "calibration", "final_test", "ood_test"],
        "deduplication": "exact and log-rounded near hash removed globally before fitting",
        "partitions": split_summary,
        "npz_sha256": sha256_file(split_path),
    }
    _atomic_json(output_dir / "split_manifest.json", split_manifest)

    norm.save(output_dir / "normalizer.pkl")
    stat.save(output_dir / "statistical.pkl")
    clf.save(output_dir / "classifier.pkl")
    ae.save(output_dir / "autoencoder.pt")
    joblib.dump(iso, output_dir / "isolation_forest.pkl")

    benchmark = _benchmark(norm, stat, clf, ae, final["X"])
    drift = _drift(
        X_train[benign_train],
        X_final[final["y"] == "Benign"],
    )
    ood_metrics = {
        "family_labels": dict(sorted(Counter(ood["y"]).items())),
        "rows": int(len(ood["y"])),
        "high_confidence_known_mislabel_rate": float(high_conf_ood.mean()),
        "review_route_rate": float(ood_review.mean()),
        "ablation": ood_ablation,
        "ensemble_retained": ensemble_kept,
        "ensemble_rule": "max of calibrated anomaly signals" if ensemble_kept else "not added; no AUROC gain over best single signal",
    }
    autoencoder_metrics = {
        "threshold": ae.threshold,
        "threshold_method": "capture_disjoint_calibration_benign_p99.5",
        "train_benign": _error_distribution(ae.score_batch(X_train[benign_indices[:100_000]])),
        "calibration_benign": _error_distribution(calibration_errors),
        "test_benign": _error_distribution(final_ae_errors[final["y"] == "Benign"]),
        "known_attack": _error_distribution(final_ae_errors[final["y"] != "Benign"]),
        "heldout_family": _error_distribution(ood_ae_errors),
    }

    supports = [row["support"] for row in classifier_metrics["per_class"].values()]
    pre_gate_payload = {
        "classifier": classifier_metrics,
        "binary": final_binary,
        "ood": ood_metrics,
        "autoencoder": autoencoder_metrics,
    }
    gate_results = {
        "final_at_least_10000_rows": len(final["y"]) >= MIN_FINAL_ROWS,
        "all_trained_classes_have_independent_support": bool(supports) and min(supports) >= MIN_CLASS_SUPPORT,
        "pipeline_beats_statistical_binary_f1": (
            final_binary["pipeline"]["f1"] > final_binary["statistical"]["f1"]
        ),
        "pipeline_beats_isolation_forest_binary_f1": (
            final_binary["pipeline"]["f1"] > final_binary["isolation_forest"]["f1"]
        ),
        "benign_fpr_within_validation_budget": (
            final_binary["pipeline"]["benign_false_positive_rate"] <= BENIGN_FPR_BUDGET
        ),
        "ood_high_confidence_mislabel_within_budget": (
            ood_metrics["high_confidence_known_mislabel_rate"] <= OOD_HIGH_CONFIDENCE_BUDGET
        ),
        "classifier_calibration_ece_at_most_0_10": (
            classifier_metrics["expected_calibration_error_10_bin"] <= 0.10
        ),
        "all_results_finite": _all_finite(pre_gate_payload),
    }
    status = "shadow_only_not_promoted" if all(gate_results.values()) else "failed_gates"
    peak_vram = int(torch.cuda.max_memory_allocated()) if torch.cuda.is_available() else 0
    results = {
        "schema_version": "cyberguard-candidate-metrics-v1",
        "candidate_status": status,
        "production_approved": False,
        "quality_gates_declared_before_final": {
            "minimum_final_rows": MIN_FINAL_ROWS,
            "minimum_independent_class_support": MIN_CLASS_SUPPORT,
            "maximum_benign_fpr": BENIGN_FPR_BUDGET,
            "maximum_ood_high_confidence_mislabel_rate": OOD_HIGH_CONFIDENCE_BUDGET,
            "maximum_ece": 0.10,
            "must_beat_statistical_and_isolation_forest_binary_f1": True,
        },
        "quality_gate_results": gate_results,
        "classifier": classifier_metrics,
        "binary_attack_vs_benign": final_binary,
        "routing": routing,
        "ood": ood_metrics,
        "autoencoder": autoencoder_metrics,
        "classifier_calibration": classifier_calibration,
        "statistical_calibration": {
            "threshold": stat.threshold,
            "method": "capture_disjoint_calibration_benign_p99",
            "false_positive_budget": BENIGN_FPR_BUDGET,
        },
        "drift": drift,
        "benchmark": benchmark,
        "resources": {
            "peak_process_rss_kib": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
            "peak_cuda_bytes": peak_vram,
            "artifact_bytes": {},
        },
        "split_manifest_sha256": sha256_file(output_dir / "split_manifest.json"),
        "dataset_audit_sha256": sha256_file(audit_path),
        "limitations": [
            "Numerical flow features do not inspect SQL/XSS payload text.",
            "CSE-CIC-IDS2018 is controlled testbed traffic, not current production telemetry.",
            "BruteForce and DDoS were held out and are not supervised classifier classes.",
            "Checksum provenance is locally observed because the publisher did not publish SHA-256.",
            "Joblib classifier/scaler artifacts remain executable formats protected by a private checksum manifest."
        ],
    }
    for filename in (
        "normalizer.pkl", "statistical.pkl", "classifier.pkl", "autoencoder.pt",
        "isolation_forest.pkl", "split_manifest.json", "split_manifest.npz",
    ):
        results["resources"]["artifact_bytes"][filename] = (output_dir / filename).stat().st_size
    _atomic_json(output_dir / "metrics.json", results)

    packages = {}
    for name in ("numpy", "pandas", "scikit-learn", "xgboost", "torch", "scipy"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = "missing"
    reproducibility = {
        "seed": SEED,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cuda_available": torch.cuda.is_available(),
        "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "packages": packages,
        "source_snapshot_sha256": _source_snapshot_hash(),
        "split_manifest_sha256": results["split_manifest_sha256"],
        "dataset_audit_sha256": results["dataset_audit_sha256"],
    }
    entries = [
        {
            "id": capture["capture_id"],
            "sha256": capture["sha256"],
        }
        for capture in audit["captures"]
    ]
    write_artifact_manifest(
        output_dir,
        dataset_entries=entries,
        metrics=results,
        classes=list(clf.classes_),
        abstention_threshold=clf.confidence_threshold,
        code_revision=reproducibility["source_snapshot_sha256"],
        production_approved=False,
        autoencoder_metadata={
            "k": ae.k, "threshold": ae.threshold,
            "threshold_status": "capture_disjoint_calibration_benign_p99.5",
        },
        reproducibility=reproducibility,
        candidate_status=status,
    )
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--audit",
        type=Path,
        default=Path("data/datasets/cse-cic-ids2018/dataset_audit.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(train_candidate(args.audit, args.output), indent=2, sort_keys=True))
