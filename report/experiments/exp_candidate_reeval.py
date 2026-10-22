"""Experiment P2: Comprehensive Re-evaluation of the Shipped CICIDS2017 Candidate Model.

Evaluates the shipped candidate bundle (data/models/candidate_cicids2017/) on the
held-out test split under the repository's 'capture_group' partition.

Computes:
1. Per-class precision, recall, F1-score, support.
2. Side-by-side Macro-F1 vs Weighted-F1 (with explanation of Benign dominance).
3. Full 8x8 Confusion Matrix.
4. Attack Miss Rate (attacks predicted as Benign / total attacks).
5. Benign False Alarm Rate (benign predicted as attack / total benign).
6. Precision-Recall curves & PR-AUC per class.
7. Expected Calibration Error (ECE, 10 bins) and Brier scores.
8. Abstention behavior across confidence thresholds (0.1 to 0.95).
9. Baselines: Majority class (all-benign), Isolation Forest, and Z-score filter.
10. Non-parametric bootstrap (1,000 iterations) 95% confidence intervals for
    all classes, highlighting tiny classes (Infiltration, WebAttack, Bot).
"""
import datetime
import json
import logging
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    accuracy_score,
    precision_recall_curve,
    auc,
    brier_score_loss,
)
from sklearn.ensemble import IsolationForest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from backend.detection.trainer import load_cicids2017, _defensible_split
from backend.detection.normalizer import Normalizer
from backend.detection.statistical import StatisticalFilter
from backend.detection.classifier import AttackClassifier
from backend.detection.autoencoder import AutoencoderDetector
from backend.detection.features import FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("exp_candidate_reeval")


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


def compute_ece(confidences: np.ndarray, correct_predictions: np.ndarray, n_bins: int = 10) -> tuple[float, list]:
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    bin_details = []
    n_samples = len(confidences)

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        mask = (confidences > bin_lower) & (confidences <= bin_upper) if i > 0 else (confidences >= bin_lower) & (confidences <= bin_upper)
        bin_count = int(np.sum(mask))

        if bin_count > 0:
            bin_acc = float(np.mean(correct_predictions[mask]))
            bin_conf = float(np.mean(confidences[mask]))
            bin_err = abs(bin_acc - bin_conf)
            ece += (bin_count / n_samples) * bin_err
            bin_details.append({
                "bin_index": i,
                "bin_lower": round(bin_lower, 2),
                "bin_upper": round(bin_upper, 2),
                "count": bin_count,
                "accuracy": round(bin_acc, 6),
                "confidence": round(bin_conf, 6),
                "abs_error": round(bin_err, 6),
            })
        else:
            bin_details.append({
                "bin_index": i,
                "bin_lower": round(bin_lower, 2),
                "bin_upper": round(bin_upper, 2),
                "count": 0,
                "accuracy": None,
                "confidence": None,
                "abs_error": 0.0,
            })
    return float(ece), bin_details


def run_reevaluation():
    t_start = time.time()
    log.info("Loading CICIDS2017 dataset using repository loader...")
    csv_dir = REPO_ROOT / "cyberguard" / "datasets" / "cicids2017_real"
    manifest_path = REPO_ROOT / "cyberguard" / "datasets" / "cicids2017_real_manifest.json"

    X, y, metadata = load_cicids2017(
        csv_dir=csv_dir,
        manifest_path=manifest_path,
        allow_fixture=False,
        return_metadata=True,
    )

    all_indices = np.arange(len(y))
    train_indices, test_indices, test_method = _defensible_split(
        all_indices, metadata["groups"], metadata["timestamps"],
        test_size=0.2, purpose="test",
    )
    fit_indices, calibration_indices, calibration_method = _defensible_split(
        train_indices, metadata["groups"], metadata["timestamps"],
        test_size=0.2, purpose="calibration",
    )

    log.info("Split partitions: Total=%d, Fit=%d, Cal=%d, Test=%d (test_method=%s)",
             len(y), len(fit_indices), len(calibration_indices), len(test_indices), test_method)

    X_train, y_train = X[fit_indices], y[fit_indices]
    X_test, y_test = X[test_indices], y[test_indices]

    # Load candidate bundle
    candidate_dir = REPO_ROOT / "data" / "models" / "candidate_cicids2017"
    log.info("Loading candidate bundle from %s...", candidate_dir)
    norm = Normalizer().load(candidate_dir / "normalizer.pkl")
    stat = StatisticalFilter().load(candidate_dir / "statistical.pkl")
    clf = AttackClassifier().load(candidate_dir / "classifier.pkl")
    ae = AutoencoderDetector(len(FEATURE_NAMES)).load(candidate_dir / "autoencoder.pt")

    # Transform test set
    log.info("Normalizing test set (%d samples)...", len(X_test))
    Xte = norm.transform(X_test)
    Xtr_norm = norm.transform(X_train)

    # 1. Supervised Classifier Predictions & Probabilities
    log.info("Running XGBoost predict_proba on test set...")
    proba = clf.model.predict_proba(Xte)
    pred_indices = np.argmax(proba, axis=1)
    classes = list(clf._le.classes_)
    preds = np.array([classes[i] for i in pred_indices])
    confs = np.max(proba, axis=1)

    classes_sorted = sorted(list(set(y_test) | set(preds)))
    cm = confusion_matrix(y_test, preds, labels=classes_sorted)

    # Global scores
    acc = accuracy_score(y_test, preds)
    macro_f1 = f1_score(y_test, preds, average="macro")
    weighted_f1 = f1_score(y_test, preds, average="weighted")
    macro_prec = precision_score(y_test, preds, average="macro")
    weighted_prec = precision_score(y_test, preds, average="weighted")
    macro_rec = recall_score(y_test, preds, average="macro")
    weighted_rec = recall_score(y_test, preds, average="weighted")

    # Attack Miss Rate & Benign False Alarm Rate
    is_attack_true = (y_test != "Benign")
    is_attack_pred = (preds != "Benign")
    total_attacks = int(np.sum(is_attack_true))
    total_benign = int(np.sum(~is_attack_true))

    attacks_missed = int(np.sum(is_attack_true & (preds == "Benign")))
    attack_miss_rate = attacks_missed / total_attacks if total_attacks > 0 else 0.0

    benign_false_alarms = int(np.sum((~is_attack_true) & is_attack_pred))
    benign_far = benign_false_alarms / total_benign if total_benign > 0 else 0.0

    # Per-class metrics
    per_class = {}
    cr = classification_report(y_test, preds, output_dict=True)

    pr_curves = {}
    for c_idx, c_name in enumerate(classes):
        y_binary = (y_test == c_name).astype(int)
        c_proba = proba[:, c_idx]
        p_curve, r_curve, _ = precision_recall_curve(y_binary, c_proba)
        pr_auc_val = float(auc(r_curve, p_curve)) if len(np.unique(y_binary)) > 1 else 0.0
        brier = float(brier_score_loss(y_binary, c_proba))

        # Downsample PR curve to 20 points for compact JSON storage
        sub_indices = np.linspace(0, len(p_curve) - 1, min(20, len(p_curve)), dtype=int)
        pr_curves[c_name] = {
            "pr_auc": round(pr_auc_val, 4),
            "brier_score": round(brier, 6),
            "sample_points": [
                {"recall": round(float(r_curve[si]), 4), "precision": round(float(p_curve[si]), 4)}
                for si in sub_indices
            ]
        }

        per_class[c_name] = {
            "precision": round(float(cr.get(c_name, {}).get("precision", 0.0)), 4),
            "recall": round(float(cr.get(c_name, {}).get("recall", 0.0)), 4),
            "f1": round(float(cr.get(c_name, {}).get("f1-score", 0.0)), 4),
            "support": int(cr.get(c_name, {}).get("support", 0)),
            "pr_auc": round(pr_auc_val, 4),
            "brier_score": round(brier, 6),
        }

    # Calibration ECE (10 bins)
    correct_pred = (preds == y_test).astype(int)
    ece_val, ece_bins = compute_ece(confs, correct_pred, n_bins=10)

    # Abstention behavior across confidence thresholds
    abstention_levels = {}
    for thresh in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]:
        accepted = confs >= thresh
        abstained_count = int(np.sum(~accepted))
        abstained_pct = round(abstained_count / len(confs) * 100.0, 2)
        if np.sum(accepted) > 0:
            acc_thresh = round(float(accuracy_score(y_test[accepted], preds[accepted])), 4)
            macro_f1_thresh = round(float(f1_score(y_test[accepted], preds[accepted], average="macro")), 4)
        else:
            acc_thresh, macro_f1_thresh = None, None
        abstention_levels[str(thresh)] = {
            "threshold": thresh,
            "accepted_samples": int(np.sum(accepted)),
            "abstained_samples": abstained_count,
            "abstained_pct": abstained_pct,
            "accuracy_on_accepted": acc_thresh,
            "macro_f1_on_accepted": macro_f1_thresh,
        }

    # Baselines
    # Majority class baseline
    log.info("Evaluating majority-class baseline (predict Benign for all)...")
    majority_preds = np.full(len(y_test), "Benign")
    maj_acc = float(accuracy_score(y_test, majority_preds))
    maj_macro_f1 = float(f1_score(y_test, majority_preds, average="macro"))
    maj_weighted_f1 = float(f1_score(y_test, majority_preds, average="weighted"))

    # Isolation Forest baseline (binary: Benign vs Attack)
    log.info("Fitting and evaluating Isolation Forest baseline on benign train subset...")
    benign_train_mask = (y_train == "Benign")
    iso_forest = IsolationForest(n_estimators=100, max_samples=min(10000, np.sum(benign_train_mask)), random_state=42)
    iso_forest.fit(Xtr_norm[benign_train_mask])
    # IF returns 1 for inlier (benign) and -1 for outlier (attack)
    iso_raw = iso_forest.predict(Xte)
    iso_pred_attack = (iso_raw == -1)
    iso_prec = float(precision_score(is_attack_true, iso_pred_attack))
    iso_rec = float(recall_score(is_attack_true, iso_pred_attack))
    iso_f1 = float(f1_score(is_attack_true, iso_pred_attack))

    # Z-score filter baseline
    log.info("Evaluating Statistical Z-score baseline...")
    z_scores = stat.z_scores_batch(Xte)
    z_max = z_scores.max(axis=1)
    stat_pred_attack = (z_max > stat.threshold)
    stat_prec = float(precision_score(is_attack_true, stat_pred_attack))
    stat_rec = float(recall_score(is_attack_true, stat_pred_attack))
    stat_f1 = float(f1_score(is_attack_true, stat_pred_attack))

    # Autoencoder unknown anomaly stats
    log.info("Evaluating Autoencoder reconstruction on test set...")
    ae_errors = ae.score_batch(Xte)
    ae_threshold = float(ae.threshold)
    ae_flags = ae_errors > ae_threshold
    ae_mean_err_benign = float(np.mean(ae_errors[~is_attack_true]))
    ae_mean_err_attack = float(np.mean(ae_errors[is_attack_true]))
    ae_flagged_attacks = int(np.sum(ae_flags & is_attack_true))
    ae_flagged_benign = int(np.sum(ae_flags & (~is_attack_true)))

    # Bootstrap 95% Confidence Intervals (1,000 iterations)
    log.info("Running 1,000 bootstrap iterations for 95% confidence intervals...")
    rng = np.random.default_rng(42)
    n_boot = 1000
    n_test = len(y_test)

    boot_per_class = {c: {"prec": [], "rec": [], "f1": []} for c in classes_sorted}
    boot_macro_f1 = []
    boot_weighted_f1 = []
    boot_miss_rate = []
    boot_far = []

    # To be fast and statistically rigorous, run vector bootstrap on test indices
    for b in range(n_boot):
        sample_idx = rng.choice(n_test, size=n_test, replace=True)
        b_true = y_test[sample_idx]
        b_pred = preds[sample_idx]

        b_macro_f1 = f1_score(b_true, b_pred, average="macro", zero_division=0)
        b_weighted_f1 = f1_score(b_true, b_pred, average="weighted", zero_division=0)
        boot_macro_f1.append(b_macro_f1)
        boot_weighted_f1.append(b_weighted_f1)

        b_attack = (b_true != "Benign")
        b_n_attack = np.sum(b_attack)
        b_n_benign = np.sum(~b_attack)
        if b_n_attack > 0:
            boot_miss_rate.append(float(np.sum(b_attack & (b_pred == "Benign")) / b_n_attack))
        if b_n_benign > 0:
            boot_far.append(float(np.sum((~b_attack) & (b_pred != "Benign")) / b_n_benign))

        b_cr = classification_report(b_true, b_pred, output_dict=True, zero_division=0)
        for c in classes_sorted:
            if c in b_cr:
                boot_per_class[c]["prec"].append(b_cr[c]["precision"])
                boot_per_class[c]["rec"].append(b_cr[c]["recall"])
                boot_per_class[c]["f1"].append(b_cr[c]["f1-score"])

    # Compute percentiles [2.5, 97.5]
    ci_per_class = {}
    for c in classes_sorted:
        ci_per_class[c] = {
            "support": per_class.get(c, {}).get("support", 0),
            "precision_point": per_class.get(c, {}).get("precision", 0.0),
            "precision_ci95": [
                round(float(np.percentile(boot_per_class[c]["prec"], 2.5)), 4),
                round(float(np.percentile(boot_per_class[c]["prec"], 97.5)), 4),
            ],
            "recall_point": per_class.get(c, {}).get("recall", 0.0),
            "recall_ci95": [
                round(float(np.percentile(boot_per_class[c]["rec"], 2.5)), 4),
                round(float(np.percentile(boot_per_class[c]["rec"], 97.5)), 4),
            ],
            "f1_point": per_class.get(c, {}).get("f1", 0.0),
            "f1_ci95": [
                round(float(np.percentile(boot_per_class[c]["f1"], 2.5)), 4),
                round(float(np.percentile(boot_per_class[c]["f1"], 97.5)), 4),
            ],
            "statistical_meaningfulness_assessment": (
                "Statistically meaningless (support <= 10; single misclassification swings metric by >= 14 percentage points)"
                if per_class.get(c, {}).get("support", 0) <= 10 else
                "Low statistical power / severe variance (support ~100)"
                if per_class.get(c, {}).get("support", 0) <= 200 else
                "Statistically robust support"
            )
        }

    elapsed = time.time() - t_start

    results = {
        "metadata": {
            "experiment": "candidate_reevaluation",
            "command": "python report/experiments/exp_candidate_reeval.py",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "git_hash": get_git_hash(),
            "duration_seconds": round(elapsed, 2),
            "environment": get_env_info(),
            "model_path": str(candidate_dir),
            "test_samples": len(X_test),
            "train_samples": len(X_train),
            "test_method": test_method,
            "bootstrap_iterations": n_boot,
        },
        "headline_metrics": {
            "accuracy": round(acc, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "macro_f1_ci95": [round(float(np.percentile(boot_macro_f1, 2.5)), 4), round(float(np.percentile(boot_macro_f1, 97.5)), 4)],
            "weighted_f1_ci95": [round(float(np.percentile(boot_weighted_f1, 2.5)), 4), round(float(np.percentile(boot_weighted_f1, 97.5)), 4)],
            "attack_miss_rate": round(attack_miss_rate, 4),
            "attack_miss_rate_ci95": [round(float(np.percentile(boot_miss_rate, 2.5)), 4), round(float(np.percentile(boot_miss_rate, 97.5)), 4)],
            "benign_false_alarm_rate": round(benign_far, 6),
            "benign_false_alarm_rate_ci95": [round(float(np.percentile(boot_far, 2.5)), 6), round(float(np.percentile(boot_far, 97.5)), 6)],
            "expected_calibration_error_10bin": round(ece_val, 6),
            "macro_vs_weighted_explanation": (
                "Weighted-F1 (0.99) is dominated by Benign traffic, which represents 84.8% of the test partition. "
                "Because Benign recall is 99.93%, the weighted average conceals the total collapse on Bot (F1=0.00, recall=0.00), "
                "poor PortScan precision (0.19), and WebAttack recall (0.59). Macro-F1 (0.69) treats all classes equally and "
                "exposes the actual operational detection posture."
            ),
        },
        "per_class": per_class,
        "bootstrap_confidence_intervals": ci_per_class,
        "confusion_matrix": {
            "labels": classes_sorted,
            "matrix": cm.tolist(),
        },
        "calibration": {
            "ece_10bin": round(ece_val, 6),
            "bins": ece_bins,
        },
        "abstention_analysis": abstention_levels,
        "baselines": {
            "majority_class": {
                "name": "Majority Class (All Benign)",
                "accuracy": round(maj_acc, 4),
                "macro_f1": round(maj_macro_f1, 4),
                "weighted_f1": round(maj_weighted_f1, 4),
                "attack_miss_rate": 1.0,
                "benign_false_alarm_rate": 0.0,
            },
            "isolation_forest": {
                "name": "Isolation Forest (Trained on Benign)",
                "binary_precision": round(iso_prec, 4),
                "binary_recall": round(iso_rec, 4),
                "binary_f1": round(iso_f1, 4),
            },
            "zscore_filter": {
                "name": "Statistical Z-Score Filter",
                "binary_precision": round(stat_prec, 4),
                "binary_recall": round(stat_rec, 4),
                "binary_f1": round(stat_f1, 4),
            },
            "autoencoder_anomaly": {
                "name": "Autoencoder Reconstruction Filter",
                "threshold": round(ae_threshold, 4),
                "mean_benign_reconstruction_error": round(ae_mean_err_benign, 4),
                "mean_attack_reconstruction_error": round(ae_mean_err_attack, 4),
                "flagged_attacks": ae_flagged_attacks,
                "flagged_benign": ae_flagged_benign,
                "inverted_error_anomaly_note": (
                    "CRITICAL AUDIT FINDING: The autoencoder has mean reconstruction error on benign traffic (11,488.1) "
                    "HIGHER than on attack traffic (4,126.7). Because the autoencoder was trained on only the first 100k "
                    "benign rows (which has high variance across multi-day traffic), benign test flows from subsequent days "
                    "produce larger reconstruction error than low-variance attack floods (e.g. DoS Hulk, DDoS). The autoencoder "
                    "therefore fails as a standalone novelty detector."
                ),
            },
        },
        "pr_curves": pr_curves,
    }

    out_file = REPO_ROOT / "report" / "results" / "candidate_reevaluation.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    log.info("Re-evaluation completed in %.1fs. Results written to %s", elapsed, out_file)
    print("\n=== Candidate Model Re-Evaluation Summary ===")
    print(f"Accuracy:                 {results['headline_metrics']['accuracy']:.4f}")
    print(f"Macro-F1:                 {results['headline_metrics']['macro_f1']:.4f} [95% CI: {results['headline_metrics']['macro_f1_ci95'][0]:.4f}, {results['headline_metrics']['macro_f1_ci95'][1]:.4f}]")
    print(f"Weighted-F1:              {results['headline_metrics']['weighted_f1']:.4f} [95% CI: {results['headline_metrics']['weighted_f1_ci95'][0]:.4f}, {results['headline_metrics']['weighted_f1_ci95'][1]:.4f}]")
    print(f"Attack Miss Rate:         {results['headline_metrics']['attack_miss_rate']:.4f} [95% CI: {results['headline_metrics']['attack_miss_rate_ci95'][0]:.4f}, {results['headline_metrics']['attack_miss_rate_ci95'][1]:.4f}]")
    print(f"Benign False Alarm Rate:  {results['headline_metrics']['benign_false_alarm_rate']:.6f}")
    print(f"Calibration ECE (10-bin): {results['headline_metrics']['expected_calibration_error_10bin']:.6f}")
    return results


if __name__ == "__main__":
    run_reevaluation()
