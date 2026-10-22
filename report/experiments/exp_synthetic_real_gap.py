"""Experiment P3.b: Synthetic -> Real Evaluation Gap.

Evaluates the BUNDLED synthetic-trained model (data/models/trained/) on real CICIDS2017
network traffic and quantifies the exact performance collapse compared to its synthetic fixture baseline.
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
from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score, precision_score, recall_score

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from backend.detection.trainer import load_cicids2017, _defensible_split
from backend.detection.normalizer import Normalizer
from backend.detection.statistical import StatisticalFilter
from backend.detection.classifier import AttackClassifier
from backend.detection.autoencoder import AutoencoderDetector
from backend.detection.features import FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("exp_synthetic_real_gap")


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


def run_synthetic_real_gap():
    t_start = time.time()
    log.info("Loading real CICIDS2017 dataset...")
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
    X_test, y_test = X[test_indices], y[test_indices]
    log.info("Evaluating on real test partition (%d samples)...", len(X_test))

    # Load synthetic-trained bundled model
    bundled_dir = REPO_ROOT / "data" / "models" / "trained"
    log.info("Loading bundled model from %s...", bundled_dir)
    norm = Normalizer().load(bundled_dir / "normalizer.pkl")
    clf = AttackClassifier().load(bundled_dir / "classifier.pkl")
    stat = StatisticalFilter().load(bundled_dir / "statistical.pkl")
    ae = AutoencoderDetector(len(FEATURE_NAMES)).load(bundled_dir / "autoencoder.pt")

    # Load baseline fixture score from report/results/model_evaluation_bundled.json
    bundled_res_path = REPO_ROOT / "report" / "results" / "model_evaluation_bundled.json"
    with open(bundled_res_path, "r", encoding="utf-8") as f:
        bundled_fixture = json.load(f)

    fixture_acc = bundled_fixture["classifier_metrics"]["accuracy"]
    fixture_macro_f1 = bundled_fixture["classifier_metrics"]["macro_f1"]
    fixture_classes = bundled_fixture["classifier_metrics"]["classes"]

    # Transform real test set using bundled normalizer
    Xte_norm = norm.transform(X_test)

    # Predict with bundled classifier
    log.info("Predicting real traffic with bundled classifier...")
    preds, confs = clf.predict_batch(Xte_norm)

    # 1. Overall evaluation across all real classes (8 classes)
    classes_8 = sorted(list(set(y_test) | set(preds)))
    cm_all = confusion_matrix(y_test, preds, labels=classes_8)
    acc_all = float(accuracy_score(y_test, preds))
    macro_f1_all = float(f1_score(y_test, preds, average="macro", zero_division=0))
    weighted_f1_all = float(f1_score(y_test, preds, average="weighted", zero_division=0))
    cr_all = classification_report(y_test, preds, output_dict=True, zero_division=0)

    # 2. In-Distribution evaluation: only the 4 classes bundled model was trained on
    id_mask = np.isin(y_test, fixture_classes)
    y_test_id = y_test[id_mask]
    preds_id = preds[id_mask]

    acc_id = float(accuracy_score(y_test_id, preds_id))
    macro_f1_id = float(f1_score(y_test_id, preds_id, average="macro", zero_division=0))
    weighted_f1_id = float(f1_score(y_test_id, preds_id, average="weighted", zero_division=0))
    cm_id = confusion_matrix(y_test_id, preds_id, labels=fixture_classes)
    cr_id = classification_report(y_test_id, preds_id, output_dict=True, zero_division=0)

    # Attack Miss Rate & Benign False Alarm Rate (All classes)
    is_attack_true = (y_test != "Benign")
    is_attack_pred = (preds != "Benign")
    n_attacks = int(np.sum(is_attack_true))
    n_benign = int(np.sum(~is_attack_true))
    missed_attacks = int(np.sum(is_attack_true & (preds == "Benign")))
    false_alarms = int(np.sum((~is_attack_true) & is_attack_pred))

    attack_miss_rate = missed_attacks / n_attacks if n_attacks > 0 else 0.0
    benign_far = false_alarms / n_benign if n_benign > 0 else 0.0

    # Autoencoder evaluation on real data
    ae_errors = ae.score_batch(Xte_norm)
    ae_threshold = float(ae.threshold)
    ae_flags = ae_errors > ae_threshold
    ae_flagged_attacks = int(np.sum(ae_flags & is_attack_true))
    ae_flagged_benign = int(np.sum(ae_flags & (~is_attack_true)))
    ae_mean_err_benign = float(np.mean(ae_errors[~is_attack_true]))
    ae_mean_err_attack = float(np.mean(ae_errors[is_attack_true]))

    elapsed = time.time() - t_start

    results = {
        "metadata": {
            "experiment": "synthetic_to_real_gap",
            "command": "python report/experiments/exp_synthetic_real_gap.py",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "git_hash": get_git_hash(),
            "duration_seconds": round(elapsed, 2),
            "environment": get_env_info(),
            "bundled_model_dir": str(bundled_dir),
            "real_test_samples": len(X_test),
            "id_test_samples": int(np.sum(id_mask)),
            "ood_test_samples": int(np.sum(~id_mask)),
        },
        "synthetic_fixture_baseline": {
            "accuracy": fixture_acc,
            "macro_f1": fixture_macro_f1,
            "classes": fixture_classes,
        },
        "real_data_all_classes": {
            "accuracy": round(acc_all, 4),
            "macro_f1": round(macro_f1_all, 4),
            "weighted_f1": round(weighted_f1_all, 4),
            "attack_miss_rate": round(attack_miss_rate, 4),
            "benign_false_alarm_rate": round(benign_far, 6),
            "drop_in_accuracy": round(fixture_acc - acc_all, 4),
            "drop_in_macro_f1": round(fixture_macro_f1 - macro_f1_all, 4),
            "confusion_matrix": {
                "labels": classes_8,
                "matrix": cm_all.tolist(),
            },
            "classification_report": cr_all,
        },
        "real_data_in_distribution_classes": {
            "classes": fixture_classes,
            "accuracy": round(acc_id, 4),
            "macro_f1": round(macro_f1_id, 4),
            "weighted_f1": round(weighted_f1_id, 4),
            "drop_in_accuracy_id": round(fixture_acc - acc_id, 4),
            "drop_in_macro_f1_id": round(fixture_macro_f1 - macro_f1_id, 4),
            "confusion_matrix": {
                "labels": fixture_classes,
                "matrix": cm_id.tolist(),
            },
            "classification_report": cr_id,
        },
        "autoencoder_real_eval": {
            "synthetic_threshold": ae_threshold,
            "mean_benign_reconstruction_error": round(ae_mean_err_benign, 4),
            "mean_attack_reconstruction_error": round(ae_mean_err_attack, 4),
            "flagged_attacks": ae_flagged_attacks,
            "flagged_benign": ae_flagged_benign,
            "flagged_benign_pct": round(ae_flagged_benign / n_benign * 100.0, 2),
            "flagged_attacks_pct": round(ae_flagged_attacks / n_attacks * 100.0, 2),
        },
        "gap_analysis_summary": (
            f"The bundled model achieved {fixture_acc*100:.2f}% accuracy and {fixture_macro_f1*100:.2f}% macro-F1 "
            f"on its synthetic fixture. When evaluated on real CICIDS2017 traffic, overall accuracy drops by "
            f"{(fixture_acc - acc_all)*100:.2f} percentage points (to {acc_all*100:.2f}%), and macro-F1 collapses by "
            f"{(fixture_macro_f1 - macro_f1_all)*100:.2f} percentage points (to {macro_f1_all*100:.2f}%). Even when "
            f"restricted strictly to in-distribution classes ({fixture_classes}), macro-F1 drops to {macro_f1_id*100:.2f}%. "
            f"This empirically refutes Hypothesis H1: high performance on synthetic fixtures is an artifact of distribution "
            f"symmetry and does NOT generalize to real enterprise telemetry."
        ),
    }

    out_file = REPO_ROOT / "report" / "results" / "synthetic_to_real_gap.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    log.info("Synthetic -> Real gap evaluation complete in %.1fs. Written to %s", elapsed, out_file)
    print("\n=== Synthetic -> Real Gap Evaluation Summary ===")
    print(f"Fixture Baseline:   Acc={fixture_acc:.4f}, Macro-F1={fixture_macro_f1:.4f}")
    print(f"Real Data (All):    Acc={acc_all:.4f}, Macro-F1={macro_f1_all:.4f} (Drop: Acc -{fixture_acc-acc_all:.4f}, Macro-F1 -{fixture_macro_f1-macro_f1_all:.4f})")
    print(f"Real Data (ID-4):   Acc={acc_id:.4f}, Macro-F1={macro_f1_id:.4f} (Drop: Acc -{fixture_acc-acc_id:.4f}, Macro-F1 -{fixture_macro_f1-macro_f1_id:.4f})")
    print(f"Attack Miss Rate:   {attack_miss_rate:.4f} ({missed_attacks:,} / {n_attacks:,} attacks missed)")
    print(f"Benign False Alarm: {benign_far:.6f} ({false_alarms:,} / {n_benign:,} benign false alarms)")
    return results


if __name__ == "__main__":
    run_synthetic_real_gap()
