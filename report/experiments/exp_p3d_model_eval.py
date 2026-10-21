"""Experiment P3.d: Bundled Model Evaluation on Bundled Deterministic Fixture.

Empirically measures:
1. Known-attack classifier accuracy, per-class Precision, Recall, F1-score, and Confusion Matrix.
2. Autoencoder reconstruction error distribution and threshold exceedance rate.
3. Statistical Z-score distribution and anomaly trigger rate.
4. Explains the synthetic fixture trap and why high metrics on this dataset do not prove real-world IDS efficacy.
"""
import datetime
import json
import os
import platform
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir))

from backend.api.detection import _get_pipeline
from backend.detection.features import FEATURE_NAMES


def get_environment_info():
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "cpu_count": os.cpu_count() or 1,
    }


def run_model_evaluation():
    print("[*] Initializing Pipeline for Model Evaluation...")
    pipeline = _get_pipeline()

    fixture_path = root_dir / "cyberguard" / "datasets" / "cicids2017" / "sample_traffic.csv"
    df = pd.read_csv(fixture_path)
    
    # Ground truth labels in fixture: BENIGN, DDoS, PortScan, Bot
    # Map BENIGN -> Benign to match classifier classes if needed
    true_labels_raw = df["Label"].tolist()
    true_labels = ["Benign" if x.upper() == "BENIGN" else x for x in true_labels_raw]

    raw_matrix = df[FEATURE_NAMES].to_numpy(dtype=float)
    normalized = pipeline.normalizer.transform(raw_matrix)

    # 1. Classifier Evaluation
    pred_labels, confidences = pipeline.clf.predict_batch(normalized)
    
    classes_order = sorted(list(set(true_labels) | set(pred_labels)))
    cm = confusion_matrix(true_labels, pred_labels, labels=classes_order)
    acc = accuracy_score(true_labels, pred_labels)
    macro_f1 = f1_score(true_labels, pred_labels, average="macro")
    clf_report = classification_report(true_labels, pred_labels, output_dict=True)

    # 2. Autoencoder Evaluation
    ae_errors = pipeline.ae.score_batch(normalized)
    ae_threshold = pipeline.ae.threshold
    ae_flags = ae_errors > ae_threshold

    ae_by_class = {}
    for c in classes_order:
        mask = [i for i, lbl in enumerate(true_labels) if lbl == c]
        if mask:
            c_errors = ae_errors[mask]
            c_flags = ae_flags[mask]
            ae_by_class[c] = {
                "count": len(mask),
                "mean_reconstruction_error": round(float(np.mean(c_errors)), 6),
                "median_reconstruction_error": round(float(np.median(c_errors)), 6),
                "std_reconstruction_error": round(float(np.std(c_errors)), 6),
                "min_reconstruction_error": round(float(np.min(c_errors)), 6),
                "p95_reconstruction_error": round(float(np.percentile(c_errors, 95)), 6),
                "p99_reconstruction_error": round(float(np.percentile(c_errors, 99)), 6),
                "max_reconstruction_error": round(float(np.max(c_errors)), 6),
                "flagged_as_anomaly_count": int(np.sum(c_flags)),
                "flagged_rate_pct": round(float(np.sum(c_flags) / len(mask) * 100.0), 2),
            }

    # 3. Statistical Filter Evaluation
    z_matrix = pipeline.stat.z_scores_batch(normalized)
    max_z = z_matrix.max(axis=1)
    stat_threshold = pipeline.stat.threshold
    stat_flags = max_z > stat_threshold

    stat_by_class = {}
    for c in classes_order:
        mask = [i for i, lbl in enumerate(true_labels) if lbl == c]
        if mask:
            c_z = max_z[mask]
            c_sflags = stat_flags[mask]
            stat_by_class[c] = {
                "count": len(mask),
                "mean_max_z": round(float(np.mean(c_z)), 3),
                "median_max_z": round(float(np.median(c_z)), 3),
                "max_max_z": round(float(np.max(c_z)), 3),
                "flagged_as_anomaly_count": int(np.sum(c_sflags)),
                "flagged_rate_pct": round(float(np.sum(c_sflags) / len(mask) * 100.0), 2),
            }

    results = {
        "metadata": {
            "experiment": "P3.d_bundled_model_evaluation",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "fixture_rows": len(df),
            "environment": get_environment_info(),
            "classifier_threshold": pipeline.clf.confidence_threshold,
            "autoencoder_threshold": ae_threshold,
            "statistical_threshold": stat_threshold,
            "tautology_warning": (
                "The bundled model was trained on a synthetic dataset generated with the same parameter distributions "
                "(seed 42). Metrics measured on this fixture reflect fitting to synthetic Gaussian/exponential assumptions, "
                "not generalization to real non-stationary enterprise network traffic."
            )
        },
        "classifier_metrics": {
            "accuracy": round(acc, 4),
            "macro_f1": round(macro_f1, 4),
            "classes": classes_order,
            "confusion_matrix": cm.tolist(),
            "classification_report": clf_report,
            "confidence_distribution": {
                "mean": round(float(np.mean(confidences)), 4),
                "median": round(float(np.median(confidences)), 4),
                "p95": round(float(np.percentile(confidences, 95)), 4),
                "p99": round(float(np.percentile(confidences, 99)), 4),
            }
        },
        "autoencoder_metrics": {
            "threshold": ae_threshold,
            "overall_flagged_rate_pct": round(float(np.mean(ae_flags) * 100.0), 2),
            "by_class": ae_by_class
        },
        "statistical_metrics": {
            "threshold": stat_threshold,
            "overall_flagged_rate_pct": round(float(np.mean(stat_flags) * 100.0), 2),
            "by_class": stat_by_class
        }
    }

    out_dir = root_dir / "report" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "model_evaluation_bundled.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"[*] Model evaluation complete. Saved to {out_path}")
    print(f"[*] Accuracy: {acc:.4f}, Macro-F1: {macro_f1:.4f}")
    print(f"[*] Confusion Matrix ({classes_order}):\n{cm}")
    print("[*] Autoencoder Flag Rate by Class:")
    for c, stats in ae_by_class.items():
        print(f"  {c:10}: {stats['flagged_rate_pct']}% flagged ({stats['mean_reconstruction_error']} mean error)")


if __name__ == "__main__":
    run_model_evaluation()
