"""Training + evaluation on CICIDS2017.

Rules enforced here (thesis fixes):
- Never evaluate on fewer than 10,000 test samples. (Thesis: 40-100 samples)
- Always report precision / recall / F1 / confusion matrix. (Thesis: BERTScore)
- Always compare against baselines: Z-Score alone, Isolation Forest alone.
  (Thesis: no baselines at all)
- Never fabricate numbers. If the test hasn't run, we say so.
"""
from __future__ import annotations
import json
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import (precision_recall_fscore_support,
                             confusion_matrix, classification_report)
from sklearn.ensemble import IsolationForest
from .features import extract_features, FEATURE_NAMES
from .normalizer import Normalizer
from .statistical import StatisticalFilter
from .classifier import AttackClassifier
from .autoencoder import AutoencoderDetector

log = logging.getLogger("cyberguard.trainer")

MIN_TEST_SAMPLES = 10_000

# ── CICIDS2017 label normalization ────────────────────────────────────────────
# The dataset has inconsistent label casing and naming across CSV files.
_LABEL_MAP = {
    "BENIGN": "Benign",
    "benign": "Benign",
    "DDoS": "DDoS",
    "ddos": "DDoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Heartbleed": "DoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack – Brute Force": "WebAttack",
    "Web Attack – XSS": "WebAttack",
    "Web Attack – Sql Injection": "WebAttack",
    "Web Attack Brute Force": "WebAttack",
    "Web Attack XSS": "WebAttack",
    "Web Attack Sql Injection": "WebAttack",
    "Bot": "Bot",
    "Infiltration": "Infiltration",
}


def normalize_label(raw: str) -> str:
    """Map any raw CICIDS2017 label to a canonical class name."""
    stripped = raw.strip()
    if stripped in _LABEL_MAP:
        return _LABEL_MAP[stripped]
    # Try case-insensitive partial match
    lower = stripped.lower().replace(" ", "").replace("-", "").replace("–", "")
    for key, val in _LABEL_MAP.items():
        if key.lower().replace(" ", "").replace("-", "").replace("–", "") == lower:
            return val
    # Default: keep original but title-case it
    return stripped


def load_cicids2017(csv_dir: str | Path) -> tuple[np.ndarray, np.ndarray]:
    """Load MachineLearningCSV directory → (X_raw_features, y_labels).

    Args:
        csv_dir: Path to directory containing CICIDS2017 CSV files.

    Returns:
        (X, y) — feature matrix and normalized label array.
    """
    csv_path = Path(csv_dir)
    files = sorted(csv_path.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {csv_dir}")

    log.info("Loading %d CSV files from %s", len(files), csv_dir)
    frames = []
    for f in files:
        try:
            df = pd.read_csv(f, low_memory=False)
            df.columns = df.columns.str.strip()
            frames.append(df)
            log.info("  Loaded %s: %d rows", f.name, len(df))
        except Exception as e:
            log.warning("  Skipping %s: %s", f.name, e)

    if not frames:
        raise ValueError("No valid CSV files found")

    df = pd.concat(frames, ignore_index=True)
    df.columns = df.columns.str.strip()

    # Find label column
    label_col = None
    for candidate in ["Label", "label", " Label"]:
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise KeyError("No 'Label' column found in CSV files")

    # Normalize labels
    y = df[label_col].astype(str).map(normalize_label).to_numpy()

    # Extract features
    feats_df = df.drop(columns=[label_col], errors="ignore")
    records = feats_df.to_dict("records")

    log.info("Extracting features from %d records...", len(records))
    X = np.array([[extract_features(row)[n] for n in FEATURE_NAMES]
                  for row in records], dtype=float)

    # Clean infinities and NaN
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    log.info("Dataset loaded: %d samples × %d features, %d classes",
             X.shape[0], X.shape[1], len(np.unique(y)))
    return X, y


def train_all(csv_dir: str | Path, out_dir: str | Path) -> dict:
    """Train all pipeline stages and save models.

    Args:
        csv_dir: Path to CICIDS2017 CSV directory.
        out_dir: Path to save trained model files.

    Returns:
        Evaluation results dict with metrics and comparisons.
    """
    X, y = load_cicids2017(csv_dir)

    # Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)

    if len(X_test) < MIN_TEST_SAMPLES:
        raise ValueError(f"Test set too small: {len(X_test)} < {MIN_TEST_SAMPLES}")

    log.info("Train: %d samples, Test: %d samples", len(X_train), len(X_test))

    # Normalize
    norm = Normalizer().fit(X_train)
    Xtr, Xte = norm.transform(X_train), norm.transform(X_test)
    benign_mask_train = y_train == "Benign"
    benign_mask_test = y_test == "Benign"

    # Stage 2: Statistical filter (trained on benign only)
    stat = StatisticalFilter().fit(Xtr[benign_mask_train])

    # Stage 3: XGBoost classifier
    clf = AttackClassifier().fit(Xtr, y_train)

    # Stage 4: Autoencoder (trained on benign only)
    val_benign = Xte[benign_mask_test]
    n_val = min(5000, len(val_benign))
    ae = AutoencoderDetector(n_features=Xtr.shape[1]).fit(
        Xtr[benign_mask_train], val_benign[:n_val])

    # Save all models
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    norm.save(out / "normalizer.pkl")
    stat.save(out / "statistical.pkl")
    clf.save(out / "classifier.pkl")
    ae.save(out / "autoencoder.pt")

    log.info("All models saved to %s", out)
    return evaluate_all(stat, clf, ae, norm, Xte, y_test)


def evaluate_all(stat, clf, ae, norm, X_test, y_test) -> dict:
    """Full pipeline vs baselines. No fabricated numbers — everything here
    is computed from the actual test split.

    Returns:
        Dict with classifier metrics, baseline comparisons, and test size.
    """
    # Pipeline classifier evaluation
    labels_pred, _ = clf.predict_batch(X_test)
    p, r, f1, _ = precision_recall_fscore_support(
        y_test, labels_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_test, labels_pred).tolist()

    # Binary: attack vs benign
    y_binary = np.where(y_test == "Benign", "BENIGN", "ATTACK")
    pred_binary = np.where(labels_pred == "Benign", "BENIGN", "ATTACK")

    # Baseline 1: Z-Score alone (flags = attack)
    z_pred = np.where(stat.filter_batch(X_test), "ATTACK", "BENIGN")
    zp, zr, zf, _ = precision_recall_fscore_support(
        y_binary, z_pred, average="binary", pos_label="ATTACK", zero_division=0)

    # Baseline 2: Isolation Forest alone
    iso = IsolationForest(contamination=0.1, n_jobs=-1, random_state=42)
    iso.fit(X_test[y_test == "Benign"][:10000])
    iso_pred = np.where(iso.predict(X_test) == -1, "ATTACK", "BENIGN")
    ip, ir, if1, _ = precision_recall_fscore_support(
        y_binary, iso_pred, average="binary", pos_label="ATTACK", zero_division=0)

    # Autoencoder zero-day scoring
    ae_errors = ae.score_batch(X_test)
    ae_flagged = np.sum(ae_errors > ae.threshold) if ae.threshold else 0

    results = {
        "test_samples": int(len(X_test)),
        "classifier": {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f1), 4),
            "confusion_matrix": cm,
            "report": classification_report(y_test, labels_pred, zero_division=0),
        },
        "baseline_zscore": {
            "precision": round(float(zp), 4),
            "recall": round(float(zr), 4),
            "f1": round(float(zf), 4),
        },
        "baseline_isolation_forest": {
            "precision": round(float(ip), 4),
            "recall": round(float(ir), 4),
            "f1": round(float(if1), 4),
        },
        "autoencoder": {
            "threshold": round(float(ae.threshold or 0), 4),
            "flagged_zero_day": int(ae_flagged),
            "mean_error_benign": round(float(ae_errors[y_test == "Benign"].mean()), 4),
            "mean_error_attack": round(float(ae_errors[y_test != "Benign"].mean()), 4),
        },
        "feature_importance": clf.feature_importance(10),
    }

    log.info("Evaluation complete: Classifier F1=%.4f, Z-Score F1=%.4f, IF F1=%.4f",
             f1, zf, if1)
    return results


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    if len(sys.argv) < 3:
        print("Usage: python -m backend.detection.trainer <csv_dir> <output_dir>")
        sys.exit(1)
    results = train_all(sys.argv[1], sys.argv[2])
    print(json.dumps({k: v for k, v in results.items()
                      if k != "classifier"}, indent=2))
    print(results["classifier"]["report"])
