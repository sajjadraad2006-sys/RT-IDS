"""Candidate training + evaluation on manifest-validated flow datasets.

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
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (precision_recall_fscore_support,
                             confusion_matrix, classification_report,
                             average_precision_score, brier_score_loss)
from sklearn.preprocessing import label_binarize
from sklearn.ensemble import IsolationForest
from .features import extract_features, extract_features_matrix, FEATURE_NAMES
from .normalizer import Normalizer
from .statistical import StatisticalFilter
from .classifier import AttackClassifier
from .autoencoder import AutoencoderDetector
from .integrity import (
    IntegrityError,
    validate_dataset_manifest,
    write_artifact_manifest,
)
from ..config import BASE_DIR

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
    # CSE-CIC-IDS2018 labels
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Slowloris": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-Hulk": "DoS",
    "Brute Force -Web": "WebAttack",
    "Brute Force -XSS": "WebAttack",
    "SQL Injection": "WebAttack",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DDOS attack-HOIC": "DDoS",
    "FTP-BruteForce": "BruteForce",
    "SSH-Bruteforce": "BruteForce",
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


def _selected_manifest_entries(
    csv_dir: Path, manifest_path: Path, *, allow_fixture: bool
) -> list[dict]:
    entries = validate_dataset_manifest(manifest_path, BASE_DIR)
    selected = [
        item for item in entries
        if Path(item["resolved_path"]).parent.resolve() == csv_dir.resolve()
    ]
    actual = {path.resolve() for path in csv_dir.glob("*.csv")}
    declared = {Path(item["resolved_path"]).resolve() for item in selected}
    if actual != declared:
        missing = sorted(str(path) for path in actual - declared)
        stale = sorted(str(path) for path in declared - actual)
        raise IntegrityError(
            f"training directory and manifest differ; undeclared={missing}, missing={stale}"
        )
    if not selected:
        raise IntegrityError(f"no manifested CSV files selected from {csv_dir}")
    if not allow_fixture:
        rejected = [item["id"] for item in selected if not item["training_approved"]]
        if rejected:
            raise IntegrityError(
                "fixture-only datasets cannot train a deployable candidate: "
                + ", ".join(rejected)
            )
    return selected


def load_cicids2017(
    csv_dir: str | Path,
    *,
    manifest_path: str | Path | None = None,
    allow_fixture: bool = False,
    return_metadata: bool = False,
) -> tuple[np.ndarray, np.ndarray] | tuple[np.ndarray, np.ndarray, dict]:
    """Load MachineLearningCSV directory → (X_raw_features, y_labels).

    Args:
        csv_dir: Path to directory containing CICIDS2017 CSV files.

    Returns:
        (X, y) — feature matrix and normalized label array.
    """
    csv_path = Path(csv_dir).resolve()
    manifest_file = Path(manifest_path or BASE_DIR / "cyberguard/datasets/manifest.json")
    entries = _selected_manifest_entries(
        csv_path, manifest_file, allow_fixture=allow_fixture
    )

    log.info("Loading %d manifest-verified CSV files from %s", len(entries), csv_dir)
    frames = []
    for entry in entries:
        f = Path(entry["resolved_path"])
        try:
            df = pd.read_csv(f, low_memory=False)
            df.columns = df.columns.str.strip()
            df["__capture_id"] = str(entry.get("capture_id", entry["id"]))
            df["__dataset_id"] = str(entry["id"])
            frames.append(df)
            log.info("  Loaded %s: %d rows", f.name, len(df))
        except Exception as e:
            raise IntegrityError(f"validated CSV could not be loaded: {f}: {e}") from e

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

    # Normalize labels and reject unknown classes instead of quietly inventing
    # a new model output contract.
    y = df[label_col].astype(str).map(normalize_label).to_numpy()
    from ..config import CLASSES
    unknown = sorted(set(y) - set(CLASSES))
    if unknown:
        raise IntegrityError(f"unmapped labels in training data: {unknown}")

    groups = df["__capture_id"].astype(str).to_numpy()
    timestamp_col = next(
        (name for name in ("Timestamp", "timestamp", "Flow Start") if name in df.columns),
        None,
    )
    timestamps = (
        pd.to_datetime(df[timestamp_col], errors="coerce", utc=True).astype("int64").to_numpy()
        if timestamp_col else np.full(len(df), np.iinfo("int64").min, dtype=np.int64)
    )

    # Extract features
    feats_df = df.drop(
        columns=[label_col, "__capture_id", "__dataset_id"], errors="ignore"
    )
    records = feats_df.to_dict("records")

    log.info("Extracting features from %d records using vectorized matrix conversion...", len(records))
    X = extract_features_matrix(records)

    # Clean infinities and NaN
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Exact duplicate flows are removed before any split so identical rows can
    # never leak across candidate/calibration/test partitions.
    fingerprints = pd.util.hash_pandas_object(
        pd.DataFrame(X).assign(__label=y), index=False
    ).to_numpy()
    keep = ~pd.Series(fingerprints).duplicated().to_numpy()
    duplicate_count = int((~keep).sum())
    X, y, groups, timestamps = X[keep], y[keep], groups[keep], timestamps[keep]

    log.info("Dataset loaded: %d samples × %d features, %d classes",
             X.shape[0], X.shape[1], len(np.unique(y)))
    if not return_metadata:
        return X, y
    return X, y, {
        "groups": groups,
        "timestamps": timestamps,
        "duplicate_rows_removed": duplicate_count,
        "dataset_entries": entries,
    }


def _defensible_split(
    indices: np.ndarray,
    groups: np.ndarray,
    timestamps: np.ndarray,
    *,
    test_size: float,
    purpose: str,
) -> tuple[np.ndarray, np.ndarray, str]:
    """Split by capture when possible, otherwise strictly forward in time."""
    local_groups = groups[indices]
    if len(np.unique(local_groups)) >= 2:
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=42)
        left, right = next(splitter.split(indices, groups=local_groups))
        return indices[left], indices[right], "capture_group"

    local_times = timestamps[indices]
    valid = local_times != np.iinfo("int64").min
    if valid.mean() >= 0.95 and len(np.unique(local_times[valid])) > 1:
        ordered = indices[np.argsort(local_times, kind="stable")]
        cut = int(len(ordered) * (1.0 - test_size))
        if cut <= 0 or cut >= len(ordered):
            raise IntegrityError(f"{purpose} temporal split is empty")
        return ordered[:cut], ordered[cut:], "forward_time"

    raise IntegrityError(
        f"cannot create leakage-resistant {purpose} split: provide multiple "
        "capture files/groups or a parseable Timestamp column"
    )


def _calibrate_abstention_threshold(clf, X_val: np.ndarray, y_val: np.ndarray) -> dict:
    probabilities = clf.model.predict_proba(X_val)
    indices = np.argmax(probabilities, axis=1)
    labels = clf._le.inverse_transform(indices)
    confidences = probabilities[np.arange(len(indices)), indices]
    true_attack = y_val != "Benign"
    candidates = []
    for threshold in np.linspace(0.50, 0.99, 50):
        accepted = (labels != "Benign") & (confidences >= threshold)
        correct = accepted & (labels == y_val)
        precision = float(correct.sum() / max(accepted.sum(), 1))
        recall = float(correct.sum() / max(true_attack.sum(), 1))
        f1 = 2 * precision * recall / max(precision + recall, 1e-12)
        candidates.append((float(threshold), precision, recall, f1, int(accepted.sum())))
    eligible = [item for item in candidates if item[1] >= 0.95 and item[4] >= 10]
    chosen = max(eligible, key=lambda item: (item[2], -item[0])) if eligible else max(
        candidates, key=lambda item: item[3]
    )
    return {
        "threshold": round(chosen[0], 4),
        "precision": round(chosen[1], 4),
        "recall": round(chosen[2], 4),
        "f1": round(chosen[3], 4),
        "accepted": chosen[4],
        "validation_samples": int(len(y_val)),
        "method": "held_out_capture_or_forward_time",
    }


def train_all(
    csv_dir: str | Path,
    out_dir: str | Path,
    *,
    manifest_path: str | Path | None = None,
    allow_fixture: bool = False,
) -> dict:
    """Train all pipeline stages and save models.

    Args:
        csv_dir: Path to CICIDS2017 CSV directory.
        out_dir: Path to save trained model files.

    Returns:
        Evaluation results dict with metrics and comparisons.
    """
    X, y, metadata = load_cicids2017(
        csv_dir,
        manifest_path=manifest_path,
        allow_fixture=allow_fixture,
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
    X_train, y_train = X[fit_indices], y[fit_indices]
    X_cal, y_cal = X[calibration_indices], y[calibration_indices]
    X_test, y_test = X[test_indices], y[test_indices]

    if len(X_test) < MIN_TEST_SAMPLES:
        raise ValueError(f"Test set too small: {len(X_test)} < {MIN_TEST_SAMPLES}")
    missing_test_classes = sorted(set(y) - set(y_test))
    if missing_test_classes:
        raise IntegrityError(
            "independent test partition has no examples for classes: "
            + ", ".join(missing_test_classes)
        )

    log.info("Train: %d samples, Test: %d samples", len(X_train), len(X_test))

    # Fit preprocessing only on benign candidate-training flows.
    benign_mask_train = y_train == "Benign"
    if not benign_mask_train.any():
        raise IntegrityError("candidate training partition has no benign flows")
    norm = Normalizer().fit(X_train[benign_mask_train])
    Xtr, Xcal, Xte = (
        norm.transform(X_train), norm.transform(X_cal), norm.transform(X_test)
    )
    benign_mask_train = y_train == "Benign"
    benign_mask_cal = y_cal == "Benign"

    # Stage 2: Statistical filter (trained on benign only)
    stat = StatisticalFilter().fit(Xtr[benign_mask_train])

    # Stage 3: XGBoost classifier
    clf = AttackClassifier().fit(Xtr, y_train)
    calibration = _calibrate_abstention_threshold(clf, Xcal, y_cal)
    clf.confidence_threshold = calibration["threshold"]

    # Stage 4: Autoencoder (trained on benign only)
    val_benign = Xcal[benign_mask_cal]
    if not len(val_benign):
        raise IntegrityError("calibration partition has no benign flows")
    n_val = min(5000, len(val_benign))
    ae = AutoencoderDetector(n_features=Xtr.shape[1]).fit(
        Xtr[benign_mask_train], val_benign[:n_val])

    # Save a candidate bundle. Training never promotes it to production.
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    norm.save(out / "normalizer.pkl")
    stat.save(out / "statistical.pkl")
    clf.save(out / "classifier.pkl")
    ae.save(out / "autoencoder.pt")

    results = evaluate_all(
        stat, clf, ae, norm, Xte, y_test,
        baseline_benign_train=Xtr[benign_mask_train],
    )
    results["split"] = {
        "test_method": test_method,
        "calibration_method": calibration_method,
        "train_samples": int(len(fit_indices)),
        "calibration_samples": int(len(calibration_indices)),
        "test_samples": int(len(test_indices)),
        "duplicate_rows_removed": metadata["duplicate_rows_removed"],
    }
    results["calibration"] = calibration
    results["candidate_status"] = "shadow_only_not_promoted"
    try:
        head = (BASE_DIR / ".git/HEAD").read_text(encoding="ascii").strip()
        if head.startswith("ref: "):
            ref_path = BASE_DIR / ".git" / head[5:]
            revision = ref_path.read_text(encoding="ascii").strip()
        else:
            revision = head
        if len(revision) != 40 or any(char not in "0123456789abcdef" for char in revision.lower()):
            revision = "unknown"
    except (OSError, UnicodeDecodeError):
        revision = "unknown"
    write_artifact_manifest(
        out,
        dataset_entries=metadata["dataset_entries"],
        metrics=results,
        classes=clf.classes_,
        abstention_threshold=clf.confidence_threshold,
        code_revision=revision,
        production_approved=False,
    )
    (out / "metrics.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    log.info("Candidate models and integrity metadata saved to %s", out)
    return results


def evaluate_all(
    stat, clf, ae, norm, X_test, y_test,
    *, baseline_benign_train: np.ndarray | None = None,
) -> dict:
    """Full pipeline vs baselines. No fabricated numbers — everything here
    is computed from the actual test split.

    Returns:
        Dict with classifier metrics, baseline comparisons, and test size.
    """
    # Pipeline classifier evaluation
    labels_pred, confidences = clf.predict_batch(X_test)
    classes = list(clf.classes_)
    p, r, f1, _ = precision_recall_fscore_support(
        y_test, labels_pred, average="weighted", zero_division=0)
    per_p, per_r, per_f1, per_support = precision_recall_fscore_support(
        y_test, labels_pred, labels=classes, average=None, zero_division=0
    )
    cm = confusion_matrix(y_test, labels_pred, labels=classes).tolist()
    probabilities = clf.model.predict_proba(X_test)
    binary_targets = label_binarize(y_test, classes=classes)
    if len(classes) == 2:
        binary_targets = np.column_stack([1 - binary_targets[:, 0], binary_targets[:, 0]])
    per_class = {}
    for index, label in enumerate(classes):
        truth = y_test == label
        predicted = labels_pred == label
        fp = int((predicted & ~truth).sum())
        tn = int((~predicted & ~truth).sum())
        per_class[label] = {
            "precision": round(float(per_p[index]), 4),
            "recall": round(float(per_r[index]), 4),
            "f1": round(float(per_f1[index]), 4),
            "support": int(per_support[index]),
            "false_positive_rate": round(fp / max(fp + tn, 1), 6),
            "pr_auc": (
                round(float(average_precision_score(
                    binary_targets[:, index], probabilities[:, index]
                )), 4)
                if binary_targets[:, index].any() else None
            ),
            "brier": round(float(brier_score_loss(
                binary_targets[:, index], probabilities[:, index]
            )), 6),
        }
    bin_edges = np.linspace(0.0, 1.0, 11)
    correct = labels_pred == y_test
    ece = 0.0
    for low, high in zip(bin_edges[:-1], bin_edges[1:]):
        selected = (confidences >= low) & (
            confidences <= high if high == 1.0 else confidences < high
        )
        if selected.any():
            ece += selected.mean() * abs(
                float(correct[selected].mean()) - float(confidences[selected].mean())
            )

    # Binary: attack vs benign
    y_binary = np.where(y_test == "Benign", "BENIGN", "ATTACK")
    pred_binary = np.where(labels_pred == "Benign", "BENIGN", "ATTACK")

    # Baseline 1: Z-Score alone (flags = attack)
    z_pred = np.where(stat.filter_batch(X_test), "ATTACK", "BENIGN")
    zp, zr, zf, _ = precision_recall_fscore_support(
        y_binary, z_pred, average="binary", pos_label="ATTACK", zero_division=0)

    # Baseline 2: Isolation Forest alone
    iso_training = baseline_benign_train
    if iso_training is None:
        raise IntegrityError(
            "Isolation Forest baseline requires benign candidate-training data"
        )
    iso = IsolationForest(contamination=0.1, n_jobs=-1, random_state=42)
    iso.fit(iso_training[:10000])
    iso_pred = np.where(iso.predict(X_test) == -1, "ATTACK", "BENIGN")
    ip, ir, if1, _ = precision_recall_fscore_support(
        y_binary, iso_pred, average="binary", pos_label="ATTACK", zero_division=0)

    # Autoencoder unknown-anomaly scoring (not proof of a zero-day exploit)
    ae_errors = ae.score_batch(X_test)
    ae_flagged = np.sum(ae_errors > ae.threshold) if ae.threshold else 0

    results = {
        "test_samples": int(len(X_test)),
        "classifier": {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f1), 4),
            "confusion_matrix": cm,
            "confusion_matrix_labels": classes,
            "per_class": per_class,
            "expected_calibration_error_10_bin": round(float(ece), 6),
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
            "flagged_unknown_anomaly": int(ae_flagged),
            "mean_error_benign": round(float(ae_errors[y_test == "Benign"].mean()), 4),
            "mean_error_attack": round(float(ae_errors[y_test != "Benign"].mean()), 4),
        },
        "feature_importance": clf.feature_importance(10),
    }

    log.info("Evaluation complete: Classifier F1=%.4f, Z-Score F1=%.4f, IF F1=%.4f",
             f1, zf, if1)
    return results


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(
        description="Train a shadow-only CyberGuard candidate from manifested data"
    )
    parser.add_argument("csv_dir")
    parser.add_argument("output_dir")
    parser.add_argument("--manifest")
    parser.add_argument(
        "--allow-fixture", action="store_true",
        help="allow synthetic fixtures for smoke tests; never marks artifacts production-ready",
    )
    args = parser.parse_args()
    results = train_all(
        args.csv_dir, args.output_dir,
        manifest_path=args.manifest,
        allow_fixture=args.allow_fixture,
    )
    print(json.dumps({k: v for k, v in results.items()
                      if k != "classifier"}, indent=2))
    print(results["classifier"]["report"])
