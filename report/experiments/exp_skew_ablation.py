"""Experiment P3.e: Train/Serve Feature Skew Ablation.

Analyzes the divergence between features computed by CICFlowMeter (offline dataset)
and features produced by the project's live sniffer (backend/detection/live_sniffer.py)
and Suricata bridge (backend/suricata/tailer.py).

Features with documented skew:
- active_mean: CICFlowMeter calculates mean active duration; live_sniffer sets to 0.0; tailer sets to flow_duration.
- idle_mean: CICFlowMeter calculates mean idle duration; live_sniffer sets to 0.0; tailer sets to 0.0.
- init_win_bytes_fwd: TCP SYN/ACK capture only in sniffer; tailer hardcodes to 64240.0.
- init_win_bytes_bwd: TCP SYN/ACK capture only in sniffer; tailer hardcodes to 29200.0.

Evaluations:
1. Serving Skew Evaluation: Evaluate shipped candidate with skewed features forced to sniffer/Suricata values.
2. Retrained Model (Zeroed Features): Retrain XGBoost on training set with the 4 skewed features zeroed (3 seeds).
3. Feature Equivalence Matrix across all 32 features.
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
from sklearn.metrics import accuracy_score, f1_score, classification_report
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from backend.detection.trainer import load_cicids2017, _defensible_split
from backend.detection.normalizer import Normalizer
from backend.detection.classifier import AttackClassifier
from backend.detection.features import FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("exp_skew_ablation")


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


FEATURE_EQUIVALENCE_TABLE = [
    {"index": 0, "name": "flow_duration", "cicflowmeter_def": "Flow duration in microseconds", "sniffer_impl": "time.monotonic_ns() delta in microseconds", "suricata_impl": "doc.get('flow', {}).get('age', 0) * 1e6", "status": "identical"},
    {"index": 1, "name": "total_fwd_packets", "cicflowmeter_def": "Total packets in forward direction", "sniffer_impl": "fwd_packets counter", "suricata_impl": "flow.pkts_toserver", "status": "identical"},
    {"index": 2, "name": "total_bwd_packets", "cicflowmeter_def": "Total packets in backward direction", "sniffer_impl": "bwd_packets counter", "suricata_impl": "flow.pkts_toclient", "status": "identical"},
    {"index": 3, "name": "total_fwd_bytes", "cicflowmeter_def": "Total bytes in forward direction", "sniffer_impl": "fwd_bytes accumulator", "suricata_impl": "flow.bytes_toserver", "status": "identical"},
    {"index": 4, "name": "total_bwd_bytes", "cicflowmeter_def": "Total bytes in backward direction", "sniffer_impl": "bwd_bytes accumulator", "suricata_impl": "flow.bytes_toclient", "status": "identical"},
    {"index": 5, "name": "packets_per_sec", "cicflowmeter_def": "Flow packets per second", "sniffer_impl": "(fwd+bwd)/(duration_us/1e6)", "suricata_impl": "total_pkts / max(duration_sec, 1e-6)", "status": "approximate"},
    {"index": 6, "name": "bytes_per_sec", "cicflowmeter_def": "Flow bytes per second", "sniffer_impl": "(fwd_b+bwd_b)/(duration_us/1e6)", "suricata_impl": "total_bytes / max(duration_sec, 1e-6)", "status": "approximate"},
    {"index": 7, "name": "fwd_packet_length_mean", "cicflowmeter_def": "Mean packet size in forward direction", "sniffer_impl": "fwd_bytes / max(1, fwd_packets)", "suricata_impl": "fwd_bytes / max(1, fwd_pkts)", "status": "approximate"},
    {"index": 8, "name": "bwd_packet_length_mean", "cicflowmeter_def": "Mean packet size in backward direction", "sniffer_impl": "bwd_bytes / max(1, bwd_packets)", "suricata_impl": "bwd_bytes / max(1, bwd_pkts)", "status": "approximate"},
    {"index": 9, "name": "packet_length_mean", "cicflowmeter_def": "Mean size of all packets", "sniffer_impl": "all_bytes / max(1, all_pkts)", "suricata_impl": "total_bytes / max(1, total_pkts)", "status": "approximate"},
    {"index": 10, "name": "packet_length_std", "cicflowmeter_def": "Standard deviation of packet size", "sniffer_impl": "Calculated across packet list", "suricata_impl": "0.0 (not computed by eve.json)", "status": "absent (suricata)"},
    {"index": 11, "name": "packet_length_max", "cicflowmeter_def": "Maximum packet length", "sniffer_impl": "max(packet_lengths)", "suricata_impl": "Estimated from fwd/bwd averages", "status": "approximate"},
    {"index": 12, "name": "packet_length_min", "cicflowmeter_def": "Minimum packet length", "sniffer_impl": "min(packet_lengths)", "suricata_impl": "Estimated from fwd/bwd averages", "status": "approximate"},
    {"index": 13, "name": "avg_pkt_size", "cicflowmeter_def": "Average segment size", "sniffer_impl": "packet_length_mean", "suricata_impl": "packet_length_mean", "status": "identical"},
    {"index": 14, "name": "syn_flag_count", "cicflowmeter_def": "Count of packets with SYN flag", "sniffer_impl": "Packet TCP flag parser", "suricata_impl": "tcp.syn flag indicator", "status": "identical"},
    {"index": 15, "name": "ack_flag_count", "cicflowmeter_def": "Count of packets with ACK flag", "sniffer_impl": "Packet TCP flag parser", "suricata_impl": "tcp.ack flag indicator", "status": "identical"},
    {"index": 16, "name": "rst_flag_count", "cicflowmeter_def": "Count of packets with RST flag", "sniffer_impl": "Packet TCP flag parser", "suricata_impl": "tcp.rst flag indicator", "status": "identical"},
    {"index": 17, "name": "fin_flag_count", "cicflowmeter_def": "Count of packets with FIN flag", "sniffer_impl": "Packet TCP flag parser", "suricata_impl": "tcp.fin flag indicator", "status": "identical"},
    {"index": 18, "name": "psh_flag_count", "cicflowmeter_def": "Count of packets with PSH flag", "sniffer_impl": "Packet TCP flag parser", "suricata_impl": "tcp.psh flag indicator", "status": "identical"},
    {"index": 19, "name": "urg_flag_count", "cicflowmeter_def": "Count of packets with URG flag", "sniffer_impl": "Packet TCP flag parser", "suricata_impl": "tcp.urg flag indicator", "status": "identical"},
    {"index": 20, "name": "init_win_bytes_fwd", "cicflowmeter_def": "Bytes in initial window forward", "sniffer_impl": "Captured on SYN; 0 if mid-stream or UDP (live_sniffer.py:100,224)", "suricata_impl": "Hardcoded constant 64240.0 (tailer.py:111)", "status": "absent (suricata) / skewed (sniffer)"},
    {"index": 21, "name": "init_win_bytes_bwd", "cicflowmeter_def": "Bytes in initial window backward", "sniffer_impl": "Captured on SYN-ACK; 0 if mid-stream or UDP (live_sniffer.py:101,225)", "suricata_impl": "Hardcoded 29200.0 if bwd_pkts > 0 else 0.0 (tailer.py:112)", "status": "absent (suricata) / skewed (sniffer)"},
    {"index": 22, "name": "flow_iat_mean", "cicflowmeter_def": "Mean time between flow packets", "sniffer_impl": "Mean of inter-arrival timestamp deltas", "suricata_impl": "duration_sec / max(1, total_pkts-1)", "status": "approximate"},
    {"index": 23, "name": "flow_iat_std", "cicflowmeter_def": "Standard deviation of inter-arrival time", "sniffer_impl": "Std dev of timestamp deltas", "suricata_impl": "Hardcoded 0.0 (tailer.py:114)", "status": "absent (suricata)"},
    {"index": 24, "name": "flow_iat_max", "cicflowmeter_def": "Maximum inter-arrival time", "sniffer_impl": "Max of timestamp deltas", "suricata_impl": "duration_sec (tailer.py:115)", "status": "approximate"},
    {"index": 25, "name": "fwd_iat_mean", "cicflowmeter_def": "Mean time between forward packets", "sniffer_impl": "Mean of fwd packet deltas", "suricata_impl": "duration_sec / max(1, fwd_pkts-1)", "status": "approximate"},
    {"index": 26, "name": "fwd_header_len", "cicflowmeter_def": "Total forward header bytes", "sniffer_impl": "Sum of IP+TCP/UDP header lengths", "suricata_impl": "fwd_pkts * 40.0 (estimated IPv4+TCP)", "status": "approximate"},
    {"index": 27, "name": "bwd_header_len", "cicflowmeter_def": "Total backward header bytes", "sniffer_impl": "Sum of IP+TCP/UDP header lengths", "suricata_impl": "bwd_pkts * 40.0 (estimated IPv4+TCP)", "status": "approximate"},
    {"index": 28, "name": "down_up_ratio", "cicflowmeter_def": "Ratio of backward to forward packets", "sniffer_impl": "bwd_packets / max(1, fwd_packets)", "suricata_impl": "bwd_pkts / max(1, fwd_pkts)", "status": "identical"},
    {"index": 29, "name": "flow_bytes_ratio", "cicflowmeter_def": "Ratio of forward bytes to total bytes", "sniffer_impl": "fwd_bytes / max(1, total_bytes)", "suricata_impl": "fwd_bytes / max(1, total_bytes)", "status": "identical"},
    {"index": 30, "name": "active_mean", "cicflowmeter_def": "Mean time flow was active before idle", "sniffer_impl": "Hardcoded 0.0 (live_sniffer.py:234)", "suricata_impl": "Hardcoded duration_us (tailer.py:123)", "status": "absent (sniffer) / semantic mismatch (suricata)"},
    {"index": 31, "name": "idle_mean", "cicflowmeter_def": "Mean time flow was idle before active", "sniffer_impl": "Hardcoded 0.0 (live_sniffer.py:235)", "suricata_impl": "Hardcoded 0.0 (tailer.py:124)", "status": "absent (both)"},
]


def run_skew_ablation():
    t_start = time.time()
    csv_dir = REPO_ROOT / "cyberguard" / "datasets" / "cicids2017_real"
    manifest_path = REPO_ROOT / "cyberguard" / "datasets" / "cicids2017_real_manifest.json"

    log.info("Loading CICIDS2017 dataset for skew ablation...")
    X, y, metadata = load_cicids2017(
        csv_dir=csv_dir,
        manifest_path=manifest_path,
        allow_fixture=False,
        return_metadata=True,
    )

    all_indices = np.arange(len(y))
    train_indices, test_indices, _ = _defensible_split(
        all_indices, metadata["groups"], metadata["timestamps"], test_size=0.2, purpose="test"
    )
    fit_indices, _, _ = _defensible_split(
        train_indices, metadata["groups"], metadata["timestamps"], test_size=0.2, purpose="calibration"
    )

    X_train, y_train = X[fit_indices], y[fit_indices]
    X_test, y_test = X[test_indices], y[test_indices]

    # Load candidate model
    candidate_dir = REPO_ROOT / "data" / "models" / "candidate_cicids2017"
    norm = Normalizer().load(candidate_dir / "normalizer.pkl")
    clf = AttackClassifier().load(candidate_dir / "classifier.pkl")

    # Indices of the 4 skewed features:
    # 20: init_win_bytes_fwd, 21: init_win_bytes_bwd, 30: active_mean, 31: idle_mean
    skewed_indices = [20, 21, 30, 31]

    # Baseline candidate evaluation on un-skewed test set
    Xte_norm_clean = norm.transform(X_test)
    preds_clean, _ = clf.predict_batch(Xte_norm_clean)
    baseline_acc = float(accuracy_score(y_test, preds_clean))
    baseline_macro_f1 = float(f1_score(y_test, preds_clean, average="macro", zero_division=0))
    baseline_weighted_f1 = float(f1_score(y_test, preds_clean, average="weighted", zero_division=0))

    # 1. Serving Skew: Candidate evaluated with sniffer values (all 4 zeroed)
    log.info("Evaluating candidate under live sniffer feature values (zeros)...")
    X_test_sniffer = X_test.copy()
    X_test_sniffer[:, skewed_indices] = 0.0
    Xte_norm_sniffer = norm.transform(X_test_sniffer)
    preds_sniffer, _ = clf.predict_batch(Xte_norm_sniffer)

    sniffer_acc = float(accuracy_score(y_test, preds_sniffer))
    sniffer_macro_f1 = float(f1_score(y_test, preds_sniffer, average="macro", zero_division=0))
    sniffer_weighted_f1 = float(f1_score(y_test, preds_sniffer, average="weighted", zero_division=0))

    # 2. Serving Skew: Candidate evaluated with Suricata bridge values
    # init_win_bytes_fwd=64240, init_win_bytes_bwd=29200, active_mean=duration, idle_mean=0
    log.info("Evaluating candidate under Suricata bridge feature values...")
    X_test_suricata = X_test.copy()
    X_test_suricata[:, 20] = 64240.0
    # bwd window 29200 if bwd packets > 0 else 0
    bwd_pkts = X_test_suricata[:, 2]
    X_test_suricata[:, 21] = np.where(bwd_pkts > 0, 29200.0, 0.0)
    # active_mean = flow_duration
    X_test_suricata[:, 30] = X_test_suricata[:, 0]
    X_test_suricata[:, 31] = 0.0

    Xte_norm_suricata = norm.transform(X_test_suricata)
    preds_suricata, _ = clf.predict_batch(Xte_norm_suricata)

    suri_acc = float(accuracy_score(y_test, preds_suricata))
    suri_macro_f1 = float(f1_score(y_test, preds_suricata, average="macro", zero_division=0))
    suri_weighted_f1 = float(f1_score(y_test, preds_suricata, average="weighted", zero_division=0))

    # 3. Retrained Model with the 4 Skewed Features Zeroed (3 seeds)
    log.info("Retraining XGBoost models with the 4 skewed features zeroed (3 seeds)...")
    X_train_zeroed = X_train.copy()
    X_train_zeroed[:, skewed_indices] = 0.0

    benign_train_mask = (y_train == "Benign")
    norm_zeroed = Normalizer().fit(X_train_zeroed[benign_train_mask])
    Xtr_zeroed_norm = norm_zeroed.transform(X_train_zeroed)
    Xte_zeroed_norm = norm_zeroed.transform(X_test_sniffer)

    le = LabelEncoder()
    y_tr_enc = le.fit_transform(y_train)
    classes = list(le.classes_)

    u_classes, counts = np.unique(y_tr_enc, return_counts=True)
    weights = {c: len(y_tr_enc) / (len(u_classes) * n) for c, n in zip(u_classes, counts)}
    sample_weights = np.array([weights[v] for v in y_tr_enc])

    seeds = [42, 123, 456]
    retrain_runs = []
    for s in seeds:
        xgb_z = XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            tree_method="hist",
            device="cpu",
            n_jobs=-1,
            eval_metric="mlogloss",
            random_state=s,
            verbosity=0,
        )
        xgb_z.fit(Xtr_zeroed_norm, y_tr_enc, sample_weight=sample_weights)
        preds_z = np.array([classes[i] for i in xgb_z.predict(Xte_zeroed_norm)])

        z_acc = float(accuracy_score(y_test, preds_z))
        z_macro_f1 = float(f1_score(y_test, preds_z, average="macro", zero_division=0))
        z_weighted_f1 = float(f1_score(y_test, preds_z, average="weighted", zero_division=0))

        retrain_runs.append({
            "seed": s,
            "accuracy": round(z_acc, 4),
            "macro_f1": round(z_macro_f1, 4),
            "weighted_f1": round(z_weighted_f1, 4),
        })

    retrain_accs = [r["accuracy"] for r in retrain_runs]
    retrain_macros = [r["macro_f1"] for r in retrain_runs]
    retrain_weighteds = [r["weighted_f1"] for r in retrain_runs]

    elapsed = time.time() - t_start

    results = {
        "metadata": {
            "experiment": "train_serve_skew_ablation",
            "command": "python report/experiments/exp_skew_ablation.py",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "git_hash": get_git_hash(),
            "duration_seconds": round(elapsed, 2),
            "environment": get_env_info(),
            "skewed_features": [FEATURE_NAMES[idx] for idx in skewed_indices],
        },
        "baseline_candidate_clean": {
            "accuracy": round(baseline_acc, 4),
            "macro_f1": round(baseline_macro_f1, 4),
            "weighted_f1": round(baseline_weighted_f1, 4),
        },
        "serving_skew_live_sniffer": {
            "description": "Candidate model evaluated with features forced to live sniffer values (active_mean=0, idle_mean=0, init_win=0)",
            "accuracy": round(sniffer_acc, 4),
            "macro_f1": round(sniffer_macro_f1, 4),
            "weighted_f1": round(sniffer_weighted_f1, 4),
            "macro_f1_drop": round(baseline_macro_f1 - sniffer_macro_f1, 4),
        },
        "serving_skew_suricata_tailer": {
            "description": "Candidate model evaluated with features forced to Suricata bridge values (init_win=64240/29200, active_mean=duration, idle_mean=0)",
            "accuracy": round(suri_acc, 4),
            "macro_f1": round(suri_macro_f1, 4),
            "weighted_f1": round(suri_weighted_f1, 4),
            "macro_f1_drop": round(baseline_macro_f1 - suri_macro_f1, 4),
        },
        "retrained_model_zeroed_features": {
            "description": "XGBoost retrained on training set with the 4 skewed features zeroed out (evaluated on sniffer-like zeroed test set)",
            "seeds": seeds,
            "runs": retrain_runs,
            "metrics_mean_std": {
                "accuracy": {"mean": round(float(np.mean(retrain_accs)), 4), "std": round(float(np.std(retrain_accs)), 4)},
                "macro_f1": {"mean": round(float(np.mean(retrain_macros)), 4), "std": round(float(np.std(retrain_macros)), 4)},
                "weighted_f1": {"mean": round(float(np.mean(retrain_weighteds)), 4), "std": round(float(np.std(retrain_weighteds)), 4)},
            },
            "macro_f1_drop_vs_clean": round(baseline_macro_f1 - float(np.mean(retrain_macros)), 4),
        },
        "feature_equivalence_matrix": FEATURE_EQUIVALENCE_TABLE,
        "end_to_end_validation_limitation": (
            "CRITICAL SCIENTIFIC LIMITATION: Because the original raw PCAP packet captures from UNB "
            "(~50 GB) are not present in the workspace, end-to-end packet-level equivalence between "
            "CICFlowMeter's original Java extractor and CyberGuard's live Python sniffer (live_sniffer.py) "
            "could NOT be directly measured. Live serving predictions rely on proxy approximations that "
            "suffer from severe train/serve feature skew."
        ),
    }

    out_file = REPO_ROOT / "report" / "results" / "skew_ablation_experiment.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    log.info("Skew ablation experiment completed in %.1fs. Written to %s", elapsed, out_file)
    print("\n=== Train/Serve Skew Ablation Summary ===")
    print(f"Clean Baseline:         Acc={baseline_acc:.4f}, Macro-F1={baseline_macro_f1:.4f}")
    print(f"Live Sniffer Skew:      Acc={sniffer_acc:.4f}, Macro-F1={sniffer_macro_f1:.4f} (Drop: {baseline_macro_f1 - sniffer_macro_f1:.4f})")
    print(f"Suricata Bridge Skew:   Acc={suri_acc:.4f}, Macro-F1={suri_macro_f1:.4f} (Drop: {baseline_macro_f1 - suri_macro_f1:.4f})")
    print(f"Retrained (4 Zeroed):   Acc={results['retrained_model_zeroed_features']['metrics_mean_std']['accuracy']['mean']:.4f}, Macro-F1={results['retrained_model_zeroed_features']['metrics_mean_std']['macro_f1']['mean']:.4f}")
    return results


if __name__ == "__main__":
    run_skew_ablation()
