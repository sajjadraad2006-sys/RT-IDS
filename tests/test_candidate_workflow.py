"""Candidate split, schema, and calibration leakage regression tests."""
from __future__ import annotations

import json

import numpy as np

from backend.detection.candidate_workflow import (
    _calibrate_classifier,
    _load_partitions,
    _sample_training,
)
from backend.detection.features import FEATURE_NAMES, extract_features_dataframe
from backend.detection.trainer import normalize_label


def _capture(tmp_path, name, partition, hashes, near_hashes):
    path = tmp_path / f"{name}.npz"
    rows = len(hashes)
    np.savez_compressed(
        path,
        X=np.arange(rows * len(FEATURE_NAMES), dtype=np.float32).reshape(
            rows, len(FEATURE_NAMES)
        ),
        y=np.array(["Benign"] * rows, dtype="U32"),
        timestamps=np.arange(rows, dtype=np.int64),
        row_hashes=np.array(hashes, dtype=np.uint64),
        near_hashes=np.array(near_hashes, dtype=np.uint64),
    )
    return {
        "capture_id": name,
        "intended_partition": partition,
        "derived": {"path": str(path)},
    }


def test_split_loader_removes_exact_and_near_overlap_before_fit(tmp_path):
    audit = {
        "captures": [
            _capture(tmp_path, "train", "training", [1, 2], [11, 12]),
            _capture(tmp_path, "cal", "calibration", [2, 3, 30], [20, 13, 12]),
            _capture(tmp_path, "final", "final_test", [3, 4], [13, 14]),
            _capture(tmp_path, "ood", "ood_test", [5, 6], [15, 14]),
        ]
    }
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(audit), encoding="utf-8")
    partitions, _ = _load_partitions(audit_path)
    exact_sets = [set(map(int, part["row_hashes"])) for part in partitions.values()]
    near_sets = [set(map(int, part["near_hashes"])) for part in partitions.values()]
    for index, left in enumerate(exact_sets):
        for right in exact_sets[index + 1:]:
            assert left.isdisjoint(right)
    for index, left in enumerate(near_sets):
        for right in near_sets[index + 1:]:
            assert left.isdisjoint(right)
    assert partitions["calibration"]["removed_exact_overlap"] == 1
    assert partitions["calibration"]["removed_near_overlap"] == 1


def test_training_sampling_is_deterministic_and_never_samples_other_partitions():
    part = {
        "y": np.array(["Benign"] * 10 + ["DoS"] * 2),
        "row_hashes": np.arange(12, dtype=np.uint64)[::-1],
    }
    first = _sample_training(part)
    second = _sample_training(part)
    assert np.array_equal(first, second)
    assert set(first) <= set(range(len(part["y"])))
    assert {10, 11}.issubset(set(first))


def test_classifier_threshold_calibration_has_no_test_set_parameter():
    class FakeClassifier:
        classes_ = ["Benign", "DoS"]

        def predict_batch(self, X):
            return (
                np.array(["Benign", "DoS", "DoS"]),
                np.array([0.9, 0.7, 0.99]),
            )

    result = _calibrate_classifier(
        FakeClassifier(),
        np.zeros((3, 2)),
        np.array(["Benign", "Benign", "BruteForce"]),
    )
    assert result["validation_samples"] == 3
    assert 0.5 <= result["threshold"] <= 0.995
    assert "heldout" in result["method"]


def test_cse_cic_ids2018_columns_map_to_nonzero_canonical_features():
    import pandas as pd

    matrix = extract_features_dataframe(pd.DataFrame([{
        "Flow Duration": 1000,
        "Tot Fwd Pkts": 4,
        "Tot Bwd Pkts": 2,
        "TotLen Fwd Pkts": 400,
        "TotLen Bwd Pkts": 100,
        "SYN Flag Cnt": 3,
        "Init Fwd Win Byts": -1,
    }]))
    values = dict(zip(FEATURE_NAMES, matrix[0]))
    assert values["total_fwd_packets"] == 4
    assert values["total_bwd_packets"] == 2
    assert values["syn_flag_count"] == 3
    assert values["init_win_bytes_fwd"] == 0
    assert values["flow_bytes_ratio"] == 0.8


def test_cse_cic_ids2018_labels_are_normalized_without_inventing_classes():
    assert normalize_label("DoS attacks-Hulk") == "DoS"
    assert normalize_label("Brute Force -XSS") == "WebAttack"
    assert normalize_label("DDOS attack-HOIC") == "DDoS"
