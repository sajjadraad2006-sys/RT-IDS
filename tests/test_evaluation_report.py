"""Evaluation provenance envelopes cannot turn fixtures into accuracy."""
from __future__ import annotations

import hashlib

import pytest

from backend.detection.evaluation_intake import INTAKE_REPORT_VERSION
from backend.detection.evaluation_report import (
    EVALUATION_REPORT_VERSION,
    build_evaluation_report,
    validate_evaluation_report_bindings,
)
from backend.detection.integrity import ARTIFACT_FILENAMES, IntegrityError


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _complete_metrics():
    binary = {
        key: value for key, value in {
            "tp": 2, "fp": 1, "fn": 0, "tn": 1,
            "precision": 2 / 3, "recall": 1.0, "f1": 0.8,
            "benign_false_positive_rate": 0.5,
            "false_positives_per_10000_benign": 5000.0,
        }.items()
    }
    return {
        "classifier": {
            "per_class": {
                "Benign": {
                    "precision": 1.0, "recall": 0.5, "f1": 2 / 3,
                    "pr_auc": 0.75, "support": 2,
                },
                "DDoS": {
                    "precision": 1.0, "recall": 1.0, "f1": 1.0,
                    "pr_auc": 1.0, "support": 1,
                },
            },
            "macro": {"precision": 1.0, "recall": 0.75, "f1": 5 / 6},
            "weighted": {"precision": 1.0, "recall": 2 / 3, "f1": 7 / 9},
            "expected_calibration_error_10_bin": 0.05,
        },
        "binary_attack_vs_benign": {
            name: dict(binary)
            for name in ("classifier", "statistical", "autoencoder", "pipeline")
        },
        "routing": {
            "counts": {
                "known_attack": 2, "human_review": 0,
                "unknown_anomaly_review": 1, "benign": 1,
            },
            "review_rate": 0.25,
            "human_review_rate": 0.0,
            "unknown_anomaly_review_rate": 0.25,
            "unsupported_label_rate": 0.0,
        },
        "ood": {"high_confidence_known_mislabel_rate": 0.0},
        "benchmark": {"pipeline": {"throughput_rows_per_second": 1234.0}},
        "resources": {"peak_process_rss_kib": 1024},
    }


def _bound_inputs(tmp_path):
    dataset = tmp_path / "dataset-manifest.json"
    dataset.write_bytes(b'{"fixture":true}\n')
    split = tmp_path / "final-split.json"
    split.write_bytes(b'{"rows":4}\n')
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    for name in ARTIFACT_FILENAMES:
        (artifacts / name).write_bytes(("fixture:" + name).encode())
    intake = {
        "schema_version": INTAKE_REPORT_VERSION,
        "status": "validated",
        "dataset_id": "synthetic-fixture-do-not-evaluate",
        "manifest_sha256": _sha(dataset.read_bytes()),
        "fixture_only": True,
        "evaluation_approved": False,
        "accuracy_claim_allowed": False,
    }
    return dataset, split, artifacts, intake


def test_fixture_metrics_receive_immutable_bindings_but_no_accuracy_claim(tmp_path):
    dataset, split, artifacts, intake = _bound_inputs(tmp_path)
    calibration = {"classifier_threshold": 0.9, "source": "fixture"}
    report = build_evaluation_report(
        _complete_metrics(),
        measurement_role="synthetic_fixture_verification",
        intake_report=intake,
        dataset_manifest_path=dataset,
        split_manifest_paths={"final_evaluation": split},
        artifact_dir=artifacts,
        calibration_metadata=calibration,
        source_revision="unit-source-revision",
        command=["python", "-m", "future.evaluator"],
        environment={"python": "3.12", "fixture": True},
    )
    assert report["schema_version"] == EVALUATION_REPORT_VERSION
    assert report["measurement_role"] == "synthetic_fixture_verification"
    assert report["accuracy_claim_allowed"] is False
    assert set(report["artifact_hashes"]) == set(ARTIFACT_FILENAMES)
    validate_evaluation_report_bindings(
        report,
        dataset_manifest_path=dataset,
        split_manifest_paths={"final_evaluation": split},
        artifact_dir=artifacts,
        calibration_metadata=calibration,
    )


def test_fixture_cannot_be_labeled_final_evaluation(tmp_path):
    dataset, split, artifacts, intake = _bound_inputs(tmp_path)
    with pytest.raises(IntegrityError, match="fixture measurements"):
        build_evaluation_report(
            _complete_metrics(),
            measurement_role="final_evaluation",
            intake_report=intake,
            dataset_manifest_path=dataset,
            split_manifest_paths={"final_evaluation": split},
            artifact_dir=artifacts,
            calibration_metadata={"threshold": 0.9},
            source_revision="unit",
            command=["unit"],
            environment={"python": "3.12"},
        )


def test_artifact_change_after_report_invalidates_binding(tmp_path):
    dataset, split, artifacts, intake = _bound_inputs(tmp_path)
    calibration = {"threshold": 0.9}
    report = build_evaluation_report(
        _complete_metrics(),
        measurement_role="synthetic_fixture_verification",
        intake_report=intake,
        dataset_manifest_path=dataset,
        split_manifest_paths={"final_evaluation": split},
        artifact_dir=artifacts,
        calibration_metadata=calibration,
        source_revision="unit",
        command=["unit"],
        environment={"python": "3.12"},
    )
    (artifacts / "classifier.pkl").write_bytes(b"changed-after-report")
    with pytest.raises(IntegrityError, match="artifact_hashes binding"):
        validate_evaluation_report_bindings(
            report,
            dataset_manifest_path=dataset,
            split_manifest_paths={"final_evaluation": split},
            artifact_dir=artifacts,
            calibration_metadata=calibration,
        )


def test_calibration_change_after_report_invalidates_binding(tmp_path):
    dataset, split, artifacts, intake = _bound_inputs(tmp_path)
    calibration = {"threshold": 0.9}
    report = build_evaluation_report(
        _complete_metrics(),
        measurement_role="synthetic_fixture_verification",
        intake_report=intake,
        dataset_manifest_path=dataset,
        split_manifest_paths={"final_evaluation": split},
        artifact_dir=artifacts,
        calibration_metadata=calibration,
        source_revision="unit",
        command=["unit"],
        environment={"python": "3.12"},
    )
    with pytest.raises(IntegrityError, match="calibration_metadata_sha256"):
        validate_evaluation_report_bindings(
            report,
            dataset_manifest_path=dataset,
            split_manifest_paths={"final_evaluation": split},
            artifact_dir=artifacts,
            calibration_metadata={"threshold": 0.91},
        )


def test_incomplete_metrics_cannot_be_bound(tmp_path):
    dataset, split, artifacts, intake = _bound_inputs(tmp_path)
    metrics = _complete_metrics()
    del metrics["routing"]["unsupported_label_rate"]
    with pytest.raises(IntegrityError, match="routing rates"):
        build_evaluation_report(
            metrics,
            measurement_role="synthetic_fixture_verification",
            intake_report=intake,
            dataset_manifest_path=dataset,
            split_manifest_paths={"final_evaluation": split},
            artifact_dir=artifacts,
            calibration_metadata={"threshold": 0.9},
            source_revision="unit",
            command=["unit"],
            environment={"python": "3.12"},
        )
