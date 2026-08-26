"""Shadow non-mutation and promotion-gate regression tests."""
from __future__ import annotations

import hashlib
import json
import shutil

import numpy as np
import pytest

from backend.config import CLASSES, TRAINED_DIR
from backend.detection.features import FEATURE_NAMES
from backend.detection.integrity import (
    ARTIFACT_FILENAMES,
    COVERAGE_CONTRACT_VERSION,
    PIPELINE_V2_VERSION,
    ROUTING_V2_SCHEMA_VERSION,
    IntegrityError,
    sha256_file,
)
from backend.detection.shadow import SHADOW_REPORT_VERSION, _route, run_shadow


def _copy_bundle(source, destination):
    destination.mkdir(parents=True)
    for name in (*ARTIFACT_FILENAMES, "artifacts.json"):
        shutil.copy2(source / name, destination / name)


def _promotable_candidate(tmp_path, monkeypatch):
    from backend.detection import promote as promotion

    models = tmp_path / "models"
    candidate = models / "candidates" / "candidate-v2"
    _copy_bundle(TRAINED_DIR, candidate)
    manifest_path = candidate / "artifacts.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    classes = list(manifest["classes"])
    calibration_id, calibration_hash = next(iter(manifest["dataset_hashes"].items()))
    manifest.update({
        "candidate_status": "shadow_only_not_promoted",
        "production_approved": False,
        "evaluation_only": True,
        "pipeline_version": PIPELINE_V2_VERSION,
        "routing_schema_version": ROUTING_V2_SCHEMA_VERSION,
        "routing_calibration": {
            "known_attack_confidence_threshold": manifest["classifier"][
                "abstention_threshold"
            ],
            "statistical_anomaly_threshold": 3.0,
            "autoencoder_error_threshold": manifest["autoencoder"]["threshold"],
            "calibration_source": "unit-fixture-only",
            "calibration_dataset_hashes": {calibration_id: calibration_hash},
        },
        "coverage_contract": {
            "schema_version": COVERAGE_CONTRACT_VERSION,
            "trained_supported_labels": classes,
            "evaluated_labels": classes,
            "ood_only_labels": [],
            "unsupported_labels": sorted(set(CLASSES) - set(classes)),
            "telemetry_profile": "deterministic-unit-fixture-v1",
        },
        "metrics": {
            "candidate_status": "shadow_only_not_promoted",
            "quality_gate_results": {
                "independent_evaluation": True,
                "coverage_contract": True,
            },
        },
    })
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(promotion, "MODELS_DIR", models)
    return candidate, promotion


def _write_valid_shadow(candidate, **overrides):
    manifest = json.loads((candidate / "artifacts.json").read_text(encoding="utf-8"))
    artifact_hashes = {
        name: manifest["artifacts"][name]["sha256"] for name in ARTIFACT_FILENAMES
    }
    manifest_digest = sha256_file(candidate / "artifacts.json")
    unchanged_file = {"exists": False, "sha256": None, "bytes": 0}
    payload = {
        "schema_version": SHADOW_REPORT_VERSION,
        "shadow_status": "passed",
        "candidate_bundle": str(candidate.resolve()),
        "candidate_manifest_sha256": manifest_digest,
        "candidate_artifact_hashes": artifact_hashes,
        "candidate_pipeline_version": manifest["pipeline_version"],
        "candidate_routing_schema_version": manifest["routing_schema_version"],
        "audit_sha256": hashlib.sha256(b"unit-shadow-audit").hexdigest(),
        "rows": 100,
        "artifact_hashes_unchanged": True,
        "manifest_hashes_unchanged": True,
        "llm_calls": 0,
        "database_mutations": 0,
        "active_pointer_mutations": 0,
        "state_invariants": {
            "artifacts_before": {"active": {}, "candidate": artifact_hashes},
            "artifacts_after": {"active": {}, "candidate": artifact_hashes},
            "manifests_before": {"active": "unit", "candidate": manifest_digest},
            "manifests_after": {"active": "unit", "candidate": manifest_digest},
            "active_pointer_before": unchanged_file,
            "active_pointer_after": unchanged_file,
            "database_before": unchanged_file,
            "database_after": unchanged_file,
        },
    }
    payload.update(overrides)
    path = candidate / "shadow_report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_shadow_runner_binds_report_and_does_not_mutate_external_state(tmp_path):
    candidate = tmp_path / "candidate"
    _copy_bundle(TRAINED_DIR, candidate)
    derived = tmp_path / "capture.npz"
    np.savez_compressed(
        derived,
        X=np.zeros((10, len(FEATURE_NAMES)), dtype=np.float32),
        y=np.array(["Benign"] * 10, dtype="U32"),
        timestamps=np.arange(10, dtype=np.int64),
        row_hashes=np.arange(10, dtype=np.uint64),
        near_hashes=np.arange(10, dtype=np.uint64),
    )
    audit = tmp_path / "audit.json"
    audit.write_text(json.dumps({"captures": [{
        "capture_id": "test-final",
        "intended_partition": "final_test",
        "derived": {"path": str(derived)},
    }]}), encoding="utf-8")
    before = {name: sha256_file(candidate / name) for name in ARTIFACT_FILENAMES}
    report = run_shadow(candidate, audit, tmp_path / "shadow.json", max_rows=10)
    after = {name: sha256_file(candidate / name) for name in ARTIFACT_FILENAMES}
    assert before == after
    assert report["schema_version"] == SHADOW_REPORT_VERSION
    assert report["candidate_artifact_hashes"] == before
    assert report["candidate_manifest_sha256"] == sha256_file(
        candidate / "artifacts.json"
    )
    assert report["artifact_hashes_unchanged"] is True
    assert report["manifest_hashes_unchanged"] is True
    assert report["shadow_status"] == "passed"
    assert report["llm_calls"] == 0
    assert report["database_mutations"] == 0
    assert report["active_pointer_mutations"] == 0


def test_shadow_pipeline_v2_classifier_receives_every_validated_row():
    class IdentityNormalizer:
        def transform(self, X):
            return X

    class NoStatisticalSignal:
        threshold = 3.0

        def z_scores_batch(self, X):
            return np.zeros_like(X)

    class CountingClassifier:
        confidence_threshold = 0.9

        def __init__(self):
            self.rows_seen = 0

        def predict_batch(self, X):
            self.rows_seen += len(X)
            return np.array(["Benign"] * len(X)), np.full(len(X), 0.99)

    class NoAutoencoderSignal:
        threshold = 1.0

        def score_batch(self, X):
            return np.zeros(len(X))

    classifier = CountingClassifier()
    result = _route((
        {}, IdentityNormalizer(), NoStatisticalSignal(), classifier,
        NoAutoencoderSignal(),
    ), np.zeros((17, len(FEATURE_NAMES)), dtype=np.float32))
    assert classifier.rows_seen == 17
    assert result["routes"].tolist() == ["benign"] * 17


def test_dry_run_promotion_rejects_unexpected_candidate_status(tmp_path, monkeypatch):
    candidate, promotion = _promotable_candidate(tmp_path, monkeypatch)
    manifest_path = candidate / "artifacts.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["candidate_status"] = "failed_gates"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(IntegrityError, match="status is not promotable"):
        promotion.verify_promotion(candidate)


def test_dry_run_promotion_rejects_failed_quality_gate(tmp_path, monkeypatch):
    candidate, promotion = _promotable_candidate(tmp_path, monkeypatch)
    manifest_path = candidate / "artifacts.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metrics"]["quality_gate_results"]["independent_evaluation"] = False
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(IntegrityError, match="failed promotion gates"):
        promotion.verify_promotion(candidate)


def test_dry_run_promotion_rejects_missing_shadow_report(tmp_path, monkeypatch):
    candidate, promotion = _promotable_candidate(tmp_path, monkeypatch)
    with pytest.raises(IntegrityError, match="no safe shadow_report"):
        promotion.verify_promotion(candidate)


def test_dry_run_promotion_rejects_stale_shadow_manifest_digest(tmp_path, monkeypatch):
    candidate, promotion = _promotable_candidate(tmp_path, monkeypatch)
    _write_valid_shadow(candidate)
    manifest_path = candidate / "artifacts.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["description"] = "changed after shadow"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(IntegrityError, match="manifest digest is stale"):
        promotion.verify_promotion(candidate)


def test_dry_run_promotion_rejects_mismatched_shadow_artifact_hashes(tmp_path, monkeypatch):
    candidate, promotion = _promotable_candidate(tmp_path, monkeypatch)
    report_path = _write_valid_shadow(candidate)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["candidate_artifact_hashes"]["classifier.pkl"] = "0" * 64
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(IntegrityError, match="artifact hashes do not match"):
        promotion.verify_promotion(candidate)


def test_dry_run_promotion_rejects_failed_shadow_report(tmp_path, monkeypatch):
    candidate, promotion = _promotable_candidate(tmp_path, monkeypatch)
    _write_valid_shadow(candidate, shadow_status="failed_invariants")
    with pytest.raises(IntegrityError, match="shadow evaluation did not pass"):
        promotion.verify_promotion(candidate)


def test_valid_matching_shadow_report_is_eligible_but_stays_dry_run(tmp_path, monkeypatch):
    candidate, promotion = _promotable_candidate(tmp_path, monkeypatch)
    shadow_path = _write_valid_shadow(candidate)
    before = sha256_file(candidate / "artifacts.json")
    result = promotion.verify_promotion(candidate)
    assert result["eligible"] is True
    assert result["dry_run"] is True
    assert result["pipeline_version"] == PIPELINE_V2_VERSION
    assert result["shadow_report"] == str(shadow_path)
    assert result["shadow_rows"] == 100
    assert sha256_file(candidate / "artifacts.json") == before
