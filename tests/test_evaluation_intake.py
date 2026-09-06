"""Independent-data intake uses tiny fixtures, never evaluation evidence."""
from __future__ import annotations

import hashlib
import json

import pytest

from backend.detection.evaluation_intake import (
    FINGERPRINT_SIDECAR_VERSION,
    INTAKE_MANIFEST_VERSION,
    INTAKE_REPORT_VERSION,
    IntakeValidationError,
    validate_intake_manifest,
)


ROLES = ("training", "calibration", "shadow", "final_evaluation")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_manifest(tmp_path):
    files = []
    for index, role in enumerate(ROLES):
        data = f"NON-EVALUATION-TEST-DATA:{role}\n".encode()
        data_path = tmp_path / f"{role}.flows"
        data_path.write_bytes(data)
        fingerprint_record = {
            "feature_sha256": _sha(f"feature:{role}".encode()),
            "label": "Benign" if role != "shadow" else "DDoS",
        }
        sidecar = (json.dumps(fingerprint_record, sort_keys=True) + "\n").encode()
        sidecar_path = tmp_path / f"{role}.fingerprints.jsonl"
        sidecar_path.write_bytes(sidecar)
        files.append({
            "file_id": f"fixture-{role}",
            "path": data_path.name,
            "bytes": len(data),
            "sha256": _sha(data),
            "capture_id": f"fixture-capture-{role}",
            "capture_time_range": {
                "start": f"2026-0{index + 1}-01T00:00:00+00:00",
                "end": f"2026-0{index + 1}-02T00:00:00+00:00",
            },
            "supported_labels": [fingerprint_record["label"]],
            "label_provenance": {
                "method": "deterministic synthetic unit fixture",
                "reference": "tests/test_evaluation_intake.py",
            },
            "known_preprocessing": ["none; opaque fixture bytes"],
            "intended_role": role,
            "feature_fingerprints": {
                "schema_version": FINGERPRINT_SIDECAR_VERSION,
                "label_included_in_feature_hash": False,
                "path": sidecar_path.name,
                "bytes": len(sidecar),
                "sha256": _sha(sidecar),
            },
        })
    manifest = {
        "schema_version": INTAKE_MANIFEST_VERSION,
        "dataset_id": "synthetic-intake-fixture-do-not-evaluate",
        "source_and_license_record": {
            "name": "CyberGuard deterministic unit fixture",
            "source_uri": "repository:test-only",
            "license_id": "test-fixture-only",
            "license_record": "not licensed or approved for model evaluation",
            "acquisition_date": "2026-01-01",
        },
        "telemetry_profile": "cyberguard-canonical-flow-v1",
        "role_overlap_prohibited": True,
        "forward_time_evaluation": True,
        "fixture_only": True,
        "evaluation_approved": False,
        "files": files,
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path, manifest


def _rewrite(path, manifest):
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _fingerprint_path(tmp_path, item):
    return tmp_path / item["feature_fingerprints"]["path"]


def _replace_fingerprint(tmp_path, item, feature_hash, label=None):
    value = {
        "feature_sha256": feature_hash,
        "label": label or item["supported_labels"][0],
    }
    content = (json.dumps(value, sort_keys=True) + "\n").encode()
    path = _fingerprint_path(tmp_path, item)
    path.write_bytes(content)
    item["feature_fingerprints"]["bytes"] = len(content)
    item["feature_fingerprints"]["sha256"] = _sha(content)


def test_valid_fixture_manifest_is_bound_but_cannot_support_accuracy_claims(tmp_path):
    path, _ = _write_manifest(tmp_path)
    report = validate_intake_manifest(path)
    assert report["schema_version"] == INTAKE_REPORT_VERSION
    assert report["status"] == "validated"
    assert report["manifest_sha256"] == _sha(path.read_bytes())
    assert report["roles"] == {role: 1 for role in ROLES}
    assert report["fingerprint_rows"] == 4
    assert report["fixture_only"] is True
    assert report["accuracy_claim_allowed"] is False


def test_missing_hash_is_rejected(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    manifest["files"][0]["sha256"] = ""
    _rewrite(path, manifest)
    with pytest.raises(IntakeValidationError, match="sha256"):
        validate_intake_manifest(path)


def test_file_changed_after_manifest_is_rejected(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    (tmp_path / manifest["files"][0]["path"]).write_bytes(b"changed")
    with pytest.raises(IntakeValidationError, match="file size changed"):
        validate_intake_manifest(path)


def test_capture_overlap_across_roles_is_rejected(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    manifest["files"][3]["capture_id"] = manifest["files"][1]["capture_id"]
    _rewrite(path, manifest)
    with pytest.raises(IntakeValidationError, match="capture_overlap_across_splits"):
        validate_intake_manifest(path)


def test_forward_time_leakage_is_rejected(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    manifest["files"][3]["capture_time_range"] = {
        "start": "2026-01-01T00:00:00+00:00",
        "end": "2026-01-02T00:00:00+00:00",
    }
    _rewrite(path, manifest)
    with pytest.raises(IntakeValidationError, match="forward_time_leakage"):
        validate_intake_manifest(path)


def test_exact_feature_duplicate_crossing_splits_is_rejected(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    duplicate = _sha(b"feature:training")
    _replace_fingerprint(tmp_path, manifest["files"][2], duplicate, "Benign")
    manifest["files"][2]["supported_labels"] = ["Benign"]
    _rewrite(path, manifest)
    with pytest.raises(IntakeValidationError, match="exact_feature_duplicate_crossing_splits"):
        validate_intake_manifest(path)


def test_conflicting_label_duplicate_is_rejected(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    duplicate = _sha(b"feature:training")
    _replace_fingerprint(tmp_path, manifest["files"][2], duplicate, "DDoS")
    _rewrite(path, manifest)
    with pytest.raises(IntakeValidationError, match="conflicting_label_duplicate"):
        validate_intake_manifest(path)


def test_final_evaluation_data_cannot_be_reused_for_calibration(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    duplicate = _sha(b"feature:calibration")
    _replace_fingerprint(tmp_path, manifest["files"][3], duplicate, "Benign")
    _rewrite(path, manifest)
    with pytest.raises(
        IntakeValidationError,
        match="final_evaluation_data_reused_for_calibration",
    ):
        validate_intake_manifest(path)


def test_unsupported_telemetry_profile_is_rejected(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    manifest["telemetry_profile"] = "arbitrary-payload-events"
    _rewrite(path, manifest)
    with pytest.raises(IntakeValidationError, match="unsupported_telemetry_profile"):
        validate_intake_manifest(path)


def test_ambiguous_dataset_role_is_rejected(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    manifest["files"][0]["intended_role"] = ["training", "final_evaluation"]
    _rewrite(path, manifest)
    with pytest.raises(IntakeValidationError, match="ambiguous_or_unsupported_dataset_role"):
        validate_intake_manifest(path)


def test_file_path_cannot_be_declared_under_two_roles(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    manifest["files"][3]["path"] = manifest["files"][0]["path"]
    manifest["files"][3]["bytes"] = manifest["files"][0]["bytes"]
    manifest["files"][3]["sha256"] = manifest["files"][0]["sha256"]
    _rewrite(path, manifest)
    with pytest.raises(IntakeValidationError, match="file_path_reused"):
        validate_intake_manifest(path)


def test_fixture_cannot_be_marked_evaluation_approved(tmp_path):
    path, manifest = _write_manifest(tmp_path)
    manifest["evaluation_approved"] = True
    _rewrite(path, manifest)
    with pytest.raises(IntakeValidationError, match="fixture data cannot be approved"):
        validate_intake_manifest(path)
