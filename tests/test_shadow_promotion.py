"""Shadow non-mutation and promotion-gate regression tests."""
from __future__ import annotations

import json
import shutil

import numpy as np
import pytest

from backend.config import TRAINED_DIR
from backend.detection.features import FEATURE_NAMES
from backend.detection.integrity import ARTIFACT_FILENAMES, IntegrityError, sha256_file
from backend.detection.shadow import run_shadow


def test_shadow_runner_does_not_mutate_artifacts_or_external_state(tmp_path):
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    for name in (*ARTIFACT_FILENAMES, "artifacts.json"):
        shutil.copy2(TRAINED_DIR / name, candidate / name)
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
    assert report["artifact_hashes_unchanged"] is True
    assert report["llm_calls"] == 0
    assert report["database_mutations"] == 0
    assert report["active_pointer_mutations"] == 0


def test_dry_run_promotion_rejects_failed_quality_gate(tmp_path, monkeypatch):
    from backend.detection import promote as promotion

    models = tmp_path / "models"
    candidate = models / "candidates" / "failed"
    candidate.mkdir(parents=True)
    for name in (*ARTIFACT_FILENAMES, "artifacts.json"):
        shutil.copy2(TRAINED_DIR / name, candidate / name)
    manifest_path = candidate / "artifacts.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["candidate_status"] = "failed_gates"
    manifest["metrics"] = {"quality_gate_results": {"independent_test": False}}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(promotion, "MODELS_DIR", models)
    with pytest.raises(IntegrityError, match="failed promotion gates"):
        promotion.verify_promotion(candidate)
