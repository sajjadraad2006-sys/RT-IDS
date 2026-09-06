"""Dataset/model provenance and database migration regression tests."""
from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import DatabaseError

from backend.config import BASE_DIR, TRAINED_DIR
from backend.db.init_db import init_application_tables
from backend.detection.integrity import (
    ARTIFACT_FILENAMES,
    IntegrityError,
    PIPELINE_V2_VERSION,
    ROUTING_V2_SCHEMA_VERSION,
    feature_schema_hash,
    validate_artifact_bundle,
    validate_dataset_manifest,
)
from backend.detection.trainer import _defensible_split


def test_bundled_dataset_inventory_is_valid_but_fixture_only():
    manifest = BASE_DIR / "cyberguard/datasets/manifest.json"
    rows = validate_dataset_manifest(manifest, BASE_DIR)
    assert {item["row_count"] for item in rows} == {2000}
    assert {item["id"] for item in rows} == {
        "synthetic-cicids-shape-fixture-small-v1"
    }
    assert all(item["training_approved"] is False for item in rows)
    with pytest.raises(IntegrityError, match="fixture-only"):
        validate_dataset_manifest(manifest, BASE_DIR, require_training_approved=True)


def test_html_download_is_rejected_even_if_declared(tmp_path):
    dataset = tmp_path / "fake.csv"
    dataset.write_bytes(b"<!doctype html><title>404 Not Found</title>" * 10)
    payload = {
        "schema_version": "cyberguard-datasets-v1",
        "datasets": [{
            "id": "bad", "path": "fake.csv", "source_url": "https://example.invalid/data",
            "publisher": "test", "publisher_page": "https://example.invalid",
            "license": "unknown", "access_date": "2026-08-18",
            "bytes": dataset.stat().st_size,
            "sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
            "checksum_provenance": "test", "capture_id": "test-capture",
            "time_range": {"start": None, "end": None, "timezone": None},
            "schema_version": "bad-v1", "row_count": 1, "labels": {"BENIGN": 1},
            "columns": ["Label"], "label_column": "Label", "training_approved": True,
            "transformation_lineage": {"parent_sha256": None, "transform": "none"},
            "allowed_uses": ["test"],
            "minimum_bytes": 1,
        }],
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(IntegrityError, match="HTML"):
        validate_dataset_manifest(manifest, tmp_path)


def test_plain_404_placeholder_is_rejected_even_when_manifest_hash_matches(tmp_path):
    dataset = tmp_path / "placeholder.csv"
    dataset.write_bytes(b"404: Not Found\n")
    payload = {
        "schema_version": "cyberguard-datasets-v1",
        "datasets": [{
            "id": "placeholder", "path": dataset.name,
            "source_url": "https://example.invalid/data.csv",
            "publisher": "test", "publisher_page": "https://example.invalid",
            "license": "unknown", "access_date": "2026-08-31",
            "bytes": dataset.stat().st_size,
            "sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
            "checksum_provenance": "test", "capture_id": "test-capture",
            "time_range": {"start": None, "end": None, "timezone": None},
            "schema_version": "bad-v1", "row_count": 0, "labels": {},
            "columns": ["Label"], "label_column": "Label",
            "training_approved": False,
            "transformation_lineage": {"parent_sha256": None, "transform": "none"},
            "allowed_uses": ["negative_test"], "minimum_bytes": 1,
        }],
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(IntegrityError, match="error.*document|placeholder"):
        validate_dataset_manifest(manifest, tmp_path)


def test_artifact_checksum_is_verified_before_deserialization(tmp_path):
    artifacts = {}
    for name in ARTIFACT_FILENAMES:
        path = tmp_path / name
        path.write_bytes((name + "-opaque-test-bytes").encode())
        artifacts[name] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }
    manifest = {
        "schema_version": "cyberguard-artifacts-v1",
        "feature_schema_hash": feature_schema_hash(),
        "classifier": {"abstention_threshold": 0.91},
        "artifacts": artifacts,
    }
    (tmp_path / "artifacts.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert validate_artifact_bundle(tmp_path)["classifier"]["abstention_threshold"] == 0.91
    (tmp_path / "classifier.pkl").write_bytes(b"tampered")
    with pytest.raises(IntegrityError, match="SHA-256"):
        validate_artifact_bundle(tmp_path)


def test_active_artifact_bundle_is_verified_and_explicitly_not_production():
    metadata = validate_artifact_bundle(TRAINED_DIR)
    assert metadata["production_approved"] is False
    assert metadata["evaluation_only"] is True
    assert metadata["pipeline_version"] == "cyberguard-pipeline-legacy-v1"
    assert metadata["routing_schema_version"] == "cyberguard-routing-legacy-v1"
    assert metadata["coverage_contract"]["evaluated_labels"] == []
    assert metadata["metrics"]["independent_test_split"] is False


def test_pipeline_v2_manifest_without_calibration_fails_closed(tmp_path):
    artifacts = {}
    for name in ARTIFACT_FILENAMES:
        path = tmp_path / name
        path.write_bytes((name + "-unit").encode())
        artifacts[name] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }
    manifest = {
        "schema_version": "cyberguard-artifacts-v1",
        "feature_schema_hash": feature_schema_hash(),
        "production_approved": False,
        "evaluation_only": True,
        "pipeline_version": PIPELINE_V2_VERSION,
        "routing_schema_version": ROUTING_V2_SCHEMA_VERSION,
        "classes": ["Benign"],
        "classifier": {"abstention_threshold": 0.9},
        "autoencoder": {"threshold": 1.0},
        "artifacts": artifacts,
    }
    (tmp_path / "artifacts.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    with pytest.raises(IntegrityError, match="calibration metadata is missing"):
        validate_artifact_bundle(tmp_path)


def test_split_never_mixes_capture_groups():
    import numpy as np

    indices = np.arange(12)
    groups = np.array(["a"] * 4 + ["b"] * 4 + ["c"] * 4)
    no_times = np.full(12, np.iinfo("int64").min, dtype=np.int64)
    left, right, method = _defensible_split(
        indices, groups, no_times, test_size=0.33, purpose="test"
    )
    assert method == "capture_group"
    assert set(groups[left]).isdisjoint(set(groups[right]))


def test_fresh_and_existing_database_migrations(tmp_path):
    fresh = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}", future=True)
    init_application_tables(fresh)
    inspector = inspect(fresh)
    assert {"decision_cases", "audit_events"}.issubset(inspector.get_table_names())
    assert "policy_version" in {
        column["name"] for column in inspector.get_columns("decision_cases")
    }

    existing = create_engine(f"sqlite:///{tmp_path / 'existing.db'}", future=True)
    with existing.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE decision_cases ("
            "id INTEGER PRIMARY KEY, alert_id INTEGER, smart_log_json TEXT, "
            "decision_json TEXT, provider VARCHAR(32), prompt_version VARCHAR(32), "
            "created_at FLOAT, updated_at FLOAT)"
        )
    init_application_tables(existing)
    columns = {column["name"] for column in inspect(existing).get_columns("decision_cases")}
    assert {"analyst_verdict", "analyst_notes", "reviewed_by", "reviewed_at", "policy_version"}.issubset(columns)

    with existing.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO audit_events "
            "(created_at,actor,action,entity_type,entity_id,payload_json,previous_hash,event_hash) "
            "VALUES (1,'test','created','case','1','{}','','abc')"
        )
    with pytest.raises(DatabaseError):
        with existing.begin() as connection:
            connection.exec_driver_sql("UPDATE audit_events SET actor='tampered' WHERE id=1")
