"""Dataset and executable model-artifact integrity checks.

Pickle/joblib artifacts are executable input.  Nothing in this module makes
pickle safe; it makes the trust boundary explicit and verifies a private,
locally generated checksum manifest *before* deserialization.
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .features import FEATURE_NAMES


DATASET_MANIFEST_VERSION = "cyberguard-datasets-v1"
ARTIFACT_MANIFEST_VERSION = "cyberguard-artifacts-v1"
ARTIFACT_FILENAMES = (
    "normalizer.pkl",
    "statistical.pkl",
    "classifier.pkl",
    "autoencoder.pt",
)


class IntegrityError(RuntimeError):
    """Raised when an input cannot cross a data/model trust boundary."""


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def feature_schema_hash() -> str:
    encoded = json.dumps(FEATURE_NAMES, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"invalid JSON manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrityError(f"manifest must contain one JSON object: {path}")
    return value


def _safe_repo_path(repo_root: Path, relative: str) -> Path:
    root = repo_root.resolve()
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise IntegrityError(f"manifest path escapes repository: {relative}")
    return candidate


def _reject_download_error_document(path: Path, minimum_bytes: int) -> None:
    size = path.stat().st_size
    if size < minimum_bytes:
        raise IntegrityError(
            f"dataset is unexpectedly small ({size} < {minimum_bytes} bytes): {path}"
        )
    with path.open("rb") as handle:
        prefix = handle.read(4096).lstrip().lower()
    if prefix.startswith((b"<!doctype html", b"<html", b"<?xml")) or b"<title>404" in prefix:
        raise IntegrityError(f"downloaded error/HTML document is not a dataset: {path}")


def validate_dataset_manifest(
    manifest_path: str | Path,
    repo_root: str | Path,
    *,
    require_training_approved: bool = False,
) -> list[dict[str, Any]]:
    """Validate every declared dataset byte-for-byte and against its CSV schema."""
    manifest_file = Path(manifest_path)
    manifest = _load_json_object(manifest_file)
    if manifest.get("schema_version") != DATASET_MANIFEST_VERSION:
        raise IntegrityError("unsupported dataset manifest schema")
    entries = manifest.get("datasets")
    if not isinstance(entries, list) or not entries:
        raise IntegrityError("dataset manifest has no datasets")

    validated: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise IntegrityError("dataset entry must be an object")
        required = {
            "id", "path", "publisher", "publisher_page", "source_url",
            "license", "access_date", "bytes", "sha256",
            "checksum_provenance", "capture_id", "time_range",
            "schema_version", "row_count", "labels", "columns",
            "label_column", "transformation_lineage", "training_approved",
            "allowed_uses", "minimum_bytes",
        }
        missing = sorted(required - set(entry))
        if missing:
            raise IntegrityError(f"dataset entry missing fields: {', '.join(missing)}")
        path = _safe_repo_path(Path(repo_root), str(entry["path"]))
        if path in seen_paths:
            raise IntegrityError(f"duplicate dataset path in manifest: {path}")
        seen_paths.add(path)
        if not path.is_file() or path.is_symlink():
            raise IntegrityError(f"dataset must be a regular non-symlink file: {path}")
        if path.stat().st_size != int(entry["bytes"]):
            raise IntegrityError(f"dataset byte-size mismatch: {path}")
        if not isinstance(entry["sha256"], str) or len(entry["sha256"]) != 64:
            raise IntegrityError(f"dataset SHA-256 declaration is invalid: {path}")
        if entry.get("training_approved") and not str(entry["source_url"]).startswith("https://"):
            raise IntegrityError("training-approved datasets require an HTTPS source")
        if not isinstance(entry["time_range"], dict):
            raise IntegrityError(f"dataset time_range must be an object: {path}")
        if not isinstance(entry["transformation_lineage"], dict):
            raise IntegrityError(f"dataset transformation_lineage must be an object: {path}")
        if not isinstance(entry["allowed_uses"], list) or not entry["allowed_uses"]:
            raise IntegrityError(f"dataset allowed_uses must be a non-empty list: {path}")
        _reject_download_error_document(path, int(entry["minimum_bytes"]))
        actual_hash = sha256_file(path)
        if actual_hash != entry["sha256"]:
            raise IntegrityError(f"dataset SHA-256 mismatch: {path}")
        if require_training_approved and not entry.get("training_approved", False):
            raise IntegrityError(
                f"dataset {entry['id']} is fixture-only and not approved for model training"
            )

        expected_columns = [str(item) for item in entry["columns"]]
        expected_labels = {str(k): int(v) for k, v in entry["labels"].items()}
        row_count = 0
        labels: Counter[str] = Counter()
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != expected_columns:
                raise IntegrityError(f"CSV schema mismatch: {path}")
            label_column = str(entry.get("label_column", "Label"))
            if label_column not in expected_columns:
                raise IntegrityError(f"label column is absent from schema: {path}")
            for row in reader:
                row_count += 1
                labels[str(row.get(label_column, "")).strip()] += 1
        if row_count != int(entry["row_count"]):
            raise IntegrityError(f"row count mismatch for {path}: {row_count}")
        if dict(labels) != expected_labels:
            raise IntegrityError(f"label inventory mismatch for {path}")
        validated.append({**entry, "resolved_path": str(path)})
    return validated


def validate_artifact_bundle(directory: str | Path) -> dict[str, Any]:
    """Verify metadata, feature schema, and every executable artifact checksum."""
    root = Path(directory).resolve()
    manifest_path = root / "artifacts.json"
    manifest = _load_json_object(manifest_path)
    if manifest.get("schema_version") != ARTIFACT_MANIFEST_VERSION:
        raise IntegrityError("unsupported artifact manifest schema")
    if manifest.get("feature_schema_hash") != feature_schema_hash():
        raise IntegrityError("artifact feature schema does not match running code")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise IntegrityError("artifact manifest has no artifact map")
    if set(artifacts) != set(ARTIFACT_FILENAMES):
        raise IntegrityError("artifact manifest is incomplete or contains unexpected files")
    for filename in ARTIFACT_FILENAMES:
        path = root / filename
        if not path.is_file() or path.is_symlink():
            raise IntegrityError(f"artifact must be a regular non-symlink file: {path}")
        expected = artifacts[filename].get("sha256")
        if not isinstance(expected, str) or sha256_file(path) != expected:
            raise IntegrityError(f"artifact SHA-256 mismatch: {filename}")
    threshold = manifest.get("classifier", {}).get("abstention_threshold")
    if not isinstance(threshold, (int, float)) or not 0.0 < float(threshold) <= 1.0:
        raise IntegrityError("artifact abstention threshold is missing or invalid")
    return manifest


def write_artifact_manifest(
    directory: str | Path,
    *,
    dataset_entries: list[dict[str, Any]],
    metrics: dict[str, Any],
    classes: list[str],
    abstention_threshold: float,
    code_revision: str,
    production_approved: bool = False,
    autoencoder_metadata: dict[str, Any] | None = None,
    reproducibility: dict[str, Any] | None = None,
    candidate_status: str = "shadow_only_not_promoted",
) -> Path:
    """Write reproducibility metadata after all candidate files are saved."""
    root = Path(directory)
    artifacts = {
        name: {"sha256": sha256_file(root / name), "bytes": (root / name).stat().st_size}
        for name in ARTIFACT_FILENAMES
    }
    payload = {
        "schema_version": ARTIFACT_MANIFEST_VERSION,
        "feature_schema_version": "cyberguard-flow-features-v1",
        "feature_schema_hash": feature_schema_hash(),
        "code_revision": code_revision,
        "production_approved": bool(production_approved),
        "dataset_hashes": {
            str(item["id"]): str(item["sha256"]) for item in dataset_entries
        },
        "classes": list(classes),
        "classifier": {"abstention_threshold": float(abstention_threshold)},
        "autoencoder": dict(autoencoder_metadata or {}),
        "metrics": metrics,
        "reproducibility": dict(reproducibility or {}),
        "candidate_status": candidate_status,
        "artifacts": artifacts,
    }
    path = root / "artifacts.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
