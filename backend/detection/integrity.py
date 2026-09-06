"""Dataset and executable model-artifact integrity checks.

Pickle/joblib artifacts are executable input.  Nothing in this module makes
pickle safe; it makes the trust boundary explicit and verifies a private,
locally generated checksum manifest *before* deserialization.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .features import FEATURE_NAMES


DATASET_MANIFEST_VERSION = "cyberguard-datasets-v1"
ARTIFACT_MANIFEST_VERSION = "cyberguard-artifacts-v1"
COVERAGE_CONTRACT_VERSION = "cyberguard-coverage-contract-v1"
LEGACY_PIPELINE_VERSION = "cyberguard-pipeline-legacy-v1"
PIPELINE_V2_VERSION = "cyberguard-pipeline-v2"
LEGACY_ROUTING_SCHEMA_VERSION = "cyberguard-routing-legacy-v1"
ROUTING_V2_SCHEMA_VERSION = "cyberguard-routing-v2"
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


def canonical_json_sha256(value: Any) -> str:
    """Hash deterministic JSON metadata, rejecting non-finite numbers."""
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IntegrityError("metadata is not canonical finite JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def feature_schema_hash() -> str:
    encoded = json.dumps(FEATURE_NAMES, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _string_set(value: Any, field: str, *, allow_empty: bool = True) -> set[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise IntegrityError(f"coverage contract {field} must be a list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise IntegrityError(f"coverage contract {field} contains an invalid label")
    labels = [item.strip() for item in value]
    if len(labels) != len(set(labels)):
        raise IntegrityError(f"coverage contract {field} contains duplicate labels")
    return set(labels)


def validate_coverage_contract(
    value: Any,
    classes: list[str],
    *,
    require_supported_evaluated: bool = False,
) -> dict[str, Any]:
    """Validate the model's explicit, scoped telemetry/class coverage claim."""
    if not isinstance(value, dict):
        raise IntegrityError("artifact has no coverage contract")
    required = {
        "schema_version",
        "trained_supported_labels",
        "evaluated_labels",
        "ood_only_labels",
        "unsupported_labels",
        "telemetry_profile",
    }
    missing = sorted(required - set(value))
    if missing:
        raise IntegrityError("coverage contract missing fields: " + ", ".join(missing))
    if value.get("schema_version") != COVERAGE_CONTRACT_VERSION:
        raise IntegrityError("unsupported coverage contract schema")
    telemetry = value.get("telemetry_profile")
    if not isinstance(telemetry, str) or not telemetry.strip():
        raise IntegrityError("coverage contract telemetry_profile is invalid")

    trained = _string_set(
        value.get("trained_supported_labels"),
        "trained_supported_labels",
        allow_empty=False,
    )
    evaluated = _string_set(value.get("evaluated_labels"), "evaluated_labels")
    ood = _string_set(value.get("ood_only_labels"), "ood_only_labels")
    unsupported = _string_set(value.get("unsupported_labels"), "unsupported_labels")
    declared_classes = {str(item) for item in classes}
    if trained != declared_classes:
        raise IntegrityError(
            "artifact classes must exactly match coverage trained_supported_labels"
        )
    if not ood <= evaluated:
        raise IntegrityError("coverage OOD-only labels must be independently evaluated")
    if trained & ood:
        raise IntegrityError("coverage labels cannot be both supported and OOD-only")
    if not evaluated <= (trained | ood):
        raise IntegrityError(
            "coverage evaluated labels must be categorized as supported or OOD-only"
        )
    if unsupported & (trained | evaluated | ood):
        raise IntegrityError("coverage unsupported labels overlap claimed coverage")
    if require_supported_evaluated and not trained <= evaluated:
        missing_evaluation = sorted(trained - evaluated)
        raise IntegrityError(
            "supported labels lack independent evaluation: "
            + ", ".join(missing_evaluation)
        )
    return value


def _finite_number(value: Any, field: str, *, lower: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise IntegrityError(f"{field} is missing or invalid")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < lower:
        raise IntegrityError(f"{field} is missing or invalid")
    return numeric


def _validate_pipeline_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    """Normalize legacy metadata and fail closed for incomplete Pipeline v2."""
    normalized = dict(manifest)
    production_approved = bool(normalized.get("production_approved", False))
    pipeline_version = normalized.get("pipeline_version")
    if pipeline_version is None:
        if production_approved:
            raise IntegrityError(
                "production-approved artifact cannot omit pipeline metadata"
            )
        normalized["pipeline_version"] = LEGACY_PIPELINE_VERSION
        normalized["routing_schema_version"] = LEGACY_ROUTING_SCHEMA_VERSION
        normalized["routing_calibration"] = {}
        normalized["evaluation_only"] = True
        normalized["legacy_metadata_inferred"] = True
        return normalized

    if pipeline_version == LEGACY_PIPELINE_VERSION:
        if production_approved:
            raise IntegrityError("legacy pipeline artifacts are evaluation-only")
        if normalized.get("routing_schema_version") != LEGACY_ROUTING_SCHEMA_VERSION:
            raise IntegrityError("legacy artifact routing schema is invalid")
        if normalized.get("evaluation_only") is not True:
            raise IntegrityError("legacy pipeline artifacts must be evaluation-only")
        calibration = normalized.get("routing_calibration", {})
        if not isinstance(calibration, dict):
            raise IntegrityError("legacy routing calibration metadata is invalid")
        return normalized

    if pipeline_version != PIPELINE_V2_VERSION:
        raise IntegrityError("unsupported artifact pipeline version")
    if normalized.get("routing_schema_version") != ROUTING_V2_SCHEMA_VERSION:
        raise IntegrityError("Pipeline v2 requires cyberguard-routing-v2")
    if normalized.get("evaluation_only") != (not production_approved):
        raise IntegrityError("artifact approval and evaluation-only states disagree")

    calibration = normalized.get("routing_calibration")
    if not isinstance(calibration, dict):
        raise IntegrityError("Pipeline v2 routing calibration metadata is missing")
    required = {
        "known_attack_confidence_threshold",
        "statistical_anomaly_threshold",
        "autoencoder_error_threshold",
        "calibration_source",
        "calibration_dataset_hashes",
    }
    missing = sorted(required - set(calibration))
    if missing:
        raise IntegrityError(
            "Pipeline v2 routing calibration missing fields: " + ", ".join(missing)
        )
    confidence = _finite_number(
        calibration["known_attack_confidence_threshold"],
        "known-attack confidence threshold",
    )
    if confidence > 1.0:
        raise IntegrityError("known-attack confidence threshold is missing or invalid")
    classifier_threshold = _finite_number(
        normalized.get("classifier", {}).get("abstention_threshold"),
        "artifact abstention threshold",
    )
    if not math.isclose(confidence, classifier_threshold, rel_tol=0.0, abs_tol=1e-12):
        raise IntegrityError("Pipeline v2 classifier threshold metadata mismatch")
    _finite_number(
        calibration["statistical_anomaly_threshold"],
        "statistical anomaly threshold",
    )
    ae_threshold = _finite_number(
        calibration["autoencoder_error_threshold"],
        "autoencoder error threshold",
    )
    artifact_ae_threshold = _finite_number(
        normalized.get("autoencoder", {}).get("threshold"),
        "artifact autoencoder threshold",
    )
    if not math.isclose(ae_threshold, artifact_ae_threshold, rel_tol=0.0, abs_tol=1e-12):
        raise IntegrityError("Pipeline v2 autoencoder threshold metadata mismatch")
    source = calibration.get("calibration_source")
    if not isinstance(source, str) or not source.strip():
        raise IntegrityError("Pipeline v2 calibration_source is missing or invalid")
    hashes = calibration.get("calibration_dataset_hashes")
    if not isinstance(hashes, dict) or not hashes:
        raise IntegrityError("Pipeline v2 calibration dataset hashes are missing")
    sha_pattern = re.compile(r"^[0-9a-f]{64}$")
    if any(
        not isinstance(name, str)
        or not name.strip()
        or not isinstance(digest, str)
        or not sha_pattern.fullmatch(digest)
        for name, digest in hashes.items()
    ):
        raise IntegrityError("Pipeline v2 calibration dataset hashes are invalid")
    declared_hashes = normalized.get("dataset_hashes")
    if not isinstance(declared_hashes, dict) or any(
        declared_hashes.get(name) != digest for name, digest in hashes.items()
    ):
        raise IntegrityError(
            "Pipeline v2 calibration hashes are not bound to declared datasets"
        )
    validate_coverage_contract(
        normalized.get("coverage_contract"),
        list(normalized.get("classes", [])),
        require_supported_evaluated=production_approved,
    )
    return normalized


def validate_loaded_routing_calibration(
    metadata: dict[str, Any],
    *,
    classifier_threshold: Any,
    statistical_threshold: Any,
    autoencoder_threshold: Any,
) -> None:
    """Ensure a loaded Pipeline v2 component matches signed-off metadata."""
    if metadata.get("pipeline_version") != PIPELINE_V2_VERSION:
        return
    calibration = metadata.get("routing_calibration", {})
    checks = (
        (
            "classifier",
            classifier_threshold,
            calibration.get("known_attack_confidence_threshold"),
        ),
        (
            "statistical",
            statistical_threshold,
            calibration.get("statistical_anomaly_threshold"),
        ),
        (
            "autoencoder",
            autoencoder_threshold,
            calibration.get("autoencoder_error_threshold"),
        ),
    )
    for name, loaded, declared in checks:
        loaded_value = _finite_number(loaded, f"loaded {name} threshold")
        declared_value = _finite_number(declared, f"declared {name} threshold")
        if not math.isclose(
            loaded_value, declared_value, rel_tol=0.0, abs_tol=1e-12
        ):
            raise IntegrityError(
                f"loaded {name} threshold does not match routing calibration"
            )


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
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise IntegrityError("artifact manifest must be a regular non-symlink file")
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
        declaration = artifacts[filename]
        if not isinstance(declaration, dict):
            raise IntegrityError(f"artifact checksum declaration is invalid: {filename}")
        expected = declaration.get("sha256")
        if not isinstance(expected, str) or sha256_file(path) != expected:
            raise IntegrityError(f"artifact SHA-256 mismatch: {filename}")
    threshold = manifest.get("classifier", {}).get("abstention_threshold")
    if not isinstance(threshold, (int, float)) or not 0.0 < float(threshold) <= 1.0:
        raise IntegrityError("artifact abstention threshold is missing or invalid")
    normalized = _validate_pipeline_contract(manifest)
    coverage = normalized.get("coverage_contract")
    if coverage is not None:
        validate_coverage_contract(
            coverage,
            list(normalized.get("classes", [])),
            require_supported_evaluated=bool(normalized.get("production_approved")),
        )
    return normalized


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
    coverage_contract: dict[str, Any] | None = None,
    pipeline_version: str = LEGACY_PIPELINE_VERSION,
    routing_schema_version: str = LEGACY_ROUTING_SCHEMA_VERSION,
    routing_calibration: dict[str, Any] | None = None,
    evaluation_only: bool | None = None,
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
        "evaluation_only": (
            not bool(production_approved)
            if evaluation_only is None else bool(evaluation_only)
        ),
        "pipeline_version": pipeline_version,
        "routing_schema_version": routing_schema_version,
        "routing_calibration": dict(routing_calibration or {}),
        "dataset_hashes": {
            str(item["id"]): str(item["sha256"]) for item in dataset_entries
        },
        "classes": list(classes),
        "classifier": {"abstention_threshold": float(abstention_threshold)},
        "autoencoder": dict(autoencoder_metadata or {}),
        "metrics": metrics,
        "reproducibility": dict(reproducibility or {}),
        "candidate_status": candidate_status,
        "coverage_contract": coverage_contract,
        "artifacts": artifacts,
    }
    path = root / "artifacts.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
