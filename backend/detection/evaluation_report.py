"""Cryptographic provenance envelope for future evaluation measurements.

Metric calculation remains in candidate_workflow. This module refuses to bind
an incomplete result and prevents fixture/calibration/shadow reports from being
represented as untouched independent final-evaluation accuracy.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .evaluation_intake import INTAKE_REPORT_VERSION
from .integrity import (
    ARTIFACT_FILENAMES,
    IntegrityError,
    PIPELINE_V2_VERSION,
    ROUTING_V2_SCHEMA_VERSION,
    canonical_json_sha256,
    sha256_file,
)


EVALUATION_REPORT_VERSION = "cyberguard-evaluation-report-v1"
MEASUREMENT_ROLES = frozenset({
    "synthetic_fixture_verification",
    "calibration_measurement",
    "shadow_measurement",
    "final_evaluation",
})
_BINARY_KEYS = {
    "tp", "fp", "fn", "tn", "precision", "recall", "f1",
    "benign_false_positive_rate", "false_positives_per_10000_benign",
}


def _required_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IntegrityError(f"evaluation metrics missing {field}")
    return value


def _validate_metric_contract(
    metrics: Mapping[str, Any], *, require_isolation_forest: bool
) -> None:
    binary = _required_mapping(
        metrics.get("binary_attack_vs_benign"), "binary_attack_vs_benign"
    )
    required_detectors = ["classifier", "statistical", "autoencoder", "pipeline"]
    if require_isolation_forest:
        required_detectors.append("isolation_forest")
    for detector in required_detectors:
        detector_metrics = _required_mapping(binary.get(detector), f"binary.{detector}")
        missing = sorted(_BINARY_KEYS - set(detector_metrics))
        if missing:
            raise IntegrityError(
                f"evaluation binary.{detector} missing metrics: {', '.join(missing)}"
            )
    classifier = _required_mapping(metrics.get("classifier"), "classifier")
    per_class = classifier.get("per_class")
    if not isinstance(per_class, Mapping) or not per_class:
        raise IntegrityError("evaluation metrics missing classifier per-class metrics")
    for label, value in per_class.items():
        class_metrics = _required_mapping(value, f"classifier.per_class.{label}")
        if not {"precision", "recall", "f1", "pr_auc", "support"} <= set(
            class_metrics
        ):
            raise IntegrityError(
                f"evaluation metrics incomplete classifier.per_class.{label}"
            )
    for aggregate in ("macro", "weighted"):
        value = _required_mapping(classifier.get(aggregate), f"classifier.{aggregate}")
        if not {"precision", "recall", "f1"} <= set(value):
            raise IntegrityError(f"evaluation metrics incomplete classifier.{aggregate}")
    if "expected_calibration_error_10_bin" not in classifier:
        raise IntegrityError("evaluation metrics missing calibration measurement")
    routing = _required_mapping(metrics.get("routing"), "routing")
    required_routing = {
        "counts", "review_rate", "human_review_rate",
        "unknown_anomaly_review_rate", "unsupported_label_rate",
    }
    if not required_routing <= set(routing):
        raise IntegrityError("evaluation metrics missing routing rates")
    ood = _required_mapping(metrics.get("ood"), "ood")
    if "high_confidence_known_mislabel_rate" not in ood:
        raise IntegrityError("evaluation metrics missing high-confidence OOD rate")
    benchmark = _required_mapping(metrics.get("benchmark"), "benchmark")
    if not any(
        isinstance(value, Mapping) and "throughput_rows_per_second" in value
        for value in benchmark.values()
    ):
        raise IntegrityError("evaluation metrics missing throughput benchmark")
    resources = _required_mapping(metrics.get("resources"), "resources")
    if "peak_process_rss_kib" not in resources:
        raise IntegrityError("evaluation metrics missing peak RSS")


def _artifact_hashes(artifact_dir: Path) -> dict[str, str]:
    names = list(ARTIFACT_FILENAMES)
    isolation = artifact_dir / "isolation_forest.pkl"
    if isolation.is_file() and not isolation.is_symlink():
        names.append("isolation_forest.pkl")
    result = {}
    for name in names:
        path = artifact_dir / name
        if not path.is_file() or path.is_symlink():
            raise IntegrityError(f"evaluation artifact is missing or unsafe: {name}")
        result[name] = sha256_file(path)
    return result


def _split_hashes(value: Mapping[str, str | Path]) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise IntegrityError("evaluation split manifests are missing")
    result = {}
    for role, raw_path in sorted(value.items()):
        if role not in {"training", "calibration", "shadow", "final_evaluation"}:
            raise IntegrityError(f"evaluation split role is invalid: {role}")
        path = Path(raw_path)
        if not path.is_file() or path.is_symlink():
            raise IntegrityError(f"evaluation split manifest is missing or unsafe: {role}")
        result[role] = sha256_file(path)
    return result


def build_evaluation_report(
    metrics: Mapping[str, Any],
    *,
    measurement_role: str,
    intake_report: Mapping[str, Any],
    dataset_manifest_path: str | Path,
    split_manifest_paths: Mapping[str, str | Path],
    artifact_dir: str | Path,
    calibration_metadata: Mapping[str, Any],
    source_revision: str,
    command: list[str],
    environment: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind complete metrics to immutable inputs without running evaluation."""
    if measurement_role not in MEASUREMENT_ROLES:
        raise IntegrityError("evaluation measurement role is missing or ambiguous")
    if intake_report.get("schema_version") != INTAKE_REPORT_VERSION:
        raise IntegrityError("evaluation report requires a validated intake report")
    if intake_report.get("status") != "validated":
        raise IntegrityError("independent-data intake did not validate")
    if intake_report.get("fixture_only") and measurement_role != (
        "synthetic_fixture_verification"
    ):
        raise IntegrityError("fixture measurements cannot be labeled as model evaluation")
    if measurement_role == "final_evaluation" and intake_report.get(
        "accuracy_claim_allowed"
    ) is not True:
        raise IntegrityError("final evaluation is not approved by the intake contract")
    artifact_dir = Path(artifact_dir)
    if not artifact_dir.is_dir() or artifact_dir.is_symlink():
        raise IntegrityError("evaluation artifact directory is missing or unsafe")
    _validate_metric_contract(
        metrics,
        require_isolation_forest=(artifact_dir / "isolation_forest.pkl").is_file(),
    )

    dataset_manifest = Path(dataset_manifest_path)
    if not dataset_manifest.is_file() or dataset_manifest.is_symlink():
        raise IntegrityError("evaluation dataset manifest is missing or unsafe")
    dataset_hash = sha256_file(dataset_manifest)
    if dataset_hash != intake_report.get("manifest_sha256"):
        raise IntegrityError("evaluation dataset manifest changed after intake")
    revision = str(source_revision).strip()
    if not revision:
        raise IntegrityError("evaluation source revision is missing")
    if not isinstance(command, list) or not command or any(
        not isinstance(item, str) or not item for item in command
    ):
        raise IntegrityError("evaluation command metadata is missing or invalid")
    if not isinstance(environment, Mapping) or not environment:
        raise IntegrityError("evaluation environment metadata is missing")
    report = {
        "schema_version": EVALUATION_REPORT_VERSION,
        "measurement_role": measurement_role,
        "accuracy_claim_allowed": bool(
            measurement_role == "final_evaluation"
            and intake_report.get("accuracy_claim_allowed") is True
        ),
        "dataset_id": intake_report.get("dataset_id"),
        "dataset_manifest_sha256": dataset_hash,
        "split_manifest_hashes": _split_hashes(split_manifest_paths),
        "artifact_hashes": _artifact_hashes(artifact_dir),
        "metrics_sha256": canonical_json_sha256(metrics),
        "calibration_metadata_sha256": canonical_json_sha256(calibration_metadata),
        "pipeline_version": PIPELINE_V2_VERSION,
        "routing_schema_version": ROUTING_V2_SCHEMA_VERSION,
        "source_revision": revision,
        "command": list(command),
        "environment": dict(environment),
        "intake_report": dict(intake_report),
        "metrics": dict(metrics),
    }
    report["report_payload_sha256"] = canonical_json_sha256(report)
    return report


def validate_evaluation_report_bindings(
    report: Mapping[str, Any],
    *,
    dataset_manifest_path: str | Path,
    split_manifest_paths: Mapping[str, str | Path],
    artifact_dir: str | Path,
    calibration_metadata: Mapping[str, Any],
) -> None:
    """Recompute every external binding before a report is consumed."""
    if report.get("schema_version") != EVALUATION_REPORT_VERSION:
        raise IntegrityError("evaluation report schema is missing or stale")
    if report.get("pipeline_version") != PIPELINE_V2_VERSION:
        raise IntegrityError("evaluation report pipeline version is stale")
    if report.get("routing_schema_version") != ROUTING_V2_SCHEMA_VERSION:
        raise IntegrityError("evaluation report routing schema is stale")
    expected = {
        "dataset_manifest_sha256": sha256_file(dataset_manifest_path),
        "split_manifest_hashes": _split_hashes(split_manifest_paths),
        "artifact_hashes": _artifact_hashes(Path(artifact_dir)),
        "calibration_metadata_sha256": canonical_json_sha256(calibration_metadata),
        "metrics_sha256": canonical_json_sha256(
            _required_mapping(report.get("metrics"), "metrics")
        ),
    }
    for field, value in expected.items():
        if report.get(field) != value:
            raise IntegrityError(f"evaluation report {field} binding does not match")
    payload = dict(report)
    recorded_payload_hash = payload.pop("report_payload_sha256", None)
    if recorded_payload_hash != canonical_json_sha256(payload):
        raise IntegrityError("evaluation report payload digest does not match")
