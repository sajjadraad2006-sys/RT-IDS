"""Fail-closed intake validation for future independent evaluation data.

The validator performs no acquisition and accepts no accuracy claims. Licensed
data remains outside the repository. A manifest binds every capture and its
streamable, label-independent feature fingerprint sidecar before any split may
be used by training, calibration, shadow, or final evaluation code.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime
import json
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Any, Iterable

from .integrity import sha256_file


INTAKE_MANIFEST_VERSION = "cyberguard-independent-data-manifest-v1"
INTAKE_REPORT_VERSION = "cyberguard-independent-data-intake-report-v1"
FINGERPRINT_SIDECAR_VERSION = "cyberguard-feature-fingerprints-jsonl-v1"
DATASET_ROLES = ("training", "calibration", "shadow", "final_evaluation")
SUPPORTED_TELEMETRY_PROFILES = frozenset({
    "cyberguard-canonical-flow-v1",
    "cicids2017-cicflowmeter",
    "cse-cic-ids2018-cicflowmeter-v3",
    "cse-cic-ids2018-cicflowmeter-v3-derived-v2",
})
MAX_FINGERPRINT_LINE_BYTES = 16 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")


class IntakeValidationError(RuntimeError):
    """A dataset cannot cross the independent-evaluation intake boundary."""


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IntakeValidationError("manifest_or_sidecar_duplicate_json_key")
        result[key] = value
    return result


def _load_json_object(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except IntakeValidationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeValidationError(f"{description} is missing or malformed") from exc
    if not isinstance(value, dict):
        raise IntakeValidationError(f"{description} must be one JSON object")
    return value


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IntakeValidationError(f"{field} is missing or invalid")
    return value.strip()


def _required_sha256(value: Any, field: str) -> str:
    digest = _required_text(value, field)
    if not _SHA256.fullmatch(digest):
        raise IntakeValidationError(f"{field} must be a lowercase SHA-256 digest")
    return digest


def _required_size(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IntakeValidationError(f"{field} is missing or invalid")
    return value


def _string_list(value: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise IntakeValidationError(f"{field} must be a list")
    cleaned = [_required_text(item, field) for item in value]
    if len(cleaned) != len(set(cleaned)):
        raise IntakeValidationError(f"{field} contains duplicate values")
    return cleaned


def _safe_regular_file(root: Path, value: Any, field: str) -> Path:
    relative = Path(_required_text(value, field))
    if relative.is_absolute() or ".." in relative.parts:
        raise IntakeValidationError(f"{field} must stay within the dataset root")
    candidate = root / relative
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise IntakeValidationError(f"{field} cannot traverse a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise IntakeValidationError(f"{field} does not identify an existing file") from exc
    if root != resolved and root not in resolved.parents:
        raise IntakeValidationError(f"{field} escapes the dataset root")
    if not resolved.is_file():
        raise IntakeValidationError(f"{field} must identify a regular file")
    return resolved


def _verify_bound_file(
    root: Path,
    value: dict[str, Any],
    *,
    prefix: str,
) -> Path:
    path = _safe_regular_file(root, value.get("path"), f"{prefix}.path")
    expected_size = _required_size(value.get("bytes"), f"{prefix}.bytes")
    expected_hash = _required_sha256(value.get("sha256"), f"{prefix}.sha256")
    if path.stat().st_size != expected_size:
        raise IntakeValidationError(f"{prefix} file size changed after manifest creation")
    if sha256_file(path) != expected_hash:
        raise IntakeValidationError(f"{prefix} file hash changed after manifest creation")
    return path


def _aware_datetime(value: Any, field: str) -> datetime:
    text = _required_text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntakeValidationError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IntakeValidationError(f"{field} must include a timezone")
    return parsed


def _validate_source(value: Any) -> None:
    if not isinstance(value, dict):
        raise IntakeValidationError("source_and_license_record is missing or invalid")
    for field in ("name", "source_uri", "license_id", "license_record"):
        _required_text(value.get(field), f"source.{field}")
    acquired = _required_text(value.get("acquisition_date"), "source.acquisition_date")
    try:
        date.fromisoformat(acquired)
    except ValueError as exc:
        raise IntakeValidationError("source.acquisition_date must be YYYY-MM-DD") from exc


def _iter_fingerprints(
    path: Path,
    *,
    file_id: str,
    supported_labels: set[str],
) -> Iterable[tuple[str, str]]:
    with path.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if len(raw_line) > MAX_FINGERPRINT_LINE_BYTES:
                raise IntakeValidationError(
                    f"fingerprint line too large: {file_id}:{line_number}"
                )
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(
                    stripped.decode("utf-8"),
                    object_pairs_hook=_object_without_duplicates,
                )
            except IntakeValidationError:
                raise
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise IntakeValidationError(
                    f"malformed fingerprint sidecar line: {file_id}:{line_number}"
                ) from exc
            if not isinstance(value, dict) or set(value) != {"feature_sha256", "label"}:
                raise IntakeValidationError(
                    f"invalid fingerprint sidecar record: {file_id}:{line_number}"
                )
            feature_hash = _required_sha256(
                value.get("feature_sha256"),
                f"fingerprint {file_id}:{line_number}.feature_sha256",
            )
            label = _required_text(
                value.get("label"), f"fingerprint {file_id}:{line_number}.label"
            )
            if label not in supported_labels:
                raise IntakeValidationError(
                    f"fingerprint label outside declared supported labels: {file_id}:{line_number}"
                )
            yield feature_hash, label


def _check_forward_time(ranges: dict[str, list[tuple[datetime, datetime]]]) -> None:
    populated = [role for role in DATASET_ROLES if ranges.get(role)]
    for earlier_index, earlier_role in enumerate(populated):
        earlier_end = max(end for _, end in ranges[earlier_role])
        for later_role in populated[earlier_index + 1:]:
            later_start = min(start for start, _ in ranges[later_role])
            if earlier_end > later_start:
                raise IntakeValidationError(
                    f"forward_time_leakage:{earlier_role}_overlaps_or_follows_{later_role}"
                )


def validate_intake_manifest(
    manifest_path: str | Path,
    *,
    dataset_root: str | Path | None = None,
) -> dict[str, Any]:
    """Validate immutable data/split provenance without loading feature matrices."""
    manifest_path = Path(manifest_path)
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise IntakeValidationError("dataset manifest is missing or unsafe")
    root = Path(dataset_root) if dataset_root is not None else manifest_path.parent
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise IntakeValidationError("dataset root is missing or invalid") from exc
    if not root.is_dir():
        raise IntakeValidationError("dataset root must be a directory")

    manifest = _load_json_object(manifest_path, "dataset manifest")
    if manifest.get("schema_version") != INTAKE_MANIFEST_VERSION:
        raise IntakeValidationError("unsupported independent-data manifest schema")
    dataset_id = _required_text(manifest.get("dataset_id"), "dataset_id")
    _validate_source(manifest.get("source_and_license_record"))
    telemetry_profile = _required_text(
        manifest.get("telemetry_profile"), "telemetry_profile"
    )
    if telemetry_profile not in SUPPORTED_TELEMETRY_PROFILES:
        raise IntakeValidationError("unsupported_telemetry_profile")
    if manifest.get("role_overlap_prohibited") is not True:
        raise IntakeValidationError("role_overlap_prohibited must be true")
    if not isinstance(manifest.get("forward_time_evaluation"), bool):
        raise IntakeValidationError("forward_time_evaluation must be explicit")
    if not isinstance(manifest.get("fixture_only"), bool):
        raise IntakeValidationError("fixture_only must be explicit")
    if not isinstance(manifest.get("evaluation_approved"), bool):
        raise IntakeValidationError("evaluation_approved must be explicit")
    if manifest["fixture_only"] and manifest["evaluation_approved"]:
        raise IntakeValidationError("fixture data cannot be approved for evaluation")

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise IntakeValidationError("files must be a non-empty list")
    seen_file_ids: set[str] = set()
    seen_paths: set[str] = set()
    capture_roles: dict[str, str] = {}
    role_counts: Counter[str] = Counter()
    time_ranges: dict[str, list[tuple[datetime, datetime]]] = {
        role: [] for role in DATASET_ROLES
    }
    fingerprint_specs: list[tuple[Path, str, str, str, set[str]]] = []

    for index, item in enumerate(files):
        prefix = f"files[{index}]"
        if not isinstance(item, dict):
            raise IntakeValidationError(f"{prefix} must be one object")
        file_id = _required_text(item.get("file_id"), f"{prefix}.file_id")
        if file_id in seen_file_ids:
            raise IntakeValidationError("duplicate_file_id")
        seen_file_ids.add(file_id)
        role = item.get("intended_role")
        if not isinstance(role, str) or role not in DATASET_ROLES:
            raise IntakeValidationError(f"ambiguous_or_unsupported_dataset_role:{file_id}")
        capture_id = _required_text(item.get("capture_id"), f"{prefix}.capture_id")
        previous_role = capture_roles.setdefault(capture_id, role)
        if previous_role != role:
            raise IntakeValidationError(f"capture_overlap_across_splits:{capture_id}")

        data_path = _verify_bound_file(root, item, prefix=prefix)
        relative_data = str(data_path.relative_to(root))
        if relative_data in seen_paths:
            raise IntakeValidationError("file_path_reused_across_manifest_entries")
        seen_paths.add(relative_data)

        labels = set(_string_list(
            item.get("supported_labels"), f"{prefix}.supported_labels"
        ))
        provenance = item.get("label_provenance")
        if not isinstance(provenance, dict):
            raise IntakeValidationError(f"{prefix}.label_provenance is missing")
        _required_text(provenance.get("method"), f"{prefix}.label_provenance.method")
        _required_text(
            provenance.get("reference"), f"{prefix}.label_provenance.reference"
        )
        _string_list(item.get("known_preprocessing"), f"{prefix}.known_preprocessing")
        capture_range = item.get("capture_time_range")
        if not isinstance(capture_range, dict):
            raise IntakeValidationError(f"{prefix}.capture_time_range is missing")
        start = _aware_datetime(capture_range.get("start"), f"{prefix}.capture_time_range.start")
        end = _aware_datetime(capture_range.get("end"), f"{prefix}.capture_time_range.end")
        if start > end:
            raise IntakeValidationError(f"invalid_capture_time_range:{capture_id}")
        time_ranges[role].append((start, end))

        fingerprint = item.get("feature_fingerprints")
        if not isinstance(fingerprint, dict):
            raise IntakeValidationError(f"{prefix}.feature_fingerprints is missing")
        if fingerprint.get("schema_version") != FINGERPRINT_SIDECAR_VERSION:
            raise IntakeValidationError("unsupported_feature_fingerprint_schema")
        if fingerprint.get("label_included_in_feature_hash") is not False:
            raise IntakeValidationError("feature fingerprints must exclude labels")
        fingerprint_path = _verify_bound_file(
            root, fingerprint, prefix=f"{prefix}.feature_fingerprints"
        )
        relative_fingerprint = str(fingerprint_path.relative_to(root))
        if relative_fingerprint in seen_paths:
            raise IntakeValidationError("file_path_reused_across_manifest_entries")
        seen_paths.add(relative_fingerprint)
        fingerprint_specs.append((
            fingerprint_path, file_id, capture_id, role, labels
        ))
        role_counts[role] += 1

    if manifest["forward_time_evaluation"]:
        _check_forward_time(time_ranges)

    fingerprint_rows = 0
    with tempfile.TemporaryDirectory(prefix="cyberguard-intake-") as temporary:
        database = Path(temporary) / "fingerprints.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "CREATE TABLE fingerprints ("
                "feature_sha256 TEXT PRIMARY KEY, label TEXT NOT NULL, "
                "role TEXT NOT NULL, file_id TEXT NOT NULL, capture_id TEXT NOT NULL)"
            )
            for path, file_id, capture_id, role, labels in fingerprint_specs:
                for feature_hash, label in _iter_fingerprints(
                    path, file_id=file_id, supported_labels=labels
                ):
                    fingerprint_rows += 1
                    previous = connection.execute(
                        "SELECT label, role, file_id FROM fingerprints "
                        "WHERE feature_sha256 = ?",
                        (feature_hash,),
                    ).fetchone()
                    if previous is None:
                        connection.execute(
                            "INSERT INTO fingerprints VALUES (?, ?, ?, ?, ?)",
                            (feature_hash, label, role, file_id, capture_id),
                        )
                        continue
                    previous_label, previous_role, previous_file = previous
                    if previous_label != label:
                        raise IntakeValidationError(
                            "conflicting_label_duplicate:"
                            f"{previous_file}:{file_id}:{feature_hash}"
                        )
                    if previous_role != role:
                        role_pair = {previous_role, role}
                        reason = (
                            "final_evaluation_data_reused_for_calibration"
                            if role_pair == {"calibration", "final_evaluation"}
                            else "exact_feature_duplicate_crossing_splits"
                        )
                        raise IntakeValidationError(
                            f"{reason}:{previous_file}:{file_id}:{feature_hash}"
                        )
            connection.commit()
        finally:
            connection.close()

    return {
        "schema_version": INTAKE_REPORT_VERSION,
        "status": "validated",
        "dataset_id": dataset_id,
        "manifest_sha256": sha256_file(manifest_path),
        "telemetry_profile": telemetry_profile,
        "roles": {role: role_counts.get(role, 0) for role in DATASET_ROLES},
        "files": len(files),
        "fingerprint_rows": fingerprint_rows,
        "capture_disjoint": True,
        "forward_time_evaluation": manifest["forward_time_evaluation"],
        "fixture_only": manifest["fixture_only"],
        "evaluation_approved": manifest["evaluation_approved"],
        "accuracy_claim_allowed": bool(
            not manifest["fixture_only"] and manifest["evaluation_approved"]
        ),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Validate a future independent-data intake manifest"
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--dataset-root", type=Path)
    arguments = parser.parse_args()
    try:
        report = validate_intake_manifest(
            arguments.manifest, dataset_root=arguments.dataset_root
        )
    except IntakeValidationError as exc:
        parser.exit(1, f"intake validation failed: {exc}\n")
    print(json.dumps(report, indent=2, sort_keys=True))
