"""Human-gated candidate promotion. Dry-run is the default."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from ..config import BASE_DIR, MODELS_DIR
from .bundles import ACTIVE_POINTER, resolve_active_bundle_dir
from .integrity import (
    PIPELINE_V2_VERSION,
    ROUTING_V2_SCHEMA_VERSION,
    IntegrityError,
    canonical_json_sha256,
    sha256_file,
    validate_artifact_bundle,
    validate_coverage_contract,
)
from .shadow import SHADOW_REPORT_VERSION


PROMOTABLE_CANDIDATE_STATUS = "shadow_only_not_promoted"


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _candidate_path(value: Path) -> Path:
    root = (MODELS_DIR / "candidates").resolve()
    target = value.resolve()
    if root not in target.parents or not target.is_dir() or target.is_symlink():
        raise IntegrityError("candidate must be a real directory under data/models/candidates")
    return target


def verify_promotion(candidate: Path) -> dict:
    candidate = _candidate_path(candidate)
    metadata = validate_artifact_bundle(candidate)
    if metadata.get("production_approved"):
        raise IntegrityError("candidate is already marked production-approved")
    if metadata.get("candidate_status") != PROMOTABLE_CANDIDATE_STATUS:
        raise IntegrityError(
            "candidate status is not promotable: "
            + str(metadata.get("candidate_status", "missing"))
        )
    metrics_status = metadata.get("metrics", {}).get("candidate_status")
    if metrics_status is not None and metrics_status != PROMOTABLE_CANDIDATE_STATUS:
        raise IntegrityError("candidate metric status disagrees with artifact status")
    if metadata.get("pipeline_version") != PIPELINE_V2_VERSION:
        raise IntegrityError("only a calibrated Pipeline v2 candidate is promotable")
    if metadata.get("routing_schema_version") != ROUTING_V2_SCHEMA_VERSION:
        raise IntegrityError("candidate does not use the required routing schema")
    coverage = validate_coverage_contract(
        metadata.get("coverage_contract"),
        list(metadata.get("classes", [])),
        require_supported_evaluated=True,
    )
    gates = metadata.get("metrics", {}).get("quality_gate_results", {})
    if not isinstance(gates, dict) or not gates:
        raise IntegrityError("candidate has no declared quality-gate results")
    failed = sorted(name for name, passed in gates.items() if passed is not True)
    if failed:
        raise IntegrityError("candidate failed promotion gates: " + ", ".join(failed))

    report_path = candidate / "shadow_report.json"
    if not report_path.is_file() or report_path.is_symlink():
        raise IntegrityError("candidate has no safe shadow_report.json")
    try:
        shadow = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"candidate shadow report is invalid: {exc}") from exc
    if not isinstance(shadow, dict):
        raise IntegrityError("candidate shadow report must be one JSON object")
    if shadow.get("schema_version") != SHADOW_REPORT_VERSION:
        raise IntegrityError("candidate shadow report schema is missing or stale")
    if shadow.get("shadow_status") != "passed":
        raise IntegrityError("candidate shadow evaluation did not pass")
    try:
        report_candidate = Path(str(shadow.get("candidate_bundle"))).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise IntegrityError("candidate shadow report path is invalid") from exc
    if report_candidate != candidate:
        raise IntegrityError("candidate shadow report belongs to a different candidate")

    manifest_digest = sha256_file(candidate / "artifacts.json")
    if shadow.get("candidate_manifest_sha256") != manifest_digest:
        raise IntegrityError("candidate shadow report manifest digest is stale")
    artifact_hashes = {
        name: str(item.get("sha256"))
        for name, item in metadata.get("artifacts", {}).items()
    }
    if shadow.get("candidate_artifact_hashes") != artifact_hashes:
        raise IntegrityError("candidate shadow report artifact hashes do not match")
    if shadow.get("candidate_pipeline_version") != metadata.get("pipeline_version"):
        raise IntegrityError("candidate shadow report pipeline version does not match")
    if shadow.get("candidate_routing_schema_version") != metadata.get(
        "routing_schema_version"
    ):
        raise IntegrityError("candidate shadow report routing schema does not match")
    calibration_digest = canonical_json_sha256(metadata.get("routing_calibration"))
    if shadow.get("candidate_routing_calibration_sha256") != calibration_digest:
        raise IntegrityError("candidate shadow report calibration metadata does not match")
    coverage_digest = canonical_json_sha256(metadata.get("coverage_contract"))
    if shadow.get("candidate_coverage_contract_sha256") != coverage_digest:
        raise IntegrityError("candidate shadow report coverage contract does not match")
    audit_digest = shadow.get("audit_sha256")
    if not isinstance(audit_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", audit_digest):
        raise IntegrityError("candidate shadow report audit digest is invalid")
    rows = shadow.get("rows")
    if isinstance(rows, bool) or not isinstance(rows, int) or rows <= 0:
        raise IntegrityError("candidate shadow report contains no evaluated rows")

    if shadow.get("artifact_hashes_unchanged") is not True:
        raise IntegrityError("candidate artifacts changed during shadow evaluation")
    if shadow.get("manifest_hashes_unchanged") is not True:
        raise IntegrityError("candidate manifest changed during shadow evaluation")
    for counter in ("llm_calls", "database_mutations", "active_pointer_mutations"):
        if shadow.get(counter) != 0:
            raise IntegrityError(f"shadow evaluation recorded forbidden {counter}")
    invariants = shadow.get("state_invariants")
    if not isinstance(invariants, dict):
        raise IntegrityError("candidate shadow report has no state invariants")
    artifacts_before = invariants.get("artifacts_before", {})
    artifacts_after = invariants.get("artifacts_after", {})
    manifests_before = invariants.get("manifests_before", {})
    manifests_after = invariants.get("manifests_after", {})
    if (
        not isinstance(artifacts_before, dict)
        or not isinstance(artifacts_after, dict)
        or artifacts_before.get("candidate") != artifact_hashes
        or artifacts_after.get("candidate") != artifact_hashes
    ):
        raise IntegrityError("shadow artifact invariants do not match the candidate")
    if (
        not isinstance(manifests_before, dict)
        or not isinstance(manifests_after, dict)
        or manifests_before.get("candidate") != manifest_digest
        or manifests_after.get("candidate") != manifest_digest
    ):
        raise IntegrityError("shadow manifest invariants do not match the candidate")
    for before_key, after_key, description in (
        ("active_pointer_before", "active_pointer_after", "active pointer"),
        ("database_before", "database_after", "database"),
    ):
        if invariants.get(before_key) != invariants.get(after_key):
            raise IntegrityError(f"shadow {description} state changed")
    return {
        "candidate": str(candidate),
        "classes": metadata.get("classes", []),
        "candidate_status": metadata.get("candidate_status"),
        "pipeline_version": metadata.get("pipeline_version"),
        "routing_schema_version": metadata.get("routing_schema_version"),
        "coverage_contract": coverage,
        "quality_gates": gates,
        "shadow_report": str(report_path),
        "shadow_report_sha256": sha256_file(report_path),
        "shadow_rows": rows,
        "current_active": str(resolve_active_bundle_dir()),
        "dry_run": True,
        "eligible": True,
    }


def promote(candidate: Path, approved_by: str) -> dict:
    result = verify_promotion(candidate)
    reviewer = re.sub(r"[^A-Za-z0-9_.@ -]", "", approved_by).strip()[:64]
    if not reviewer:
        raise ValueError("approved_by is required for a real promotion")
    candidate = Path(result["candidate"])
    release_root = MODELS_DIR / "releases"
    release_root.mkdir(parents=True, exist_ok=True)
    release = release_root / candidate.name
    if release.exists():
        raise FileExistsError(f"release already exists: {release}")
    shutil.copytree(candidate, release, symlinks=False)
    manifest_path = release / "artifacts.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["production_approved"] = True
    manifest["evaluation_only"] = False
    manifest["candidate_status"] = "production_approved"
    manifest["promotion"] = {
        "approved_by": reviewer,
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "source_candidate": str(candidate.relative_to(BASE_DIR)),
        "source_shadow_report_sha256": result["shadow_report_sha256"],
    }
    _atomic_json(manifest_path, manifest)
    validate_artifact_bundle(release)
    previous = str(resolve_active_bundle_dir().relative_to(BASE_DIR))
    pointer = {
        "schema_version": "cyberguard-active-bundle-v1",
        "bundle_path": str(release.relative_to(BASE_DIR)),
        "previous_bundle_path": previous,
        "approved_by": reviewer,
        "switched_at": datetime.now(timezone.utc).isoformat(),
    }
    _atomic_json(ACTIVE_POINTER, pointer)
    return {**result, "dry_run": False, "release": str(release), "previous": previous}


def rollback(approved_by: str) -> dict:
    reviewer = re.sub(r"[^A-Za-z0-9_.@ -]", "", approved_by).strip()[:64]
    if not reviewer:
        raise ValueError("approved_by is required for rollback")
    payload = json.loads(ACTIVE_POINTER.read_text(encoding="utf-8"))
    previous = payload.get("previous_bundle_path")
    if not isinstance(previous, str):
        raise IntegrityError("active pointer has no rollback predecessor")
    current = payload["bundle_path"]
    _atomic_json(ACTIVE_POINTER, {
        "schema_version": "cyberguard-active-bundle-v1",
        "bundle_path": previous,
        "previous_bundle_path": current,
        "approved_by": reviewer,
        "switched_at": datetime.now(timezone.utc).isoformat(),
        "rollback": True,
    })
    resolved = resolve_active_bundle_dir()
    validate_artifact_bundle(resolved)
    return {"rolled_back": True, "active": str(resolved), "previous": current}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path, nargs="?")
    parser.add_argument("--apply", action="store_true", help="create a release and switch pointer")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--approved-by")
    args = parser.parse_args()
    if args.rollback:
        print(json.dumps(rollback(args.approved_by or ""), indent=2))
    elif args.candidate is None:
        parser.error("candidate is required unless --rollback is used")
    elif args.apply:
        print(json.dumps(promote(args.candidate, args.approved_by or ""), indent=2))
    else:
        print(json.dumps(verify_promotion(args.candidate), indent=2))
