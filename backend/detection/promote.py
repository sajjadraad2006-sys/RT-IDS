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
from .integrity import IntegrityError, validate_artifact_bundle


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
    gates = metadata.get("metrics", {}).get("quality_gate_results", {})
    if not isinstance(gates, dict) or not gates:
        raise IntegrityError("candidate has no declared quality-gate results")
    failed = sorted(name for name, passed in gates.items() if passed is not True)
    if failed:
        raise IntegrityError("candidate failed promotion gates: " + ", ".join(failed))
    if metadata.get("production_approved"):
        raise IntegrityError("candidate is already marked production-approved")
    return {
        "candidate": str(candidate),
        "classes": metadata.get("classes", []),
        "candidate_status": metadata.get("candidate_status"),
        "quality_gates": gates,
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
    manifest["promotion"] = {
        "approved_by": reviewer,
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "source_candidate": str(candidate.relative_to(BASE_DIR)),
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
