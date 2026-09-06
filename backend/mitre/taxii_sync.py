"""Safe, freshness-aware MITRE ATT&CK Enterprise synchronization."""
from __future__ import annotations

import argparse
import json
import hashlib
import logging
import os
import re
import time
from pathlib import Path

from ..config import (
    ATTACK_VERSION,
    MITRE_DIR,
    MITRE_SYNC_MAX_AGE_HOURS,
)

log = logging.getLogger("cyberguard.taxii")
_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
_MIN_OBJECTS = 1000
_RELEASE_PATTERN = re.compile(r"^v(\d+)\.(\d+)$")
_OFFICIAL_RELEASE_ROOT = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack"
)


def official_release_url(version: str) -> str:
    """Return MITRE's immutable-by-name enterprise release artifact URL."""
    match = _RELEASE_PATTERN.fullmatch(str(version))
    if not match:
        raise ValueError("ATT&CK release must have the form vMAJOR.MINOR")
    release = f"{match.group(1)}.{match.group(2)}"
    return f"{_OFFICIAL_RELEASE_ROOT}/enterprise-attack-{release}.json"


def _validate_bundle(data: object) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("objects"), list):
        raise ValueError("MITRE response is not a STIX bundle")
    if len(data["objects"]) < _MIN_OBJECTS:
        raise ValueError("MITRE bundle is unexpectedly small")
    return data


def _write_atomic(snapshot: Path, data: dict) -> None:
    tmp = snapshot.with_suffix(snapshot.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False))
    os.replace(tmp, snapshot)


def _write_bytes_atomic(snapshot: Path, data: bytes | bytearray) -> None:
    tmp = snapshot.with_suffix(snapshot.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, snapshot)


def promote_synced_cache(status: dict) -> None:
    """Publish validated candidate files after DB/RAG activation succeeds."""
    if not status.get("candidate"):
        return
    os.replace(Path(status["path"]), Path(status["cache_path"]))
    os.replace(Path(status["candidate_metadata_path"]), Path(status["metadata_path"]))
    status["path"] = status["cache_path"]
    status["candidate"] = False


def discard_synced_candidate(status: dict) -> None:
    if not status.get("candidate"):
        return
    Path(status["path"]).unlink(missing_ok=True)
    Path(status["candidate_metadata_path"]).unlink(missing_ok=True)


def _best_cached_snapshot(preferred: Path) -> Path | None:
    if preferred.exists():
        return preferred
    candidates = sorted(
        MITRE_DIR.glob("enterprise-attack-v*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _cached_status(snapshot: Path, note: str | None = None) -> dict:
    age_h = (time.time() - snapshot.stat().st_mtime) / 3600
    version = snapshot.stem.removeprefix("enterprise-attack-")
    result = {
        "status": "cached", "version": version,
        "age_hours": round(age_h, 1), "path": str(snapshot),
    }
    if note:
        result["note"] = note
    return result


def _download_github(url: str) -> tuple[dict, str, bytes]:
    import requests

    with requests.get(url, timeout=(5, 60), stream=True) as response:
        response.raise_for_status()
        raw = bytearray()
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            raw.extend(chunk)
            if len(raw) > _MAX_DOWNLOAD_BYTES:
                raise ValueError("MITRE download exceeds safety limit")
    immutable_raw = bytes(raw)
    return (
        _validate_bundle(json.loads(immutable_raw)),
        hashlib.sha256(immutable_raw).hexdigest(),
        immutable_raw,
    )


def sync_attack(force: bool = False) -> dict:
    """Refresh pinned official ATT&CK data, retaining the last known good file."""
    snapshot = MITRE_DIR / f"enterprise-attack-{ATTACK_VERSION}.json"
    metadata_path = snapshot.with_suffix(".metadata.json")
    candidate_snapshot = snapshot.with_suffix(".candidate.json")
    candidate_metadata = snapshot.with_suffix(".candidate.metadata.json")
    cached = _best_cached_snapshot(snapshot)
    if cached and cached == snapshot and not force:
        age_h = (time.time() - cached.stat().st_mtime) / 3600
        if age_h <= MITRE_SYNC_MAX_AGE_HOURS and metadata_path.exists():
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                _validate_bundle(json.loads(cached.read_text(encoding="utf-8")))
                if metadata.get("release") == ATTACK_VERSION:
                    return {
                        **_cached_status(cached),
                        "provenance": metadata,
                    }
            except (OSError, ValueError, json.JSONDecodeError):
                pass

    source_url = official_release_url(ATTACK_VERSION)
    try:
        data, digest, raw = _download_github(source_url)
        retrieved_at = time.time()
        provenance = {
            "source_url": source_url,
            "source_kind": "official_github_release",
            "release": ATTACK_VERSION,
            "retrieved_at": retrieved_at,
            "sha256": digest,
            "verification_status": "official_release_verified",
        }
        _write_bytes_atomic(candidate_snapshot, raw)
        _write_atomic(candidate_metadata, provenance)
        return {
            "status": "synced", "version": ATTACK_VERSION,
            "count": len(data["objects"]), "path": str(candidate_snapshot),
            "source": "official_github_release", "provenance": provenance,
            "candidate": True,
            "cache_path": str(snapshot),
            "metadata_path": str(metadata_path),
            "candidate_metadata_path": str(candidate_metadata),
        }
    except Exception as exc:
        log.warning("Official ATT&CK release sync failed: %s", exc)

    cached = _best_cached_snapshot(snapshot)
    if cached:
        result = _cached_status(cached, "sync failed; using newest cached snapshot")
        if metadata_path.exists():
            try:
                result["provenance"] = json.loads(
                    metadata_path.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError):
                pass
        return result
    return {"status": "failed", "error": "No valid MITRE data is available"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    status = sync_attack(force=args.force)
    if status.get("status") not in {"synced", "cached"}:
        print(json.dumps(status, indent=2))
        return 1
    provenance = status.get("provenance")
    if not isinstance(provenance, dict):
        status["activation_status"] = "degraded_unverified_cache"
        print(json.dumps(status, indent=2))
        return 1
    from .lifecycle import activate_with_rag

    try:
        activation, _rag = activate_with_rag(
            status["path"], provenance=provenance
        )
        promote_synced_cache(status)
    except Exception:
        discard_synced_candidate(status)
        raise
    print(json.dumps({**status, "activation": activation}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
