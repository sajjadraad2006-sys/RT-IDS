"""Safe, freshness-aware MITRE ATT&CK Enterprise synchronization."""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from ..config import (
    ATTACK_VERSION,
    GITHUB_ATTACK_URL,
    MITRE_DIR,
    MITRE_SYNC_MAX_AGE_HOURS,
    TAXII_ROOT,
)

log = logging.getLogger("cyberguard.taxii")
_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
_MIN_OBJECTS = 1000


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


def _download_github() -> dict:
    import requests

    with requests.get(GITHUB_ATTACK_URL, timeout=(5, 60), stream=True) as response:
        response.raise_for_status()
        raw = bytearray()
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            raw.extend(chunk)
            if len(raw) > _MAX_DOWNLOAD_BYTES:
                raise ValueError("MITRE download exceeds safety limit")
    return _validate_bundle(json.loads(raw))


def sync_attack(force: bool = False) -> dict:
    """Refresh stale ATT&CK data, falling back to the newest valid cache."""
    snapshot = MITRE_DIR / f"enterprise-attack-{ATTACK_VERSION}.json"
    cached = _best_cached_snapshot(snapshot)
    if cached and cached == snapshot and not force:
        age_h = (time.time() - cached.stat().st_mtime) / 3600
        if age_h <= MITRE_SYNC_MAX_AGE_HOURS:
            return _cached_status(cached)

    try:
        log.info("Syncing MITRE ATT&CK via TAXII 2.1 from %s", TAXII_ROOT)
        from taxii2client.v21 import Server

        server = Server(f"{TAXII_ROOT}/taxii2/")
        api_root = server.api_roots[0]
        collection = next(c for c in api_root.collections if "Enterprise" in c.title)
        objects = list(collection.get_objects().get("objects", []))
        data = _validate_bundle({"objects": objects})
        _write_atomic(snapshot, data)
        return {
            "status": "synced", "version": ATTACK_VERSION,
            "count": len(objects), "path": str(snapshot), "source": "taxii",
        }
    except Exception as exc:
        log.warning("TAXII sync failed: %s; trying official GitHub", exc)

    try:
        data = _download_github()
        _write_atomic(snapshot, data)
        return {
            "status": "synced", "version": ATTACK_VERSION,
            "count": len(data["objects"]), "path": str(snapshot),
            "source": "github",
        }
    except Exception as exc:
        log.warning("GitHub sync failed: %s", exc)

    cached = _best_cached_snapshot(snapshot)
    if cached:
        return _cached_status(cached, "sync failed; using newest cached snapshot")
    return {"status": "failed", "error": "No valid MITRE data is available"}
