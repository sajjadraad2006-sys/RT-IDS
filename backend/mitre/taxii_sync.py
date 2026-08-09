"""TAXII 2.1 client — auto-sync MITRE ATT&CK Enterprise from the official server.
Stores STIX objects locally so everything works offline afterwards.

Fallback chain:
1. TAXII 2.1 official server (attack-taxii.mitre.org)
2. GitHub raw STIX JSON (mitre/cti repository)
3. Cached local snapshot (if previously synced)

Thesis fix #8: "MITRE ATT&CK must auto-update via TAXII 2.1 — not a static copy."
"""
from __future__ import annotations
import json
import time
import logging
from pathlib import Path
from ..config import TAXII_ROOT, MITRE_DIR, ATTACK_VERSION, GITHUB_ATTACK_URL

log = logging.getLogger("cyberguard.taxii")


def sync_attack(force: bool = False) -> dict:
    """Pull the Enterprise ATT&CK collection into data/mitre/.

    Returns a status dict for the settings page. Never raises — sync failure
    must not break the app (local-first rule).

    Args:
        force: If True, re-sync even if a cached snapshot exists.
    """
    snapshot = MITRE_DIR / f"enterprise-attack-{ATTACK_VERSION}.json"

    # Check cache first
    if snapshot.exists() and not force:
        age_h = (time.time() - snapshot.stat().st_mtime) / 3600
        return {"status": "cached", "version": ATTACK_VERSION,
                "age_hours": round(age_h, 1), "path": str(snapshot)}

    # ── Attempt 1: TAXII 2.1 official server ──────────────────────────────
    try:
        log.info("Syncing MITRE ATT&CK via TAXII 2.1 from %s...", TAXII_ROOT)
        from taxii2client.v21 import Server
        server = Server(f"{TAXII_ROOT}/taxii2/")
        api_root = server.api_roots[0]
        collection = next(c for c in api_root.collections
                         if "Enterprise" in c.title)
        objects = list(collection.get_objects().get("objects", []))
        snapshot.write_text(json.dumps({"objects": objects}, ensure_ascii=False))
        log.info("TAXII sync successful: %d objects", len(objects))
        return {"status": "synced", "version": ATTACK_VERSION,
                "count": len(objects), "path": str(snapshot),
                "source": "taxii"}
    except Exception as exc:
        log.warning("TAXII sync failed: %s — trying GitHub fallback...", exc)

    # ── Attempt 2: GitHub raw STIX JSON ──────────────────────────────────
    try:
        import requests
        log.info("Syncing from GitHub: %s", GITHUB_ATTACK_URL)
        resp = requests.get(GITHUB_ATTACK_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        objects = data.get("objects", [])
        snapshot.write_text(json.dumps(data, ensure_ascii=False))
        log.info("GitHub sync successful: %d objects", len(objects))
        return {"status": "synced", "version": ATTACK_VERSION,
                "count": len(objects), "path": str(snapshot),
                "source": "github"}
    except Exception as exc:
        log.warning("GitHub sync also failed: %s", exc)

    # ── Fallback: use existing snapshot ──────────────────────────────────
    if snapshot.exists():
        return {"status": "cached", "version": ATTACK_VERSION,
                "note": "sync failed, using cached snapshot",
                "path": str(snapshot)}

    return {"status": "failed", "error": "No MITRE data available — check internet connection"}
