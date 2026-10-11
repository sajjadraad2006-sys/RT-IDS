"""Local ATT&CK query layer over the synced STIX snapshot + SQLite index.
Powers the MITRE browser: tactics, techniques, groups, software, and
which techniques were detected in uploaded logs.
"""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import json
import sqlite3
import logging
import re
import time
from pathlib import Path
from ..config import ATTACK_VERSION, BUNDLED_MITRE_DIR, DB_PATH

log = logging.getLogger("cyberguard.attack_db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS techniques (
  id TEXT PRIMARY KEY,          -- e.g. T1046
  stix_id TEXT,
  name TEXT,
  description TEXT,
  tactics TEXT,                 -- JSON array of tactic shortnames
  url TEXT,
  platforms TEXT DEFAULT '[]',  -- JSON array
  is_subtechnique INTEGER DEFAULT 0,
  parent_id TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS inactive_techniques (
  id TEXT PRIMARY KEY,          -- e.g. T1086 (revoked or deprecated)
  status TEXT,                 -- 'revoked' or 'deprecated'
  name TEXT,
  description TEXT
);
CREATE TABLE IF NOT EXISTS sync_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version TEXT,
  object_count INTEGER,
  synced_at REAL,
  source TEXT DEFAULT '',
  sha256 TEXT DEFAULT '',
  last_error TEXT DEFAULT '',
  source_url TEXT DEFAULT '',
  source_kind TEXT DEFAULT 'local_snapshot',
  retrieved_at REAL,
  indexed_at REAL,
  verification_status TEXT DEFAULT 'unverified',
  successful INTEGER DEFAULT 1,
  active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS detected (
  technique_id TEXT,
  alert_id INTEGER,
  detected_at REAL,
  source_file TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  name TEXT,
  description TEXT,
  aliases TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS software (
  id TEXT PRIMARY KEY,
  name TEXT,
  description TEXT,
  type TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_techniques_tactics ON techniques(tactics);
CREATE INDEX IF NOT EXISTS idx_detected_technique ON detected(technique_id);
"""

_ATTACK_ID_PATTERNS = {
    "attack-pattern": re.compile(r"^T\d{4}(?:\.\d{3})?$"),
    "intrusion-set": re.compile(r"^G\d{4}$"),
    "software": re.compile(r"^S\d{4}$"),
}


def bundled_snapshot_path() -> Path:
    """Return the versioned ATT&CK snapshot shipped with the source tree."""
    return BUNDLED_MITRE_DIR / f"enterprise-attack-{ATTACK_VERSION}.json"


def _load_snapshot(path: str | Path | None = None) -> tuple[Path, dict]:
    snapshot = Path(path) if path is not None else bundled_snapshot_path()
    if not snapshot.exists():
        raise FileNotFoundError(f"ATT&CK snapshot is missing: {snapshot}")
    if not snapshot.is_file() or snapshot.is_symlink():
        raise ValueError("ATT&CK snapshot must be a regular non-symlink file")
    try:
        data = json.loads(snapshot.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"ATT&CK snapshot is malformed: {snapshot}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("objects"), list):
        raise ValueError("ATT&CK snapshot is not a STIX bundle")
    return snapshot, data


def validate_snapshot(path: str | Path | None = None) -> dict:
    """Validate the bundled snapshot with the same minimum used for syncs."""
    snapshot, data = _load_snapshot(path)
    from .taxii_sync import _validate_bundle

    _validate_bundle(data)
    return {"path": str(snapshot), "objects": len(data["objects"])}


@contextmanager
def get_conn(db_path: str | Path | None = None):
    target = Path(db_path) if db_path is not None else DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _migrate_sync_log(c: sqlite3.Connection) -> None:
    try:
        cols = {row["name"] for row in c.execute("PRAGMA table_info(sync_log)").fetchall()}
        if "sha256" not in cols:
            c.execute("ALTER TABLE sync_log ADD COLUMN sha256 TEXT DEFAULT ''")
        if "last_error" not in cols:
            c.execute("ALTER TABLE sync_log ADD COLUMN last_error TEXT DEFAULT ''")
        additions = {
            "source_url": "TEXT DEFAULT ''",
            "source_kind": "TEXT DEFAULT 'local_snapshot'",
            "retrieved_at": "REAL",
            "indexed_at": "REAL",
            "verification_status": "TEXT DEFAULT 'unverified'",
            "successful": "INTEGER DEFAULT 1",
            "active": "INTEGER DEFAULT 1",
        }
        for name, declaration in additions.items():
            if name not in cols:
                c.execute(f"ALTER TABLE sync_log ADD COLUMN {name} {declaration}")
    except Exception as exc:
        log.debug("Migration of sync_log skipped/failed: %s", exc)


def init(db_path: str | Path | None = None) -> None:
    """Create all MITRE-related tables and apply forward-only migrations."""
    with get_conn(db_path) as c:
        c.execute("PRAGMA journal_mode=WAL;")
        c.executescript(_SCHEMA)
        _migrate_sync_log(c)
    log.info("MITRE database initialized")


def _attack_reference(obj: dict, kind: str) -> dict | None:
    """Select MITRE's ATT&CK reference instead of assuming list order."""
    pattern = _ATTACK_ID_PATTERNS[kind]
    references = [
        ref for ref in obj.get("external_references", [])
        if isinstance(ref, dict)
    ]
    for ref in references:
        external_id = str(ref.get("external_id", ""))
        if ref.get("source_name") == "mitre-attack" and pattern.fullmatch(external_id):
            return ref
    for ref in references:
        external_id = str(ref.get("external_id", ""))
        if pattern.fullmatch(external_id):
            return ref
    return None


def index_snapshot(
    path: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
    provenance: dict | None = None,
) -> int:
    """Parse the STIX snapshot into SQLite for fast browsing.

    Returns:
        Number of techniques indexed.
    """
    snapshot, data = _load_snapshot(path)
    objects = data["objects"]
    tech_rows = []
    inactive_tech_rows = []
    group_rows = []
    software_rows = []

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        obj_type = obj.get("type")
        inactive = bool(obj.get("revoked", False) or obj.get("x_mitre_deprecated", False))

        if obj_type == "attack-pattern":
            ext = _attack_reference(obj, "attack-pattern")
            if ext is None:
                continue
            tid = ext.get("external_id", "")
            if not inactive:
                tactics = [p["phase_name"] for p in
                           obj.get("kill_chain_phases", []) if "phase_name" in p]
                platforms = obj.get("x_mitre_platforms", [])
                is_sub = 1 if "." in tid else 0
                parent = tid.split(".")[0] if is_sub else ""

                tech_rows.append((
                    tid, obj.get("id"), obj.get("name", ""),
                    (obj.get("description", "") or "")[:4000],
                    json.dumps(tactics), ext.get("url", ""),
                    json.dumps(platforms), is_sub, parent
                ))
            else:
                status = "revoked" if obj.get("revoked") else "deprecated"
                inactive_tech_rows.append((
                    tid, status, obj.get("name", ""),
                    (obj.get("description", "") or "")[:4000]
                ))

        elif obj_type == "intrusion-set" and not inactive:
            ext = _attack_reference(obj, "intrusion-set")
            if ext is None:
                continue
            gid = ext["external_id"]
            aliases = obj.get("aliases", [])
            group_rows.append((
                gid, obj.get("name", ""),
                (obj.get("description", "") or "")[:4000],
                json.dumps(aliases)
            ))

        elif obj_type in ("malware", "tool") and not inactive:
            ext = _attack_reference(obj, "software")
            if ext is None:
                continue
            sid = ext["external_id"]
            software_rows.append((
                sid, obj.get("name", ""),
                (obj.get("description", "") or "")[:4000],
                obj_type
            ))

    provenance = dict(provenance or {})
    version = str(
        provenance.get("release")
        or snapshot.stem.removeprefix("enterprise-attack-")
    )
    snapshot_sha256 = ""
    try:
        h = hashlib.sha256()
        with snapshot.open("rb") as sf:
            while chunk := sf.read(65536):
                h.update(chunk)
        snapshot_sha256 = h.hexdigest()
    except Exception as exc:
        log.warning("Could not calculate SHA-256 for snapshot %s: %s", snapshot, exc)

    with get_conn(db_path) as c:
        # A snapshot is authoritative. Replacing indexes in one transaction
        # separates active from revoked/deprecated techniques cleanly.
        c.execute("DELETE FROM techniques")
        c.execute("DELETE FROM inactive_techniques")
        c.execute("DELETE FROM groups")
        c.execute("DELETE FROM software")
        c.executemany(
            "INSERT OR REPLACE INTO techniques VALUES (?,?,?,?,?,?,?,?,?)", tech_rows)
        c.executemany(
            "INSERT OR REPLACE INTO inactive_techniques VALUES (?,?,?,?)", inactive_tech_rows)
        c.executemany(
            "INSERT OR REPLACE INTO groups VALUES (?,?,?,?)", group_rows)
        c.executemany(
            "INSERT OR REPLACE INTO software VALUES (?,?,?,?)", software_rows)
        indexed_at = time.time()
        c.execute("UPDATE sync_log SET active=0 WHERE active=1")
        c.execute(
            "INSERT INTO sync_log (version, object_count, synced_at, source, sha256, "
            "last_error, source_url, source_kind, retrieved_at, indexed_at, "
            "verification_status, successful, active) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                version, len(objects), indexed_at, str(snapshot)[:2048],
                snapshot_sha256, "", str(provenance.get("source_url", ""))[:2048],
                str(provenance.get("source_kind", "local_snapshot"))[:128],
                provenance.get("retrieved_at"), indexed_at,
                str(provenance.get("verification_status", "unverified"))[:128],
                1, 1,
            ),
        )

    log.info("Indexed %d active techniques, %d inactive, %d groups, %d software from snapshot",
             len(tech_rows), len(inactive_tech_rows), len(group_rows), len(software_rows))
    return len(tech_rows)


def _record_failed_activation(
    *, db_path: str | Path | None, provenance: dict, error: Exception
) -> None:
    """Record a failed attempt without changing the active snapshot."""
    init(db_path)
    with get_conn(db_path) as c:
        c.execute(
            "INSERT INTO sync_log (version, object_count, synced_at, source, sha256, "
            "last_error, source_url, source_kind, retrieved_at, indexed_at, "
            "verification_status, successful, active) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(provenance.get("release", ""))[:128], 0, time.time(), "", "",
                str(error)[:2048], str(provenance.get("source_url", ""))[:2048],
                str(provenance.get("source_kind", "unknown"))[:128],
                provenance.get("retrieved_at"), None,
                str(provenance.get("verification_status", "failed_validation"))[:128],
                0, 0,
            ),
        )


def activate_snapshot(
    path: str | Path,
    *,
    provenance: dict,
    db_path: str | Path | None = None,
    minimum_objects: int = 1000,
) -> dict:
    """Validate and atomically activate an ATT&CK snapshot.

    Failed validation is audit-recorded while the previous active index remains
    untouched. ``minimum_objects`` is injectable only to permit compact,
    official-format offline fixtures in deterministic tests.
    """
    init(db_path)
    try:
        snapshot, data = _load_snapshot(path)
        objects = data["objects"]
        if len(objects) < max(1, int(minimum_objects)):
            raise ValueError("ATT&CK bundle is unexpectedly small")

        expected_sha256 = str(provenance.get("sha256", "")).lower()
        if expected_sha256:
            actual_sha256 = hashlib.sha256(snapshot.read_bytes()).hexdigest()
            if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
                raise ValueError("ATT&CK provenance SHA-256 is malformed")
            if actual_sha256 != expected_sha256:
                raise ValueError("ATT&CK snapshot SHA-256 does not match provenance")

        expected_release = str(provenance.get("release", "")).removeprefix("v")
        collection_versions = {
            str(obj.get("x_mitre_version", ""))
            for obj in objects
            if isinstance(obj, dict) and obj.get("type") == "x-mitre-collection"
            and obj.get("x_mitre_version")
        }
        official_verification = (
            provenance.get("verification_status") == "official_release_verified"
        )
        if official_verification and expected_release and not collection_versions:
            raise ValueError("ATT&CK official release metadata is missing")
        if expected_release and collection_versions and expected_release not in collection_versions:
            found = ", ".join(sorted(collection_versions))
            raise ValueError(
                f"ATT&CK release metadata mismatch: expected {expected_release}, found {found}"
            )

        active_technique_count = sum(
            1 for obj in objects
            if isinstance(obj, dict)
            and obj.get("type") == "attack-pattern"
            and not obj.get("revoked", False)
            and not obj.get("x_mitre_deprecated", False)
            and _attack_reference(obj, "attack-pattern") is not None
        )
        minimum_techniques = 500 if int(minimum_objects) >= 1000 else 1
        if active_technique_count < minimum_techniques:
            raise ValueError(
                "ATT&CK snapshot has too few active techniques "
                f"({active_technique_count} < {minimum_techniques})"
            )

        count = index_snapshot(
            snapshot, db_path=db_path, provenance=provenance
        )
        return {
            "activated": True,
            "version": provenance.get("release"),
            "technique_count": count,
            "object_count": len(objects),
        }
    except Exception as exc:
        _record_failed_activation(db_path=db_path, provenance=provenance, error=exc)
        raise


def list_techniques(
    tactic: str | None = None,
    q: str | None = None,
    limit: int = 500,
    *,
    db_path: str | Path | None = None,
) -> list[dict]:
    """Query techniques with optional tactic filter and search."""
    sql, params = "SELECT * FROM techniques WHERE 1=1", []
    if tactic:
        sql += " AND tactics LIKE ?"
        params.append(f'%"{tactic}"%')
    if q:
        sql += " AND (id LIKE ? OR name LIKE ? OR description LIKE ?)"
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    sql += " ORDER BY id LIMIT ?"
    params.append(limit)
    with get_conn(db_path) as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def get_technique(tid: str, *, db_path: str | Path | None = None) -> dict | None:
    """Get a single active technique by ID."""
    with get_conn(db_path) as c:
        row = c.execute("SELECT * FROM techniques WHERE id = ?", (tid,)).fetchone()
        return dict(row) if row else None


def check_technique_status(tid: str, *, db_path: str | Path | None = None) -> tuple[str, dict | None]:
    """Check whether a technique ID is active, revoked, deprecated, or unknown.

    Returns:
        (status_string, technique_dict_or_None)
        where status_string is one of:
        - "active_validated"
        - "active_unverified"
        - "revoked"
        - "deprecated"
        - "unknown_to_snapshot"
        - "snapshot_unavailable"
    """
    try:
        with get_conn(db_path) as c:
            active_sync = c.execute(
                "SELECT verification_status FROM sync_log "
                "WHERE active=1 AND successful=1 ORDER BY id DESC LIMIT 1"
            ).fetchone()
            snapshot_verified = bool(
                active_sync
                and active_sync["verification_status"] == "official_release_verified"
            )
            row = c.execute("SELECT * FROM techniques WHERE id = ?", (tid,)).fetchone()
            if row:
                return (
                    "active_validated" if snapshot_verified else "active_unverified",
                    dict(row),
                )
            inactive_row = c.execute(
                "SELECT * FROM inactive_techniques WHERE id = ?", (tid,)
            ).fetchone()
            if inactive_row:
                status = str(inactive_row["status"])
                if not snapshot_verified:
                    status = f"{status}_unverified"
                return status, dict(inactive_row)
            return "unknown_to_snapshot", None
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
        log.debug("Database error checking technique status for %s: %s", tid, exc)
        return "snapshot_unavailable", None


def get_candidate_mappings(
    technique_id: str | None = None,
    *,
    alert_id: int | None = None,
    limit: int = 500,
) -> list[dict]:
    """Return persisted classifier-label hypotheses with provenance."""
    sql = (
        "SELECT m.technique_id, m.alert_id, m.created_at, "
        "m.classifier_label, m.mapping_version, m.confidence, "
        "m.evidence_kind, m.observed_evidence "
        "FROM alert_technique_mappings AS m "
        "JOIN alerts AS a ON a.id = m.alert_id WHERE 1=1"
    )
    params: list[object] = []
    if technique_id:
        sql += " AND m.technique_id = ?"
        params.append(technique_id)
    if alert_id is not None:
        sql += " AND m.alert_id = ?"
        params.append(int(alert_id))
    sql += " ORDER BY m.created_at DESC, m.id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 5000)))
    try:
        with get_conn() as c:
            return [dict(row) for row in c.execute(sql, params).fetchall()]
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return []
        raise


def get_candidate_mapped_techniques() -> set[str]:
    """Return technique IDs with live heuristic mapping provenance."""
    return {row["technique_id"] for row in get_candidate_mappings(limit=5000)}


def get_detected_techniques() -> set[str]:
    """Deprecated compatibility alias for candidate mappings."""
    return get_candidate_mapped_techniques()


def get_stats(*, db_path: str | Path | None = None) -> dict:
    """Return database statistics and honest dynamic snapshot status."""
    try:
        with get_conn(db_path) as c:
            tech_count = c.execute("SELECT COUNT(*) FROM techniques").fetchone()[0]
            group_count = c.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
            try:
                candidate_count = c.execute(
                    "SELECT COUNT(DISTINCT m.technique_id) "
                    "FROM alert_technique_mappings AS m "
                    "JOIN alerts AS a ON a.id=m.alert_id"
                ).fetchone()[0]
            except sqlite3.OperationalError:
                candidate_count = 0
            latest = c.execute(
                "SELECT * FROM sync_log WHERE active=1 AND successful=1 "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            last_attempt = c.execute(
                "SELECT * FROM sync_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            latest_dict = dict(latest) if latest else None
            attempt_dict = dict(last_attempt) if last_attempt else None
            version = str(latest_dict.get("version") or "").strip() if latest_dict else ""
            has_version = bool(version and version.startswith("v") and tech_count > 0)
            reported_version = version if has_version else None
            synced_at = float(latest_dict["synced_at"]) if latest_dict and latest_dict.get("synced_at") else None
            stale = bool(synced_at and (time.time() - synced_at) > (24 * 3600))

            # Explicit provenance classification (§4 correction)
            snapshot_sha256 = str(latest_dict.get("sha256") or "") if latest_dict else ""
            source_raw = str(latest_dict.get("source") or "") if latest_dict else ""
            snapshot_filename = Path(source_raw).name if source_raw else ""
            source_kind = (
                str(latest_dict.get("source_kind") or "local_snapshot")
                if latest_dict else "local_snapshot"
            )
            verification_status = (
                str(latest_dict.get("verification_status") or "unverified")
                if latest_dict else "unverified"
            )

            if verification_status == "official_release_verified":
                version_status = "official_release_verified"
            elif has_version and snapshot_sha256:
                version_status = "filename_declared_locally_hashed"
            elif has_version:
                version_status = "filename_declared_unhashed"
            else:
                version_status = "unverified"

            # Sanitize latest_sync dict to remove absolute paths
            safe_latest = None
            if latest_dict:
                safe_latest = {
                    "version": latest_dict.get("version"),
                    "object_count": latest_dict.get("object_count"),
                    "synced_at": latest_dict.get("synced_at"),
                    "source_kind": source_kind,
                    "snapshot_filename": snapshot_filename,
                    "sha256": snapshot_sha256,
                    "last_error": latest_dict.get("last_error"),
                    "source_url": latest_dict.get("source_url"),
                    "retrieved_at": latest_dict.get("retrieved_at"),
                    "indexed_at": latest_dict.get("indexed_at"),
                    "verification_status": verification_status,
                }

            return {
                "available": bool(tech_count > 0),
                "techniques": tech_count,
                "technique_count": tech_count,
                "groups": group_count,
                "candidate_mapped": candidate_count,
                "mapping_semantics": "heuristic_classifier_label_hypothesis",
                "latest_sync": safe_latest,
                "version": reported_version,
                "version_status": version_status,
                "active_version": reported_version,
                "source_kind": source_kind,
                "snapshot_filename": snapshot_filename,
                "official_release_verified": verification_status == "official_release_verified",
                "synced_at": synced_at,
                "indexed_at": latest_dict.get("indexed_at") if latest_dict else None,
                "retrieved_at": latest_dict.get("retrieved_at") if latest_dict else None,
                "last_successful_sync": (
                    latest_dict.get("indexed_at") if latest_dict else None
                ),
                "object_count": latest_dict.get("object_count") if latest_dict else 0,
                "snapshot_sha256": snapshot_sha256,
                "stale": stale,
                "last_sync_error": (
                    attempt_dict.get("last_error")
                    if attempt_dict and not attempt_dict.get("successful") else None
                ),
            }
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
        return {
            "available": False,
            "techniques": 0,
            "technique_count": 0,
            "groups": 0,
            "candidate_mapped": 0,
            "mapping_semantics": "heuristic_classifier_label_hypothesis",
            "latest_sync": None,
            "version": None,
            "version_status": "snapshot_unavailable",
            "active_version": None,
            "source_kind": "bundled_local_snapshot",
            "snapshot_filename": "",
            "official_release_verified": False,
            "synced_at": None,
            "indexed_at": None,
            "retrieved_at": None,
            "last_successful_sync": None,
            "object_count": 0,
            "snapshot_sha256": "",
            "stale": True,
            "last_sync_error": str(exc),
        }
