"""Local ATT&CK query layer over the synced STIX snapshot + SQLite index.
Powers the MITRE browser: tactics, techniques, groups, software, and
which techniques were detected in uploaded logs.
"""
from __future__ import annotations
import json
import sqlite3
import logging
import re
import time
from pathlib import Path
from ..config import DB_PATH, MITRE_DIR, ATTACK_VERSION

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
CREATE TABLE IF NOT EXISTS sync_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version TEXT,
  object_count INTEGER,
  synced_at REAL,
  source TEXT DEFAULT ''
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


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init() -> None:
    """Create all MITRE-related tables."""
    with get_conn() as c:
        c.executescript(_SCHEMA)
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


def index_snapshot(path: str | Path | None = None) -> int:
    """Parse the STIX snapshot into SQLite for fast browsing.

    Returns:
        Number of techniques indexed.
    """
    path = path or (MITRE_DIR / f"enterprise-attack-{ATTACK_VERSION}.json")
    if not Path(path).exists():
        log.warning("No snapshot found at %s", path)
        return 0

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = data.get("objects")
    if not isinstance(objects, list):
        raise ValueError("ATT&CK snapshot is not a STIX bundle")
    tech_rows = []
    group_rows = []
    software_rows = []

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        obj_type = obj.get("type")
        inactive = bool(obj.get("revoked", False) or obj.get("x_mitre_deprecated", False))

        if obj_type == "attack-pattern" and not inactive:
            ext = _attack_reference(obj, "attack-pattern")
            if ext is None:
                continue
            tid = ext.get("external_id", "")
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

    snapshot = Path(path)
    version = snapshot.stem.removeprefix("enterprise-attack-")
    with get_conn() as c:
        # A snapshot is authoritative. Replacing all three indexes in one
        # transaction removes techniques that became revoked/deprecated or
        # disappeared instead of leaving stale rows indefinitely.
        c.execute("DELETE FROM techniques")
        c.execute("DELETE FROM groups")
        c.execute("DELETE FROM software")
        c.executemany(
            "INSERT OR REPLACE INTO techniques VALUES (?,?,?,?,?,?,?,?,?)", tech_rows)
        c.executemany(
            "INSERT OR REPLACE INTO groups VALUES (?,?,?,?)", group_rows)
        c.executemany(
            "INSERT OR REPLACE INTO software VALUES (?,?,?,?)", software_rows)
        c.execute(
            "INSERT INTO sync_log (version, object_count, synced_at, source) "
            "VALUES (?,?,?,?)",
            (version, len(objects), time.time(), str(snapshot)[:2048]),
        )

    log.info("Indexed %d techniques, %d groups, %d software from snapshot",
             len(tech_rows), len(group_rows), len(software_rows))
    return len(tech_rows)


def list_techniques(tactic: str | None = None, q: str | None = None,
                    limit: int = 500) -> list[dict]:
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
    with get_conn() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def get_technique(tid: str) -> dict | None:
    """Get a single technique by ID."""
    with get_conn() as c:
        row = c.execute("SELECT * FROM techniques WHERE id = ?", (tid,)).fetchone()
        return dict(row) if row else None


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
        # A process inspecting a pre-migration database should report no
        # candidate mappings, never revive the legacy `detected` semantics.
        if "no such table" in str(exc).lower():
            return []
        raise


def get_candidate_mapped_techniques() -> set[str]:
    """Return technique IDs with live heuristic mapping provenance."""
    return {row["technique_id"] for row in get_candidate_mappings(limit=5000)}


def get_detected_techniques() -> set[str]:
    """Deprecated compatibility alias for candidate mappings.

    The name is retained for callers outside this repository, but returned
    IDs must not be presented as observed attacker behavior.
    """
    return get_candidate_mapped_techniques()


def get_stats() -> dict:
    """Return database statistics."""
    with get_conn() as c:
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
            "SELECT version, object_count, synced_at, source FROM sync_log "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return {
            "techniques": tech_count,
            "groups": group_count,
            "candidate_mapped": candidate_count,
            "mapping_semantics": "heuristic_classifier_label_hypothesis",
            "latest_sync": dict(latest) if latest else None,
        }
