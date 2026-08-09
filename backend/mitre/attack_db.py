"""Local ATT&CK query layer over the synced STIX snapshot + SQLite index.
Powers the MITRE browser: tactics, techniques, groups, software, and
which techniques were detected in uploaded logs.
"""
from __future__ import annotations
import json
import sqlite3
import logging
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


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    """Create all MITRE-related tables."""
    with get_conn() as c:
        c.executescript(_SCHEMA)
    log.info("MITRE database initialized")


def index_snapshot(path: str | Path | None = None) -> int:
    """Parse the STIX snapshot into SQLite for fast browsing.

    Returns:
        Number of techniques indexed.
    """
    path = path or (MITRE_DIR / f"enterprise-attack-{ATTACK_VERSION}.json")
    if not Path(path).exists():
        log.warning("No snapshot found at %s", path)
        return 0

    data = json.loads(Path(path).read_text())
    tech_rows = []
    group_rows = []
    software_rows = []

    for obj in data.get("objects", []):
        obj_type = obj.get("type")

        if obj_type == "attack-pattern" and not obj.get("revoked", False):
            ext = (obj.get("external_references") or [{}])[0]
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

        elif obj_type == "intrusion-set":
            ext = (obj.get("external_references") or [{}])[0]
            gid = ext.get("external_id", obj.get("id", ""))
            aliases = obj.get("aliases", [])
            group_rows.append((
                gid, obj.get("name", ""),
                (obj.get("description", "") or "")[:4000],
                json.dumps(aliases)
            ))

        elif obj_type in ("malware", "tool"):
            ext = (obj.get("external_references") or [{}])[0]
            sid = ext.get("external_id", obj.get("id", ""))
            software_rows.append((
                sid, obj.get("name", ""),
                (obj.get("description", "") or "")[:4000],
                obj_type
            ))

    with get_conn() as c:
        c.executemany(
            "INSERT OR REPLACE INTO techniques VALUES (?,?,?,?,?,?,?,?,?)", tech_rows)
        c.executemany(
            "INSERT OR REPLACE INTO groups VALUES (?,?,?,?)", group_rows)
        c.executemany(
            "INSERT OR REPLACE INTO software VALUES (?,?,?,?)", software_rows)

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


def record_detection(technique_id: str, alert_id: int, source_file: str = "") -> None:
    """Record that a technique was detected in uploaded logs."""
    import time
    with get_conn() as c:
        c.execute("INSERT INTO detected VALUES (?,?,?,?)",
                  (technique_id, alert_id, time.time(), source_file))


def get_detected_techniques() -> set[str]:
    """Return set of technique IDs that have been detected."""
    with get_conn() as c:
        rows = c.execute("SELECT DISTINCT technique_id FROM detected").fetchall()
        return {r[0] for r in rows}


def get_stats() -> dict:
    """Return database statistics."""
    with get_conn() as c:
        tech_count = c.execute("SELECT COUNT(*) FROM techniques").fetchone()[0]
        group_count = c.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
        detected_count = c.execute("SELECT COUNT(DISTINCT technique_id) FROM detected").fetchone()[0]
        return {
            "techniques": tech_count,
            "groups": group_count,
            "detected": detected_count,
        }
