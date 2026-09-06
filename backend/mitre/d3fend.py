"""Versioned MITRE D3FEND ontology and inferred-relationship index."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path

_MAX_SOURCE_BYTES = 100 * 1024 * 1024
_ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_D3FEND_ID = re.compile(r"^D3-[A-Z0-9]+$")
_MAPPING_VERSION = "d3fend-inferred-v1"
_MAX_SYNC_LOG_ROWS = 100
_STALE_SECONDS = 30 * 24 * 3600

_SCHEMA = """
CREATE TABLE IF NOT EXISTS d3fend_techniques (
  id TEXT PRIMARY KEY,
  iri TEXT NOT NULL,
  name TEXT NOT NULL,
  definition TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS d3fend_relationships (
  attack_id TEXT NOT NULL,
  d3fend_id TEXT NOT NULL,
  relationship_type TEXT NOT NULL,
  source_version TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  ontology_hash TEXT NOT NULL,
  mapping_version TEXT NOT NULL,
  evidence_source TEXT NOT NULL,
  indexed_at REAL NOT NULL,
  PRIMARY KEY (attack_id, d3fend_id, relationship_type)
);
CREATE TABLE IF NOT EXISTS d3fend_sync_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_version TEXT,
  source_url TEXT,
  source_hash TEXT,
  ontology_hash TEXT,
  object_count INTEGER DEFAULT 0,
  relationship_count INTEGER DEFAULT 0,
  attempted_at REAL NOT NULL,
  indexed_at REAL,
  successful INTEGER NOT NULL,
  active INTEGER NOT NULL,
  last_error TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_d3fend_attack
  ON d3fend_relationships(attack_id);
"""


def _load_json(path: str | Path, label: str) -> tuple[Path, dict, str]:
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"D3FEND {label} must be a regular non-symlink file")
    if source.stat().st_size > _MAX_SOURCE_BYTES:
        raise ValueError(f"D3FEND {label} exceeds the safety size limit")
    raw = source.read_bytes()
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"D3FEND {label} is malformed JSON") from exc
    if not isinstance(data, dict):
        raise ValueError(f"D3FEND {label} must be a JSON object")
    return source, data, hashlib.sha256(raw).hexdigest()


def _local_name(value: object) -> str:
    text = str(value or "")
    return text.rsplit("#", 1)[-1].removeprefix("d3f:")


def _binding_value(binding: dict, key: str) -> str:
    item = binding.get(key)
    return str(item.get("value", "")) if isinstance(item, dict) else ""


class D3fendStore:
    """SQLite-backed active D3FEND relationship snapshot."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
            relationship_columns = {
                row["name"] for row in connection.execute(
                    "PRAGMA table_info(d3fend_relationships)"
                ).fetchall()
            }
            if "ontology_hash" not in relationship_columns:
                connection.execute(
                    "ALTER TABLE d3fend_relationships "
                    "ADD COLUMN ontology_hash TEXT NOT NULL DEFAULT ''"
                )
            log_columns = {
                row["name"] for row in connection.execute(
                    "PRAGMA table_info(d3fend_sync_log)"
                ).fetchall()
            }
            if "ontology_hash" not in log_columns:
                connection.execute(
                    "ALTER TABLE d3fend_sync_log ADD COLUMN ontology_hash TEXT"
                )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def refresh(
        self,
        ontology_path: str | Path,
        mappings_path: str | Path,
        *,
        source_version: str,
        source_url: str,
        minimum_techniques: int = 1,
        minimum_relationships: int = 1,
    ) -> dict:
        """Validate and transactionally activate official D3FEND data files."""
        attempted_at = time.time()
        try:
            _, ontology, ontology_hash = _load_json(ontology_path, "ontology")
            _, mappings, mappings_hash = _load_json(mappings_path, "mappings")
            graph = ontology.get("@graph")
            bindings = (mappings.get("results") or {}).get("bindings")
            if not isinstance(graph, list) or not isinstance(bindings, list):
                raise ValueError("D3FEND ontology or mappings has a malformed schema")

            techniques: dict[str, tuple[str, str, str, str]] = {}
            by_local_name: dict[str, str] = {}
            for node in graph:
                if not isinstance(node, dict) or node.get("owl:deprecated") is True:
                    continue
                d3fend_id = str(node.get("d3f:d3fend-id", ""))
                iri = str(node.get("@id", ""))
                name = str(node.get("rdfs:label", ""))
                if not _D3FEND_ID.fullmatch(d3fend_id) or not iri or not name:
                    continue
                techniques[d3fend_id] = (
                    d3fend_id, iri, name, str(node.get("d3f:definition", ""))[:4000]
                )
                by_local_name[_local_name(iri)] = d3fend_id

            relationships: dict[tuple[str, str, str], tuple] = {}
            indexed_at = time.time()
            for binding in bindings:
                if not isinstance(binding, dict):
                    continue
                attack_id = _binding_value(binding, "off_tech_id")
                defensive_local = _local_name(_binding_value(binding, "def_tech"))
                d3fend_id = by_local_name.get(defensive_local, "")
                if not _ATTACK_ID.fullmatch(attack_id) or d3fend_id not in techniques:
                    continue
                offensive_relation = _binding_value(binding, "off_artifact_rel_label")
                defensive_relation = _binding_value(binding, "def_artifact_rel_label")
                relationship_type = (
                    f"{offensive_relation}->{defensive_relation}"
                    if offensive_relation and defensive_relation
                    else "official_inferred_artifact_relationship"
                )
                key = (attack_id, d3fend_id, relationship_type)
                relationships[key] = (
                    attack_id, d3fend_id, relationship_type, source_version,
                    mappings_hash, ontology_hash, _MAPPING_VERSION,
                    "official_d3fend_inferred_relationship", indexed_at,
                )

            if len(techniques) < max(1, int(minimum_techniques)):
                raise ValueError(
                    "D3FEND snapshot has no active defensive techniques"
                    if not techniques else "D3FEND snapshot has too few defensive techniques"
                )
            if len(relationships) < max(1, int(minimum_relationships)):
                raise ValueError(
                    "D3FEND snapshot has no usable ATT&CK relationships"
                    if not relationships else "D3FEND snapshot has too few ATT&CK relationships"
                )

            with self._connect() as connection:
                connection.execute("DELETE FROM d3fend_techniques")
                connection.execute("DELETE FROM d3fend_relationships")
                connection.executemany(
                    "INSERT INTO d3fend_techniques VALUES (?,?,?,?)",
                    techniques.values(),
                )
                connection.executemany(
                    "INSERT INTO d3fend_relationships "
                    "(attack_id,d3fend_id,relationship_type,source_version,source_hash,"
                    "ontology_hash,mapping_version,evidence_source,indexed_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    relationships.values(),
                )
                connection.execute("UPDATE d3fend_sync_log SET active=0 WHERE active=1")
                connection.execute(
                    "INSERT INTO d3fend_sync_log "
                    "(source_version,source_url,source_hash,ontology_hash,object_count,relationship_count,"
                    "attempted_at,indexed_at,successful,active,last_error) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        source_version, source_url[:2048], mappings_hash, ontology_hash,
                        len(techniques), len(relationships), attempted_at,
                        indexed_at, 1, 1, "",
                    ),
                )
                connection.execute(
                    "DELETE FROM d3fend_sync_log WHERE id NOT IN "
                    "(SELECT id FROM d3fend_sync_log ORDER BY id DESC LIMIT ?)",
                    (_MAX_SYNC_LOG_ROWS,),
                )
            return {
                "active_version": source_version,
                "technique_count": len(techniques),
                "relationship_count": len(relationships),
                "source_hash": mappings_hash,
                "ontology_hash": ontology_hash,
                "indexed_at": indexed_at,
            }
        except Exception as exc:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO d3fend_sync_log "
                    "(source_version,source_url,attempted_at,successful,active,last_error) "
                    "VALUES (?,?,?,?,?,?)",
                    (source_version, source_url[:2048], attempted_at, 0, 0, str(exc)[:2048]),
                )
                connection.execute(
                    "DELETE FROM d3fend_sync_log WHERE id NOT IN "
                    "(SELECT id FROM d3fend_sync_log ORDER BY id DESC LIMIT ?)",
                    (_MAX_SYNC_LOG_ROWS,),
                )
            raise

    def candidate_defenses(self, attack_id: str, *, attack_verified: bool) -> list[dict]:
        """Return candidates only when the originating ATT&CK ID is verified."""
        if not attack_verified or not _ATTACK_ID.fullmatch(str(attack_id)):
            return []
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT r.attack_id,r.d3fend_id,t.name,r.relationship_type,"
                "r.source_version,r.source_hash,r.ontology_hash,r.mapping_version,r.evidence_source "
                "FROM d3fend_relationships r JOIN d3fend_techniques t "
                "ON t.id=r.d3fend_id WHERE r.attack_id=? "
                "ORDER BY r.d3fend_id,r.relationship_type",
                (attack_id,),
            ).fetchall()
        return [
            {
                "attack_technique_id": row["attack_id"],
                "d3fend_technique_id": row["d3fend_id"],
                "name": row["name"],
                "relationship_type": row["relationship_type"],
                "source_version": row["source_version"],
                "source_hash": row["source_hash"],
                "ontology_hash": row["ontology_hash"],
                "mapping_version": row["mapping_version"],
                "evidence_source": row["evidence_source"],
                "confidence_semantics": "candidate_defensive_technique",
                "executed_action": False,
            }
            for row in rows
        ]

    def health(self) -> dict:
        with self._connect() as connection:
            active = connection.execute(
                "SELECT * FROM d3fend_sync_log WHERE active=1 AND successful=1 "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            attempted = connection.execute(
                "SELECT * FROM d3fend_sync_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return {
            "available": active is not None,
            "active_version": active["source_version"] if active else None,
            "source_hash": active["source_hash"] if active else None,
            "ontology_hash": active["ontology_hash"] if active else None,
            "technique_count": active["object_count"] if active else 0,
            "relationship_count": active["relationship_count"] if active else 0,
            "indexed_at": active["indexed_at"] if active else None,
            "freshness_status": (
                "unavailable" if not active
                else "stale" if time.time() - active["indexed_at"] > _STALE_SECONDS
                else "fresh"
            ),
            "last_error": (
                attempted["last_error"]
                if attempted is not None and not attempted["successful"] else None
            ),
            "executed_action": False,
        }
