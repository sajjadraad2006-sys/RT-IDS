"""Deterministic, resource-bounded incident correlation."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
 incident_id TEXT PRIMARY KEY,
 correlation_key TEXT NOT NULL,
 first_seen REAL NOT NULL,
 last_seen REAL NOT NULL,
 severity TEXT NOT NULL,
 evidence_count INTEGER NOT NULL DEFAULT 0,
 duplicate_count INTEGER NOT NULL DEFAULT 0,
 triage_state TEXT NOT NULL DEFAULT 'insufficient_evidence',
 analyst_status TEXT NOT NULL DEFAULT 'unreviewed',
 created_sequence INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_correlation
 ON incidents(correlation_key,last_seen);
CREATE TABLE IF NOT EXISTS incident_evidence (
 event_ref TEXT PRIMARY KEY,
 incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
 source_kind TEXT NOT NULL,
 event_timestamp REAL NOT NULL,
 evidence_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_evidence_incident
 ON incident_evidence(incident_id,event_timestamp,event_ref);
CREATE TABLE IF NOT EXISTS incident_triage (
 incident_id TEXT PRIMARY KEY REFERENCES incidents(incident_id) ON DELETE CASCADE,
 triage_json TEXT NOT NULL,
 updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_analyst_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
 actor TEXT NOT NULL,
 verdict TEXT NOT NULL,
 notes TEXT NOT NULL,
 created_at REAL NOT NULL,
 previous_hash TEXT NOT NULL,
 event_hash TEXT NOT NULL UNIQUE,
 executed_action TEXT NOT NULL DEFAULT 'none'
);
CREATE TRIGGER IF NOT EXISTS incident_audit_no_update
 BEFORE UPDATE ON incident_analyst_audit BEGIN
 SELECT RAISE(ABORT, 'incident analyst audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS incident_audit_no_delete
 BEFORE DELETE ON incident_analyst_audit BEGIN
 SELECT RAISE(ABORT, 'incident analyst audit is immutable'); END;
"""
_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalized_identifiers(values: list) -> list[str]:
    normalized = set()
    for value in values:
        if isinstance(value, dict):
            value = value.get("technique_id") or value.get("id") or value.get("cve")
        if value:
            normalized.add(str(value)[:64])
    return sorted(normalized)


class IncidentCapacityError(RuntimeError):
    """The configured incident cap was reached without safe archival room."""


class IncidentStore:
    """Correlate immutable evidence references without storing address tuples."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        window_seconds: int = 300,
        max_evidence_per_incident: int = 500,
        max_incidents: int = 10_000,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.window_seconds = max(1, min(int(window_seconds), 86_400))
        self.max_evidence = max(1, min(int(max_evidence_per_incident), 10_000))
        self.max_incidents = max(1, min(int(max_incidents), 100_000))
        with self._connect() as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @staticmethod
    def _correlation_key(event: dict) -> str:
        sensor = str(event.get("sensor_id") or "unknown")[:64]
        if event.get("community_id"):
            dimensions = ["community", sensor, str(event["community_id"])[:128]]
        elif event.get("flow_id") is not None:
            dimensions = ["flow", sensor, str(event["flow_id"])[:64]]
        elif event.get("signature_id") is not None:
            dimensions = [
                "signature", sensor, str(event["signature_id"])[:32],
                str(event.get("cve") or "")[:32],
                str(event.get("attack_candidate") or "")[:32],
            ]
        else:
            dimensions = ["source", sensor, str(event.get("source_kind") or "unknown")[:32]]
        return hashlib.sha256("\x1f".join(dimensions).encode()).hexdigest()

    @staticmethod
    def _safe_evidence(event: dict) -> dict:
        allowed = {
            "event_ref", "source_kind", "timestamp", "sensor_id", "flow_id",
            "community_id", "signature_id", "cve", "attack_candidate", "severity",
            "schema_version", "adapter_version", "route", "confidence",
        }
        return {key: event[key] for key in sorted(allowed) if key in event}

    def ingest(self, event: dict, *, count_duplicate: bool = True) -> dict:
        event_ref = str(event.get("event_ref") or "")[:128]
        source_kind = str(event.get("source_kind") or "unknown")[:32]
        timestamp = float(event.get("timestamp"))
        if not event_ref:
            raise ValueError("event_ref is required")
        key = self._correlation_key(event)
        severity = str(event.get("severity") or "medium").lower()
        if severity not in _SEVERITY:
            severity = "medium"

        with self._connect() as connection:
            # Serialize the read-then-create section across API worker threads.
            # Deferred SQLite transactions allow several readers to derive the
            # same sequence/ID before the first insert; IMMEDIATE prevents that
            # race while retaining the configured 30-second busy timeout.
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT incident_id FROM incident_evidence WHERE event_ref=?", (event_ref,)
            ).fetchone()
            if existing:
                if count_duplicate:
                    connection.execute(
                        "UPDATE incidents SET duplicate_count=duplicate_count+1 "
                        "WHERE incident_id=?", (existing["incident_id"],),
                    )
                return {"incident_id": existing["incident_id"], "duplicate": True}

            incident = connection.execute(
                "SELECT * FROM incidents WHERE correlation_key=? AND last_seen>=? "
                "AND evidence_count<? ORDER BY last_seen DESC,incident_id LIMIT 1",
                (key, timestamp - self.window_seconds, self.max_evidence),
            ).fetchone()
            if incident is None:
                incident_count = connection.execute(
                    "SELECT COUNT(*) FROM incidents"
                ).fetchone()[0]
                if incident_count >= self.max_incidents:
                    raise IncidentCapacityError(
                        "incident capacity reached; source evidence remains in its "
                        "immutable source table but was not added to correlation"
                    )
                sequence = connection.execute(
                    "SELECT COALESCE(MAX(created_sequence),0)+1 FROM incidents"
                ).fetchone()[0]
                incident_id = "inc-" + hashlib.sha256(
                    f"{key}:{timestamp:.6f}:{sequence}".encode()
                ).hexdigest()[:20]
                connection.execute(
                    "INSERT INTO incidents "
                    "(incident_id,correlation_key,first_seen,last_seen,severity,"
                    "evidence_count,duplicate_count,created_sequence) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (incident_id, key, timestamp, timestamp, severity, 0, 0, sequence),
                )
            else:
                incident_id = incident["incident_id"]
                if _SEVERITY[severity] < _SEVERITY[incident["severity"]]:
                    severity = incident["severity"]

            connection.execute(
                "INSERT INTO incident_evidence VALUES (?,?,?,?,?)",
                (
                    event_ref, incident_id, source_kind, timestamp,
                    json.dumps(self._safe_evidence(event), sort_keys=True, allow_nan=False),
                ),
            )
            connection.execute(
                "UPDATE incidents SET first_seen=MIN(first_seen,?),last_seen=MAX(last_seen,?),"
                "severity=?,evidence_count=evidence_count+1 WHERE incident_id=?",
                (timestamp, timestamp, severity, incident_id),
            )
        return {"incident_id": incident_id, "duplicate": False}

    def list_incidents(self, *, limit: int = 500) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT incident_id,first_seen,last_seen,severity,evidence_count,"
                "duplicate_count,triage_state,analyst_status FROM incidents "
                "ORDER BY last_seen DESC,incident_id LIMIT ?",
                (max(1, min(int(limit), 5000)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def evidence(self, incident_id: str, *, limit: int = 1000) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_ref,source_kind,event_timestamp,evidence_json "
                "FROM incident_evidence WHERE incident_id=? "
                "ORDER BY event_timestamp,event_ref LIMIT ?",
                (incident_id, max(1, min(int(limit), 10_000))),
            ).fetchall()
        return [
            {**json.loads(row["evidence_json"]), "event_ref": row["event_ref"]}
            for row in rows
        ]

    def record_triage(self, incident_id: str, triage: dict) -> None:
        """Persist the complete versioned triage result for an incident."""
        with self._connect() as connection:
            incident = connection.execute(
                "SELECT analyst_status FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
            if not incident:
                raise ValueError("incident does not exist")
            if incident["analyst_status"] == "resolved":
                return
            existing = connection.execute(
                "SELECT triage_json FROM incident_triage WHERE incident_id=?",
                (incident_id,),
            ).fetchone()
            merged = dict(triage)
            if existing:
                prior = json.loads(existing["triage_json"])
                priority = {
                    "auto_closed_benign": 0,
                    "auto_escalated_known_attack": 1,
                    "insufficient_evidence": 2,
                    "review_required_uncertain": 3,
                    "review_required_conflicting_evidence": 4,
                    "review_required_unknown_anomaly": 5,
                }
                if priority.get(prior.get("state"), 2) > priority.get(merged.get("state"), 2):
                    chosen, other = prior, merged
                else:
                    chosen, other = merged, prior
                merged = dict(chosen)
                merged["evidence_references"] = sorted(set(
                    prior.get("evidence_references", [])
                    + triage.get("evidence_references", [])
                ))[:500]
                merged["source_provenance"] = sorted(set(
                    prior.get("source_provenance", [])
                    + triage.get("source_provenance", [])
                ))[:32]
                merged["confidence"] = max(
                    float(prior.get("confidence", 0)),
                    float(triage.get("confidence", 0)),
                )
                merged["timestamp"] = max(
                    float(prior.get("timestamp", 0)),
                    float(triage.get("timestamp", 0)),
                )
                if merged.get("state") == "review_required_unknown_anomaly":
                    merged["attack_candidates"] = []
                    merged["cves"] = []
                else:
                    merged["attack_candidates"] = _normalized_identifiers(
                        prior.get("attack_candidates", [])
                        + triage.get("attack_candidates", [])
                    )[:32]
                    merged["cves"] = _normalized_identifiers(
                        prior.get("cves", []) + triage.get("cves", [])
                    )[:32]
                del other
            serialized = json.dumps(merged, sort_keys=True, allow_nan=False)
            connection.execute(
                "INSERT INTO incident_triage VALUES (?,?,?) "
                "ON CONFLICT(incident_id) DO UPDATE SET "
                "triage_json=excluded.triage_json,updated_at=excluded.updated_at",
                (incident_id, serialized, time.time()),
            )
            connection.execute(
                "UPDATE incidents SET triage_state=? WHERE incident_id=?",
                (str(merged.get("state") or "insufficient_evidence")[:64], incident_id),
            )

    def resolve_by_analyst(
        self, incident_id: str, *, actor: str, verdict: str, notes: str = ""
    ) -> dict:
        """Resolve analytically and append an immutable audit event."""
        allowed = {"malicious", "suspicious", "benign", "needs_human"}
        if verdict not in allowed:
            raise ValueError("unsupported analyst verdict")
        actor = str(actor).strip()[:64]
        if not actor:
            raise ValueError("analyst actor is required")
        notes = str(notes)[:2000]
        created_at = time.time()
        with self._connect() as connection:
            # Resolution is a one-time state transition. Serialize the check,
            # audit append, and status update so concurrent analysts cannot
            # both pass the unresolved check.
            connection.execute("BEGIN IMMEDIATE")
            incident = connection.execute(
                "SELECT analyst_status FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
            if not incident:
                raise ValueError("incident does not exist")
            if incident["analyst_status"] == "resolved":
                raise ValueError("incident is already resolved")
            previous = connection.execute(
                "SELECT event_hash FROM incident_analyst_audit ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["event_hash"] if previous else ""
            event_payload = json.dumps({
                "incident_id": incident_id,
                "actor": actor,
                "verdict": verdict,
                "notes": notes,
                "created_at": created_at,
                "executed_action": "none",
            }, sort_keys=True, allow_nan=False)
            event_hash = hashlib.sha256(
                f"{previous_hash}\n{event_payload}".encode()
            ).hexdigest()
            connection.execute(
                "INSERT INTO incident_analyst_audit "
                "(incident_id,actor,verdict,notes,created_at,previous_hash,event_hash,"
                "executed_action) VALUES (?,?,?,?,?,?,?,?)",
                (
                    incident_id, actor, verdict, notes, created_at,
                    previous_hash, event_hash, "none",
                ),
            )
            connection.execute(
                "UPDATE incidents SET triage_state='resolved_by_analyst',"
                "analyst_status='resolved' WHERE incident_id=?", (incident_id,),
            )
        return {
            "incident_id": incident_id,
            "state": "resolved_by_analyst",
            "analyst_verdict": verdict,
            "executed_action": "none",
        }

    def analyst_audit(self, incident_id: str, *, limit: int = 200) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT actor,verdict,notes,created_at,previous_hash,event_hash,"
                "executed_action FROM incident_analyst_audit WHERE incident_id=? "
                "ORDER BY id DESC LIMIT ?",
                (incident_id, max(1, min(int(limit), 1000))),
            ).fetchall()
        return [dict(row) for row in rows]
