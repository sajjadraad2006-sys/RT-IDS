"""Initialize application tables and apply small forward-only SQLite migrations."""
from sqlalchemy import inspect

from .models import Base, engine
from ..mitre.attack_db import init as init_mitre


def _migrate_decision_cases(target_engine=engine) -> None:
    """Add review fields to databases created before Smart Log feedback existed."""
    columns = {item["name"] for item in inspect(target_engine).get_columns("decision_cases")}
    additions = {
        "analyst_verdict": "VARCHAR(32) DEFAULT ''",
        "analyst_notes": "TEXT DEFAULT ''",
        "reviewed_by": "VARCHAR(64) DEFAULT ''",
        "reviewed_at": "FLOAT",
        "policy_version": "VARCHAR(32) DEFAULT 'smart-policy-v2'",
    }
    with target_engine.begin() as connection:
        for name, ddl in additions.items():
            if name not in columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE decision_cases ADD COLUMN {name} {ddl}"
                )


def _migrate_alerts(target_engine=engine) -> None:
    """Add Pipeline v2 evidence columns without rewriting existing alerts."""
    columns = {item["name"] for item in inspect(target_engine).get_columns("alerts")}
    additions = {
        "route": "VARCHAR(32) DEFAULT ''",
        "pipeline_version": "VARCHAR(32) DEFAULT 'legacy-v1'",
        "evidence_json": "TEXT DEFAULT '{}'",
        "input_schema_json": "TEXT DEFAULT '{}'",
    }
    with target_engine.begin() as connection:
        for name, ddl in additions.items():
            if name not in columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE alerts ADD COLUMN {name} {ddl}"
                )


def _migrate_security_event_technique_mappings(target_engine=engine) -> None:
    """Drop legacy 'confidence' column from security_event_technique_mappings if present (CG-RE-002)."""
    insp = inspect(target_engine)
    if "security_event_technique_mappings" not in insp.get_table_names():
        return
    columns = {item["name"] for item in insp.get_columns("security_event_technique_mappings")}
    if "confidence" not in columns:
        return

    with target_engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TABLE security_event_technique_mappings_dg_tmp (
                id INTEGER PRIMARY KEY,
                security_event_id INTEGER NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
                technique_id VARCHAR(32) NOT NULL,
                tactic_id VARCHAR(32),
                signature_id INTEGER,
                validation_status VARCHAR(32) NOT NULL DEFAULT 'unknown_to_snapshot',
                rule_match_observed BOOLEAN NOT NULL DEFAULT 1,
                mapping_evidence_present BOOLEAN NOT NULL DEFAULT 1,
                technique_observed BOOLEAN NOT NULL DEFAULT 0,
                evidence_kind VARCHAR(32) NOT NULL DEFAULT 'suricata_rule_metadata',
                mapping_semantics VARCHAR(64) NOT NULL DEFAULT 'evidence-supported candidate ATT&CK mapping',
                mapping_version VARCHAR(64) NOT NULL DEFAULT 'suricata-rule-metadata-v1',
                metadata_extraction_confidence FLOAT NOT NULL DEFAULT 1.0,
                technique_occurrence_confidence FLOAT,
                evidence_ref VARCHAR(128) NOT NULL DEFAULT '',
                snapshot_version VARCHAR(64),
                snapshot_source VARCHAR(256),
                snapshot_indexed_time FLOAT,
                created_at FLOAT NOT NULL,
                CONSTRAINT uq_sec_event_tech_mapping UNIQUE (security_event_id, technique_id, mapping_version)
            );
            """
        )
        connection.exec_driver_sql(
            """
            INSERT INTO security_event_technique_mappings_dg_tmp (
                id, security_event_id, technique_id, tactic_id, signature_id,
                validation_status, rule_match_observed, mapping_evidence_present,
                technique_observed, evidence_kind, mapping_semantics, mapping_version,
                metadata_extraction_confidence, technique_occurrence_confidence,
                evidence_ref, snapshot_version, snapshot_source, snapshot_indexed_time,
                created_at
            )
            SELECT
                id, security_event_id, technique_id, tactic_id, signature_id,
                validation_status, rule_match_observed, mapping_evidence_present,
                technique_observed, evidence_kind, mapping_semantics, mapping_version,
                metadata_extraction_confidence, technique_occurrence_confidence,
                evidence_ref, snapshot_version, snapshot_source, snapshot_indexed_time,
                created_at
            FROM security_event_technique_mappings;
            """
        )
        connection.exec_driver_sql("DROP TABLE security_event_technique_mappings;")
        connection.exec_driver_sql(
            "ALTER TABLE security_event_technique_mappings_dg_tmp RENAME TO security_event_technique_mappings;"
        )
        connection.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_sec_event_tech_mappings_sec_event_id ON security_event_technique_mappings (security_event_id);"
        )
        connection.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_sec_event_tech_mappings_tech_id ON security_event_technique_mappings (technique_id);"
        )


def init_application_tables(target_engine=engine) -> None:
    """Create/migrate app tables; injectable engine keeps migrations testable."""
    Base.metadata.create_all(target_engine)
    _migrate_decision_cases(target_engine)
    _migrate_alerts(target_engine)
    _migrate_security_event_technique_mappings(target_engine)
    with target_engine.begin() as connection:
        # Set WAL mode once at initialization (not renegotiated per-connection)
        connection.exec_driver_sql("PRAGMA journal_mode=WAL;")
        connection.exec_driver_sql(
            "CREATE TRIGGER IF NOT EXISTS audit_events_no_update "
            "BEFORE UPDATE ON audit_events BEGIN "
            "SELECT RAISE(ABORT, 'audit events are immutable'); END"
        )
        connection.exec_driver_sql(
            "CREATE TRIGGER IF NOT EXISTS audit_events_no_delete "
            "BEFORE DELETE ON audit_events BEGIN "
            "SELECT RAISE(ABORT, 'audit events are immutable'); END"
        )


def init_all() -> None:
    init_application_tables(engine)
    init_mitre()


if __name__ == "__main__":
    init_all()
    print("database ready")
