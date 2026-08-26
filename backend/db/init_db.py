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


def init_application_tables(target_engine=engine) -> None:
    """Create/migrate app tables; injectable engine keeps migrations testable."""
    Base.metadata.create_all(target_engine)
    _migrate_decision_cases(target_engine)
    _migrate_alerts(target_engine)
    with target_engine.begin() as connection:
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
