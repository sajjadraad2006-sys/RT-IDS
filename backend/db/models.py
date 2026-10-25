"""SQLAlchemy models. API keys are stored Fernet-encrypted, never plaintext."""
from __future__ import annotations
import os, stat, time
from sqlalchemy import (create_engine, Column, Integer, String, Float,
                        Text, Boolean, UniqueConstraint, ForeignKey, event)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from ..config import DB_PATH

Base = declarative_base()
# Create the DB with a private mode before SQLite opens it.
DB_PATH.touch(mode=0o600, exist_ok=True)
os.chmod(DB_PATH, 0o600)

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    future=True,
    connect_args={"check_same_thread": False, "timeout": 30}
)

# Enable foreign key enforcement and WAL mode for high-throughput concurrency
@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.close()

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


def _fernet():
    """Open the machine-local key without following attacker-created links."""
    from cryptography.fernet import Fernet

    key_file = DB_PATH.parent / ".secret_key"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(key_file, flags)
    except FileNotFoundError:
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        create_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(key_file, create_flags, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(Fernet.generate_key())
        except FileExistsError:
            pass
        fd = os.open(key_file, flags)

    with os.fdopen(fd, "rb") as handle:
        mode = stat.S_IMODE(os.fstat(handle.fileno()).st_mode)
        if mode & 0o077:
            os.fchmod(handle.fileno(), 0o600)
        key = handle.read()
    return Fernet(key)


class AlertRecord(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    created_at = Column(Float, default=time.time, index=True)
    severity = Column(String(16), index=True)
    type = Column(String(32), index=True)
    confidence = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    stage = Column(String(16))
    mitre_techniques = Column(Text, default="[]")  # JSON array
    latency_ms = Column(Float, default=0.0)
    source_file = Column(String(256), default="")
    flow_json = Column(Text, default="{}")
    explanation = Column(Text, default="")          # LLM-generated, cached
    top_features = Column(Text, default="[]")       # JSON array of [name, z_score]
    route = Column(String(32), default="")
    pipeline_version = Column(String(32), default="legacy-v1")
    evidence_json = Column(Text, default="{}")
    input_schema_json = Column(Text, default="{}")


class AlertTechniqueMapping(Base):
    """Classifier-label hypothesis; never represented as observed behavior."""
    __tablename__ = "alert_technique_mappings"
    __table_args__ = (
        UniqueConstraint(
            "alert_id", "technique_id", "mapping_version",
            name="uq_alert_technique_mapping_version",
        ),
    )

    id = Column(Integer, primary_key=True)
    technique_id = Column(String(32), index=True, nullable=False)
    alert_id = Column(Integer, index=True, nullable=False)
    created_at = Column(Float, default=time.time, nullable=False)
    classifier_label = Column(String(64), nullable=False)
    mapping_version = Column(String(64), nullable=False)
    confidence = Column(Float, default=0.0, nullable=False)
    evidence_kind = Column(String(32), default="heuristic_hypothesis", nullable=False)
    observed_evidence = Column(Boolean, default=False, nullable=False)


@event.listens_for(AlertRecord, "after_insert")
def _persist_candidate_attack_mappings(mapper, connection, target) -> None:
    """Write mapping provenance in the same transaction as its alert.

    Only classifier labels can create a candidate mapping.  Autoencoder/OOD
    alerts intentionally create no ATT&CK row, even if legacy JSON happens to
    contain a technique id.
    """
    del mapper
    # SQLite may reuse an alert row id after legacy/bulk deletions that bypass
    # ORM ``after_delete`` hooks. Clearing the id first is a recoverable
    # consistency repair and prevents stale provenance from attaching to a
    # newly inserted benign/unknown alert.
    connection.execute(
        AlertTechniqueMapping.__table__.delete().where(
            AlertTechniqueMapping.alert_id == int(target.id)
        )
    )
    if str(target.stage or "").lower() != "classifier":
        return
    from ..mitre.mapper import MAPPING_VERSION, map_alert_to_techniques

    techniques = map_alert_to_techniques(str(target.type or ""))
    if not techniques:
        return
    confidence = min(1.0, max(0.0, float(target.confidence or 0.0)))
    rows = [{
        "technique_id": technique_id,
        "alert_id": int(target.id),
        "created_at": float(target.created_at or time.time()),
        "classifier_label": str(target.type or "unknown")[:64],
        "mapping_version": MAPPING_VERSION,
        "confidence": confidence,
        "evidence_kind": "heuristic_hypothesis",
        "observed_evidence": False,
    } for technique_id in techniques]
    connection.execute(AlertTechniqueMapping.__table__.insert(), rows)


@event.listens_for(AlertRecord, "after_delete")
def _delete_candidate_attack_mappings(mapper, connection, target) -> None:
    """Keep provenance recoverably consistent when an alert is deleted."""
    del mapper
    connection.execute(
        AlertTechniqueMapping.__table__.delete().where(
            AlertTechniqueMapping.alert_id == int(target.id)
        )
    )


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String(64), primary_key=True)
    value = Column(Text, default="")
    encrypted = Column(Boolean, default=False)

    @staticmethod
    def get(key: str, default: str = "") -> str:
        with SessionLocal() as s:
            row = s.get(Setting, key)
            if not row:
                return default
            if row.encrypted:
                try:
                    return _fernet().decrypt(row.value.encode()).decode()
                except Exception:
                    return default
            return row.value

    @staticmethod
    def set(key: str, value: str, encrypt: bool = False) -> None:
        stored = _fernet().encrypt(value.encode()).decode() if encrypt else value
        with SessionLocal() as s:
            s.merge(Setting(key=key, value=stored, encrypted=encrypt))
            s.commit()


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id = Column(Integer, primary_key=True)
    session_id = Column(String(64), index=True)
    role = Column(String(16))
    content = Column(Text)
    created_at = Column(Float, default=time.time)


class DecisionCase(Base):
    """Persisted Smart Log plus the latest guarded AI/policy decision."""
    __tablename__ = "decision_cases"
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, unique=True, index=True, nullable=False)
    smart_log_json = Column(Text, default="{}")
    decision_json = Column(Text, default="")
    provider = Column(String(32), default="policy")
    prompt_version = Column(String(32), default="smart-decision-v2")
    policy_version = Column(String(32), default="smart-policy-v2")
    analyst_verdict = Column(String(32), default="")
    analyst_notes = Column(Text, default="")
    reviewed_by = Column(String(64), default="")
    reviewed_at = Column(Float, nullable=True)
    created_at = Column(Float, default=time.time)
    updated_at = Column(Float, default=time.time, onupdate=time.time)


class AuditEvent(Base):
    """Append-only, hash-chained security workflow event."""
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True)
    created_at = Column(Float, default=time.time, index=True, nullable=False)
    actor = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False, index=True)
    entity_type = Column(String(32), nullable=False)
    entity_id = Column(String(64), nullable=False, index=True)
    payload_json = Column(Text, default="{}", nullable=False)
    previous_hash = Column(String(64), default="", nullable=False)
    event_hash = Column(String(64), unique=True, nullable=False)


class ResponseSimulation(Base):
    """Idempotent response plan only; never an actuator execution record."""
    __tablename__ = "response_simulations"
    id = Column(Integer, primary_key=True)
    idempotency_key = Column(String(64), unique=True, index=True, nullable=False)
    alert_id = Column(Integer, index=True, nullable=False)
    asset_ref = Column(String(128), nullable=False)
    requested_action = Column(String(32), nullable=False)
    approvals = Column(Integer, default=0, nullable=False)
    ttl_seconds = Column(Integer, nullable=False)
    response_json = Column(Text, nullable=False)
    created_at = Column(Float, default=time.time, nullable=False)


class SuricataIngestionRecord(Base):
    """Batch ingestion audit log for Suricata EVE imports."""
    __tablename__ = "suricata_ingestions"
    id = Column(Integer, primary_key=True)
    ingestion_id = Column(String(64), unique=True, index=True, nullable=False)
    source_file = Column(String(256), nullable=False)
    sensor_id = Column(String(64), nullable=False)
    status = Column(String(32), default="in_progress", index=True, nullable=False)
    total_parsed = Column(Integer, default=0, nullable=False)
    accepted = Column(Integer, default=0, nullable=False)
    persisted = Column(Integer, default=0, nullable=False)
    rejected_lines = Column(Integer, default=0, nullable=False)
    duplicates_count = Column(Integer, default=0, nullable=False)
    report_json = Column(Text, default="{}", nullable=False)
    created_at = Column(Float, default=time.time, index=True, nullable=False)
    completed_at = Column(Float, nullable=True)


class SecurityEventRecord(Base):
    """Canonical security event storage (cyberguard-security-event-v1)."""
    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint("event_ref", name="uq_security_events_event_ref"),
    )

    id = Column(Integer, primary_key=True)
    event_ref = Column(String(64), index=True, nullable=False)
    ingestion_id = Column(String(64), index=True, nullable=False)
    schema_version = Column(String(32), default="cyberguard-security-event-v1", nullable=False)
    adapter_version = Column(String(32), default="cyberguard-suricata-eve-v1", nullable=False)
    source_kind = Column(String(32), default="suricata_eve", nullable=False)
    source_event_type = Column(String(32), index=True, nullable=False)
    sensor_id = Column(String(64), index=True, nullable=False)
    source_line_number = Column(Integer, nullable=False)
    timestamp = Column(Float, index=True, nullable=False)
    timestamp_iso = Column(String(64), nullable=False)
    flow_id = Column(Integer, nullable=True)
    community_id = Column(String(64), nullable=True)
    proto = Column(String(16), nullable=True)
    app_proto = Column(String(32), nullable=True)
    src_ip = Column(String(64), nullable=True)
    src_port = Column(Integer, nullable=True)
    dest_ip = Column(String(64), nullable=True)
    dest_port = Column(Integer, nullable=True)
    alert_signature = Column(String(256), nullable=True)
    alert_signature_id = Column(Integer, nullable=True)
    alert_category = Column(String(128), nullable=True)
    alert_severity = Column(String(32), nullable=True)
    source_sensor_severity_raw = Column(String(32), nullable=True)
    source_sensor_action = Column(String(32), nullable=True)
    executed_action = Column(String(32), default="none", nullable=False)
    evidence_json = Column(Text, default="{}", nullable=False)
    mitre_techniques_json = Column(Text, default="[]", nullable=False)
    source_file = Column(String(256), default="", nullable=False)
    explanation = Column(Text, default="", nullable=False)
    created_at = Column(Float, default=time.time, index=True, nullable=False)


class SecurityEventTechniqueMapping(Base):
    """Evidence-supported ATT&CK technique mapping linked to a SecurityEventRecord."""
    __tablename__ = "security_event_technique_mappings"
    __table_args__ = (
        UniqueConstraint(
            "security_event_id", "technique_id", "mapping_version",
            name="uq_sec_event_tech_mapping",
        ),
    )

    id = Column(Integer, primary_key=True)
    security_event_id = Column(
        Integer, ForeignKey("security_events.id", ondelete="CASCADE"), index=True, nullable=False
    )
    technique_id = Column(String(32), index=True, nullable=False)
    tactic_id = Column(String(32), nullable=True)
    signature_id = Column(Integer, nullable=True)
    validation_status = Column(String(32), default="unknown_to_snapshot", nullable=False)
    rule_match_observed = Column(Boolean, default=True, nullable=False)
    mapping_evidence_present = Column(Boolean, default=True, nullable=False)
    technique_observed = Column(Boolean, default=False, nullable=False)
    evidence_kind = Column(String(32), default="suricata_rule_metadata", nullable=False)
    mapping_semantics = Column(
        String(64), default="evidence-supported candidate ATT&CK mapping", nullable=False
    )
    mapping_version = Column(String(64), default="suricata-rule-metadata-v1", nullable=False)
    metadata_extraction_confidence = Column(Float, default=1.0, nullable=False)
    technique_occurrence_confidence = Column(Float, nullable=True)
    evidence_ref = Column(String(128), default="", nullable=False)
    snapshot_version = Column(String(64), nullable=True)
    snapshot_source = Column(String(256), nullable=True)
    snapshot_indexed_time = Column(Float, nullable=True)
    created_at = Column(Float, default=time.time, nullable=False)


class ActionReceiptRecord(Base):
    """Persistent storage for mitigation actions and cryptographic rollback tokens."""
    __tablename__ = "action_receipts"

    id = Column(Integer, primary_key=True)
    token = Column(String(128), unique=True, index=True, nullable=False)
    underlying_token = Column(String(128), index=True, nullable=True)
    actuator_type = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    target = Column(String(256), nullable=False)
    params_json = Column(Text, default="{}", nullable=False)
    receipt_json = Column(Text, default="{}", nullable=False)
    status = Column(String(32), default="active", nullable=False)  # "active" | "rolled_back"
    is_simulated = Column(Boolean, default=True, nullable=False)
    ttl_seconds = Column(Integer, nullable=True)
    expires_at = Column(Float, nullable=True, index=True)
    executed_command = Column(Text, default="", nullable=False)
    rollback_command = Column(Text, default="", nullable=False)
    created_at = Column(Float, default=time.time, nullable=False)
    rolled_back_at = Column(Float, nullable=True)

Base.metadata.create_all(bind=engine)


def migrate_db():
    """Ensure existing SQLite tables have all required columns without manual migrations."""
    with engine.connect() as conn:
        # 1. Migrate action_receipts table
        try:
            res = conn.exec_driver_sql("PRAGMA table_info(action_receipts)").fetchall()
            existing_cols = {row[1] for row in res}
            if existing_cols:
                needed_cols = [
                    ("is_simulated", "BOOLEAN DEFAULT 1 NOT NULL"),
                    ("ttl_seconds", "INTEGER"),
                    ("expires_at", "REAL"),
                    ("executed_command", "TEXT DEFAULT '' NOT NULL"),
                    ("rollback_command", "TEXT DEFAULT '' NOT NULL"),
                ]
                for col_name, col_type in needed_cols:
                    if col_name not in existing_cols:
                        conn.exec_driver_sql(f"ALTER TABLE action_receipts ADD COLUMN {col_name} {col_type};")
                conn.exec_driver_sql(
                    "CREATE INDEX IF NOT EXISTS ix_action_receipts_expires_at ON action_receipts (expires_at);"
                )
                conn.commit()
        except Exception as exc:
            import logging
            logging.getLogger("cyberguard.db").warning("action_receipts migration note: %s", exc)

        # 2. Migrate alerts table
        try:
            res = conn.exec_driver_sql("PRAGMA table_info(alerts)").fetchall()
            existing_cols = {row[1] for row in res}
            if existing_cols:
                needed_cols = [
                    ("evidence_json", "TEXT DEFAULT '{}'"),
                    ("input_schema_json", "TEXT DEFAULT '{}'"),
                ]
                for col_name, col_type in needed_cols:
                    if col_name not in existing_cols:
                        conn.exec_driver_sql(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type};")
                conn.commit()
        except Exception:
            pass


migrate_db()

