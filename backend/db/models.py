"""SQLAlchemy models. API keys are stored Fernet-encrypted, never plaintext."""
from __future__ import annotations
import os, stat, time
from sqlalchemy import (create_engine, Column, Integer, String, Float,
                        Text, Boolean)
from sqlalchemy.orm import declarative_base, sessionmaker
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

# Enable WAL mode for multi-threaded concurrency
with engine.connect() as conn:
    conn.exec_driver_sql("PRAGMA journal_mode=WAL;")

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
