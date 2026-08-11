"""SQLAlchemy models. API keys are stored Fernet-encrypted, never plaintext."""
from __future__ import annotations
import os, time
from sqlalchemy import (create_engine, Column, Integer, String, Float,
                        Text, Boolean)
from sqlalchemy.orm import declarative_base, sessionmaker
from ..config import DB_PATH

Base = declarative_base()
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
    """Machine-local key derived from a local secret file (auto-created)."""
    from cryptography.fernet import Fernet
    key_file = DB_PATH.parent / ".secret_key"
    if not key_file.exists():
        key_file.write_bytes(Fernet.generate_key())
        os.chmod(key_file, 0o600)
    return Fernet(key_file.read_bytes())


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
