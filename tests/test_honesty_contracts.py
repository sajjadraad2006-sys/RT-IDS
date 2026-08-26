"""LLM/RAG/session/UI claims remain bounded by available evidence."""
from pathlib import Path
import time

from backend.api.chat import _HISTORY_MESSAGES, _bounded_session_history
from backend.db.init_db import init_all
from backend.db.models import ChatMessage, SessionLocal
from backend.llm.prompts import explain_alert
from backend.llm.rag import MitreRAG


def test_irrelevant_rag_query_returns_no_context():
    rag = MitreRAG(min_relevance=0.20)
    rag.index([{
        "id": "T1498",
        "name": "Network Denial of Service",
        "description": "Flood network resources to affect availability.",
    }])
    assert rag.query("purple telescope banana violin", k=3) == []


def test_chat_history_is_recent_bounded_and_session_isolated():
    init_all()
    own = f"session-own-{time.time_ns()}"
    other = f"session-other-{time.time_ns()}"
    try:
        with SessionLocal() as session:
            for index in range(_HISTORY_MESSAGES + 4):
                session.add(ChatMessage(
                    session_id=own,
                    role="user" if index % 2 == 0 else "assistant",
                    content=f"own-{index}",
                    created_at=float(index),
                ))
            session.add(ChatMessage(
                session_id=other, role="user", content="other-session-secret",
                created_at=999.0,
            ))
            session.commit()
            history = _bounded_session_history(session, own)
        assert len(history) == _HISTORY_MESSAGES
        assert history[0]["content"] == "own-4"
        assert history[-1]["content"] == f"own-{_HISTORY_MESSAGES + 3}"
        assert all("other-session-secret" not in item["content"] for item in history)
    finally:
        with SessionLocal() as session:
            session.query(ChatMessage).filter(
                ChatMessage.session_id.in_([own, other])
            ).delete(synchronize_session=False)
            session.commit()


def test_evaluation_only_explanation_prompt_contains_required_limits():
    operational = {
        "operational_mode": "evaluation_only",
        "artifact_approval_state": "evaluation_only",
        "production_approved": False,
        "supported_classes": ["Benign", "Bot", "DDoS", "PortScan"],
        "pipeline_version": "cyberguard-pipeline-legacy-v1",
        "limitations": [
            "detections are unverified model evidence requiring validation",
            "live packet ingestion is not implemented",
        ],
    }
    messages = explain_alert(
        {"type": "DDoS", "confidence": 0.9},
        "heuristic candidate mapping",
        operational,
    )
    combined = "\n".join(message["content"] for message in messages)
    assert "evaluation_only" in combined
    assert "production_approved" in combined
    assert "supported_classes" in combined
    assert "pipeline_version" in combined
    assert "unverified model evidence" in combined


def test_frontend_contains_no_misleading_unknown_or_payload_claims():
    frontend = Path(__file__).resolve().parents[1] / "frontend"
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(frontend.rglob("*"))
        if path.suffix in {".html", ".js", ".css"}
    ).lower()
    for forbidden in (
        "zero-day", "zero day", "failed ssh handshake",
        "authentication ports", "sql/xss payload", "packet payload analysis",
    ):
        assert forbidden not in source
    assert "unknown anomaly" in source
    assert "not live packet" in source or "no live ingestion" in source
    assert 'accept=".csv,.tsv,.json,.ndjson,.jsonl"' in source
    assert 'accept=".log' not in source and 'accept=".txt' not in source
