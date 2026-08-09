"""Chat endpoints — analyst chatbot with MITRE RAG context.
Works with either provider (local llama.cpp or user API key). When no LLM
is reachable, returns a clear degradation notice instead of failing.
"""
from __future__ import annotations
import json, re, time
from fastapi import APIRouter
from pydantic import BaseModel
from ..llm.provider import get_provider
from ..llm.prompts import SYSTEM_ANALYST
from ..llm.rag import MitreRAG
from ..db.models import ChatMessage, SessionLocal, Setting, AlertRecord

router = APIRouter(prefix="/api/chat", tags=["chat"])
_rag = MitreRAG()


def _resolve_mitre(ids: list) -> list:
    """Resolve technique IDs to 'ID (Official Name)' using the synced local
    ATT&CK database — so the model quotes real technique names instead of
    inventing plausible-sounding ones (e.g. T1498 is Network Denial of
    Service, not 'Data Destruction'). Falls back to the bare ID if missing."""
    from ..mitre import attack_db
    out = []
    for tid in ids:
        try:
            t = attack_db.get_technique(tid)
            out.append(f"{tid} ({t['name']})" if t and t.get("name") else tid)
        except Exception:
            out.append(tid)
    return out


class ChatRequest(BaseModel):
    session_id: str
    message: str


@router.post("")
async def chat(req: ChatRequest) -> dict:
    settings = _load_llm_settings()
    provider = get_provider(settings)
    context_docs = _rag.query(req.message, k=3)
    context = "\n\n".join(d["document"] for d in context_docs) or \
        "(MITRE index empty — run a TAXII sync from Settings)"
    # Ground truth injection: the model must see the ACTUAL pipeline alerts.
    # Without this block it fabricates plausible-looking threat summaries
    # from RAG text alone (violates the no-invented-telemetry rule).
    with SessionLocal() as s:
        recent = (s.query(AlertRecord).order_by(AlertRecord.created_at.desc())
                  .limit(10).all())
        recent_alerts = [{
            "time": time.strftime("%H:%M:%S", time.localtime(r.created_at)),
            "type": r.type, "severity": r.severity,
            "confidence": r.confidence, "stage": r.stage,
            "mitre": _resolve_mitre(json.loads(r.mitre_techniques)),
            "source_file": r.source_file,
        } for r in recent]
    alerts_block = json.dumps(recent_alerts) if recent_alerts else \
        "[]  (empty — no detections recorded yet)"
    messages = [
        {"role": "system", "content": SYSTEM_ANALYST +
            "\n\nATT&CK context:\n" + context +
            "\n\nACTUAL pipeline alerts (ground truth from the detection "
            "database — the ONLY detections you may reference; if empty, say "
            "nothing has been detected yet):\n" + alerts_block},
        {"role": "user", "content": req.message},
    ]
    try:
        answer = await provider.chat(messages)
        # Foundation-Sec/RedSage are reasoning models: they emit a
        # <think>...</think> chain-of-thought before the final answer.
        # Keep only the final answer — never show raw reasoning in the UI.
        if "</think>" in answer:
            answer = answer.split("</think>")[-1].strip()
        elif "<think>" in answer:
            answer = re.sub(r"<think>.*$", "", answer, flags=re.DOTALL).strip() or \
                "(the model returned only reasoning — please retry)"
        degraded = False
    except Exception as exc:
        answer = (f"LLM provider unavailable ({exc}). The detection pipeline "
                  "and MITRE browser keep working — only explanations are "
                  "degraded. Check Settings > AI Provider.")
        degraded = True
    with SessionLocal() as s:
        s.add(ChatMessage(session_id=req.session_id, role="user",
                          content=req.message))
        s.add(ChatMessage(session_id=req.session_id, role="assistant",
                          content=answer))
        s.commit()
    return {"answer": answer, "degraded": degraded,
            "provider": provider.name, "context_used": bool(context_docs)}


@router.get("/history/{session_id}")
def history(session_id: str) -> list[dict]:
    with SessionLocal() as s:
        rows = (s.query(ChatMessage).filter_by(session_id=session_id)
                .order_by(ChatMessage.created_at).all())
        return [{"role": r.role, "content": r.content} for r in rows]


def _load_llm_settings() -> dict:
    return {
        "llm_provider": Setting.get("llm_provider", "local"),
        "llama_url": Setting.get("llama_url", "http://127.0.0.1:8080"),
        "local_model": Setting.get("local_model", "foundation-sec"),
        "api_base_url": Setting.get("api_base_url", ""),
        "api_model": Setting.get("api_model", ""),
        "api_key": Setting.get("api_key", ""),
    }
