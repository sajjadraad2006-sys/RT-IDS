"""MITRE ATT&CK browse + sync endpoints."""
from __future__ import annotations
import json
from fastapi import APIRouter
from ..mitre import attack_db, taxii_sync
from ..llm.rag import MitreRAG

router = APIRouter(prefix="/api/mitre", tags=["mitre"])
_rag = MitreRAG()

TACTICS = ["reconnaissance", "resource-development", "initial-access",
           "execution", "persistence", "privilege-escalation",
           "defense-evasion", "credential-access", "discovery",
           "lateral-movement", "collection", "command-and-control",
           "exfiltration", "impact"]


@router.get("/tactics")
def tactics() -> list[str]:
    return TACTICS


@router.get("/techniques")
def techniques(tactic: str | None = None, q: str | None = None,
               limit: int = 400) -> list[dict]:
    detected = attack_db.get_detected_techniques()
    rows = attack_db.list_techniques(tactic=tactic, q=q)[:limit]
    for r in rows:
        r["tactics"] = json.loads(r.get("tactics") or "[]")
        r["detected"] = r["id"] in detected
    return rows


@router.get("/techniques/{tid}")
def technique_detail(tid: str) -> dict:
    r = attack_db.get_technique(tid)
    if not r:
        return {"error": "not found"}
    r["tactics"] = json.loads(r.get("tactics") or "[]")
    r["detected"] = tid in attack_db.get_detected_techniques()
    return r


@router.post("/sync")
def sync(force: bool = False) -> dict:
    status = taxii_sync.sync_attack(force=force)
    # index on BOTH fresh syncs and cached snapshots — index_snapshot uses
    # INSERT OR REPLACE, so re-indexing a cached snapshot is safe. Without
    # this, a pre-existing snapshot leaves the SQLite index empty forever.
    if status.get("status") in ("synced", "cached"):
        status["indexed"] = attack_db.index_snapshot()
        try:
            # feed the same techniques into the RAG vector store so the
            # chat answers with live ATT&CK context right after a sync
            status["rag_indexed"] = _rag.index(attack_db.list_techniques())
        except Exception as exc:
            status["rag_indexed"] = f"failed: {exc}"
    return status


@router.get("/stats")
def mitre_stats() -> dict:
    return attack_db.get_stats()
