"""MITRE ATT&CK browse + sync endpoints."""
from __future__ import annotations
import json
from fastapi import APIRouter, Query, Request
from ..mitre import attack_db, taxii_sync
from ..llm.rag import MitreRAG
from ..limiter import limiter

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
def techniques(
    tactic: str | None = Query(default=None, max_length=64),
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=400, ge=1, le=500),
) -> list[dict]:
    candidate_mapped = attack_db.get_candidate_mapped_techniques()
    mappings = attack_db.get_candidate_mappings(limit=5000)
    mapping_counts = {}
    for mapping in mappings:
        tid = mapping["technique_id"]
        mapping_counts[tid] = mapping_counts.get(tid, 0) + 1
    rows = attack_db.list_techniques(tactic=tactic, q=q)[:limit]
    for r in rows:
        r["tactics"] = json.loads(r.get("tactics") or "[]")
        r["candidate_mapping"] = r["id"] in candidate_mapped
        r["candidate_mapping_count"] = mapping_counts.get(r["id"], 0)
        r["mapping_semantics"] = "possible technique based on classifier label"
    return rows


@router.get("/techniques/{tid}")
def technique_detail(tid: str) -> dict:
    r = attack_db.get_technique(tid)
    if not r:
        return {"error": "not found"}
    r["tactics"] = json.loads(r.get("tactics") or "[]")
    mappings = attack_db.get_candidate_mappings(tid)
    r["candidate_mapping"] = bool(mappings)
    r["candidate_mappings"] = mappings
    r["mapping_semantics"] = "heuristic hypothesis, not observed evidence"
    return r


@router.post("/sync")
@limiter.limit("2/minute")
def sync(request: Request, force: bool = False) -> dict:
    status = taxii_sync.sync_attack(force=force)
    # index on BOTH fresh syncs and cached snapshots — index_snapshot uses
    # INSERT OR REPLACE, so re-indexing a cached snapshot is safe. Without
    # this, a pre-existing snapshot leaves the SQLite index empty forever.
    if status.get("status") in ("synced", "cached"):
        status["indexed"] = attack_db.index_snapshot(status.get("path"))
        try:
            # feed the same techniques into the RAG vector store so the
            # chat answers with live ATT&CK context right after a sync
            status["rag_indexed"] = _rag.index(attack_db.list_techniques(limit=5000))
            status["rag_synchronized"] = status["rag_indexed"] == status["indexed"]
        except Exception as exc:
            status["rag_indexed"] = f"failed: {exc}"
            status["rag_synchronized"] = False
    return status


@router.get("/stats")
def mitre_stats() -> dict:
    return attack_db.get_stats()
