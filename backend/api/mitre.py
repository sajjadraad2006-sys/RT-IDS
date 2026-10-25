"""MITRE ATT&CK browse + sync endpoints."""
from __future__ import annotations
import json
from fastapi import APIRouter, Depends, Query, Request
from ..auth import require_role, Role, User
from ..config import DB_PATH
from ..mitre import attack_db, taxii_sync
from ..mitre.d3fend import D3fendStore
from ..mitre.lifecycle import activate_with_rag
from ..llm.mitre_index import publish_mitre_rag
from ..limiter import limiter

router = APIRouter(prefix="/api/mitre", tags=["mitre"])
_d3fend_store = D3fendStore(DB_PATH)

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
    attack_status, _ = attack_db.check_technique_status(tid)
    r["d3fend"] = {
        "candidates": _d3fend_store.candidate_defenses(
            tid, attack_verified=attack_status == "active_validated"
        ),
        "mapping_semantics": "candidate defensive techniques",
        "originating_attack_validation": attack_status,
        "source_health": _d3fend_store.health(),
        "operational_limitation": (
            "Displayed techniques are official relationship candidates; "
            "display does not mean deployment or execution."
        ),
        "executed_action": "none",
    }
    return r


@router.post("/sync")
@limiter.limit("2/minute")
def sync(
    request: Request,
    force: bool = False,
    user: User = Depends(require_role([Role.ADMIN, Role.ANALYST])),
) -> dict:
    status = taxii_sync.sync_attack(force=force)
    if status.get("status") in ("synced", "cached"):
        provenance = status.get("provenance")
        if not isinstance(provenance, dict):
            status["activation_status"] = "degraded_unverified_cache"
            status["error"] = (
                "Cached ATT&CK data has no verified source metadata; "
                "the last-known-good active snapshot was retained"
            )
            return status
        try:
            activated, candidate_rag = activate_with_rag(
                status["path"], provenance=provenance
            )
            publish_mitre_rag(candidate_rag)
            taxii_sync.promote_synced_cache(status)
            status.update(activated)
            status["indexed"] = activated["technique_count"]
            status["activation_status"] = "active"
        except Exception as exc:
            taxii_sync.discard_synced_candidate(status)
            status["activation_status"] = "failed_last_known_good_retained"
            status["error"] = str(exc)
            status["rag_synchronized"] = False
    return status


@router.get("/stats")
def mitre_stats() -> dict:
    return attack_db.get_stats()


@router.get("/status")
def mitre_status() -> dict:
    """Report dynamic active ATT&CK snapshot information honestly."""
    return attack_db.get_stats()


@router.get("/d3fend/status")
def d3fend_status() -> dict:
    """Report the active local D3FEND relationship snapshot."""
    return _d3fend_store.health()
