"""Deterministic ATT&CK snapshot, SQLite, and local-RAG verification."""
from __future__ import annotations

from pathlib import Path

from . import attack_db
from ..llm.rag import MitreRAG


KNOWN_TECHNIQUE_ID = "T1498"
KNOWN_TECHNIQUE_QUERY = "T1498 Network Denial of Service distributed denial DDoS"


class MitreVerificationError(RuntimeError):
    """A named verification stage failed after zero or more successful stages."""

    def __init__(self, stage: str, message: str, partial: dict) -> None:
        super().__init__(message)
        self.stage = stage
        self.partial = dict(partial)


def verify_snapshot_index(
    db_path: str | Path, *, snapshot_path: str | Path | None = None
) -> dict:
    """Build an isolated index from the bundled snapshot and prove retrieval.

    The caller owns ``db_path``. Existing process or repository databases are
    never consulted, so a zero/stale local index cannot produce a passing gate.
    """
    target = Path(db_path)
    report: dict = {}
    try:
        snapshot = attack_db.validate_snapshot(snapshot_path)
    except Exception as exc:
        raise MitreVerificationError("snapshot_validation", str(exc), report) from exc
    report["snapshot_path"] = snapshot["path"]
    report["snapshot_objects"] = snapshot["objects"]

    try:
        attack_db.init(target)
        indexed = attack_db.index_snapshot(snapshot_path, db_path=target)
    except Exception as exc:
        raise MitreVerificationError("sqlite_indexing", str(exc), report) from exc
    if indexed <= 0:
        raise MitreVerificationError(
            "sqlite_indexing",
            "validated ATT&CK snapshot indexed zero techniques",
            report,
        )
    report["sqlite_indexed"] = indexed

    try:
        stats = attack_db.get_stats(db_path=target)
        technique_count = int(stats.get("techniques", 0))
        technique = attack_db.get_technique(KNOWN_TECHNIQUE_ID, db_path=target)
    except Exception as exc:
        raise MitreVerificationError("technique_count", str(exc), report) from exc
    if technique_count <= 0 or technique_count != indexed:
        raise MitreVerificationError(
            "technique_count",
            "ATT&CK SQLite technique count is empty or inconsistent with indexing",
            report,
        )
    if not technique:
        raise MitreVerificationError(
            "technique_count",
            f"ATT&CK SQLite index cannot retrieve {KNOWN_TECHNIQUE_ID}",
            report,
        )
    report["technique_count"] = technique_count
    report["known_technique"] = KNOWN_TECHNIQUE_ID

    try:
        techniques = attack_db.list_techniques(limit=5000, db_path=target)
        rag = MitreRAG()
        rag.clear()
        rag_count = rag.index(techniques)
        matches = rag.query(KNOWN_TECHNIQUE_QUERY, k=5)
    except Exception as exc:
        raise MitreVerificationError("rag_retrieval", str(exc), report) from exc
    if rag_count != technique_count:
        raise MitreVerificationError(
            "rag_retrieval",
            "ATT&CK RAG index count does not match SQLite technique count",
            report,
        )
    if not any(item.get("id") == KNOWN_TECHNIQUE_ID for item in matches):
        raise MitreVerificationError(
            "rag_retrieval",
            f"ATT&CK RAG cannot retrieve {KNOWN_TECHNIQUE_ID}",
            report,
        )
    report["rag_indexed"] = rag_count
    report["rag_match_ids"] = [str(item["id"]) for item in matches]
    return report
