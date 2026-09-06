"""Transactional ATT&CK activation across SQLite and local retrieval."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Callable

from . import attack_db
from ..llm.rag import MitreRAG


def activate_with_rag(
    snapshot_path: str | Path,
    *,
    provenance: dict,
    db_path: str | Path | None = None,
    rag_factory: Callable[[], MitreRAG] = MitreRAG,
    minimum_objects: int = 1000,
) -> tuple[dict, MitreRAG]:
    """Build SQLite and RAG candidates before replacing active state.

    The candidate database and retrieval index are isolated. The operational
    database is changed only after both candidates validate and agree on their
    technique count. Callers publish the returned RAG instance only after this
    function succeeds.
    """
    with tempfile.TemporaryDirectory(prefix="cyberguard-attack-stage-") as directory:
        staged_db = Path(directory) / "attack.sqlite"
        staged = attack_db.activate_snapshot(
            snapshot_path,
            provenance=provenance,
            db_path=staged_db,
            minimum_objects=minimum_objects,
        )
        techniques = attack_db.list_techniques(limit=5000, db_path=staged_db)
        candidate_rag = rag_factory()
        rag_count = candidate_rag.index(techniques)
        if rag_count != staged["technique_count"]:
            raise ValueError(
                "ATT&CK RAG candidate count does not match the validated SQLite index"
            )

    activated = attack_db.activate_snapshot(
        snapshot_path,
        provenance=provenance,
        db_path=db_path,
        minimum_objects=minimum_objects,
    )
    activated["rag_indexed"] = rag_count
    activated["rag_synchronized"] = True
    return activated, candidate_rag
