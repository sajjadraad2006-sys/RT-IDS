"""Atomically published process-wide ATT&CK retrieval index."""
from __future__ import annotations

import threading

from .rag import MitreRAG

_lock = threading.Lock()
_active = MitreRAG()


def get_mitre_rag() -> MitreRAG:
    """Return the currently published immutable-by-convention index instance."""
    with _lock:
        return _active


def publish_mitre_rag(candidate: MitreRAG) -> None:
    """Publish a fully built candidate for every advisory consumer."""
    if not isinstance(candidate, MitreRAG) or candidate.count() <= 0:
        raise ValueError("MITRE RAG candidate must be a populated MitreRAG index")
    global _active
    with _lock:
        _active = candidate
