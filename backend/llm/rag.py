"""Deterministic local retrieval over the synced MITRE ATT&CK database.

This intentionally avoids model-loading vector databases. A small TF-IDF
index is rebuilt from the trusted local SQLite ATT&CK index when needed.
"""
from __future__ import annotations

import logging
import os
import threading

log = logging.getLogger("cyberguard.rag")


class MitreRAG:
    """In-process TF-IDF retrieval over MITRE technique text."""

    def __init__(self, min_relevance: float | None = None) -> None:
        if min_relevance is None:
            try:
                min_relevance = float(os.getenv("CG_RAG_MIN_RELEVANCE", "0.12"))
            except ValueError:
                min_relevance = 0.12
        self.min_relevance = min(1.0, max(0.0, float(min_relevance)))
        self._lock = threading.Lock()
        self._ids: list[str] = []
        self._documents: list[str] = []
        self._vectorizer = None
        self._matrix = None

    def clear(self) -> None:
        """Drop the active index so a refreshed empty snapshot cannot go stale."""
        with self._lock:
            self._ids = []
            self._documents = []
            self._vectorizer = None
            self._matrix = None

    def _ensure(self) -> bool:
        if self._matrix is not None:
            return True
        try:
            from ..mitre.attack_db import list_techniques
            return self.index(list_techniques(limit=5000)) > 0
        except Exception as exc:
            log.warning("MITRE retrieval index unavailable: %s", exc)
            return False

    def index(self, techniques: list[dict]) -> int:
        """Build a bounded local retrieval index from validated DB rows."""
        clean = [
            technique for technique in techniques
            if technique.get("id") and technique.get("name")
        ]
        if not clean:
            self.clear()
            return 0

        from sklearn.feature_extraction.text import TfidfVectorizer

        ids = [str(technique["id"]) for technique in clean]
        documents = [
            f"{technique['id']} {technique['name']}: "
            f"{str(technique.get('description', ''))[:4000]}"
            for technique in clean
        ]
        vectorizer = TfidfVectorizer(
            lowercase=True, ngram_range=(1, 2), max_features=50_000,
            strip_accents="unicode",
        )
        matrix = vectorizer.fit_transform(documents)
        with self._lock:
            self._ids = ids
            self._documents = documents
            self._vectorizer = vectorizer
            self._matrix = matrix
        log.info("Indexed %d MITRE techniques into local TF-IDF RAG", len(ids))
        return len(ids)

    def query(self, text: str, k: int = 3) -> list[dict]:
        """Return the top lexical matches without network or model execution."""
        if not text or not self._ensure():
            return []
        from sklearn.metrics.pairwise import linear_kernel

        k = max(1, min(int(k), 20, len(self._ids)))
        query = self._vectorizer.transform([text[:8000]])
        scores = linear_kernel(query, self._matrix).ravel()
        order = [
            int(index) for index in scores.argsort()[::-1]
            if float(scores[index]) >= self.min_relevance
        ][:k]
        return [
            {
                "id": self._ids[index],
                "document": self._documents[index],
                "score": float(scores[index]),
                "distance": float(1.0 - scores[index]),
            }
            for index in order
        ]

    def count(self) -> int:
        self._ensure()
        return len(self._ids)
