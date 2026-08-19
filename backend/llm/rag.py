"""Deterministic local retrieval over the synced MITRE ATT&CK database.

This intentionally avoids model-loading vector databases. A small TF-IDF
index is rebuilt from the trusted local SQLite ATT&CK index when needed.
"""
from __future__ import annotations

import logging
import threading

log = logging.getLogger("cyberguard.rag")


class MitreRAG:
    """In-process TF-IDF retrieval over MITRE technique text."""

    _lock = threading.Lock()
    _ids: list[str] = []
    _documents: list[str] = []
    _vectorizer = None
    _matrix = None

    def _ensure(self) -> bool:
        if self.__class__._matrix is not None:
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
        with self.__class__._lock:
            self.__class__._ids = ids
            self.__class__._documents = documents
            self.__class__._vectorizer = vectorizer
            self.__class__._matrix = matrix
        log.info("Indexed %d MITRE techniques into local TF-IDF RAG", len(ids))
        return len(ids)

    def query(self, text: str, k: int = 3) -> list[dict]:
        """Return the top lexical matches without network or model execution."""
        if not text or not self._ensure():
            return []
        from sklearn.metrics.pairwise import linear_kernel

        k = max(1, min(int(k), 20, len(self.__class__._ids)))
        query = self.__class__._vectorizer.transform([text[:8000]])
        scores = linear_kernel(query, self.__class__._matrix).ravel()
        order = scores.argsort()[::-1][:k]
        return [
            {
                "id": self.__class__._ids[index],
                "document": self.__class__._documents[index],
                "distance": float(1.0 - scores[index]),
            }
            for index in order
        ]

    def count(self) -> int:
        self._ensure()
        return len(self.__class__._ids)
