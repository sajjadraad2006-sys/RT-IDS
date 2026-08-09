"""RAG over the local MITRE ATT&CK snapshot (ChromaDB). Fully offline after
the first TAXII sync + indexing pass.
"""
from __future__ import annotations
import logging
from ..config import DATA_DIR

log = logging.getLogger("cyberguard.rag")


class MitreRAG:
    """Retrieval-Augmented Generation over MITRE ATT&CK knowledge base."""

    def __init__(self) -> None:
        self._collection = None  # lazy chromadb collection

    def _ensure(self):
        """Lazy-load ChromaDB collection."""
        if self._collection is None:
            try:
                import chromadb
                client = chromadb.PersistentClient(path=str(DATA_DIR / "chroma"))
                self._collection = client.get_or_create_collection("attack")
            except Exception as e:
                log.warning("ChromaDB not available: %s — RAG will return empty results", e)
                return None
        return self._collection

    def index(self, techniques: list[dict]) -> int:
        """Index MITRE techniques into ChromaDB for semantic search.

        Args:
            techniques: List of dicts with 'id', 'name', 'description' keys.

        Returns:
            Number of techniques indexed.
        """
        col = self._ensure()
        if col is None or not techniques:
            return 0
        try:
            col.upsert(
                ids=[t["id"] for t in techniques],
                documents=[f"{t['id']} {t['name']}: {t.get('description', '')[:800]}"
                           for t in techniques],
                metadatas=[{"name": t["name"]} for t in techniques],
            )
            log.info("Indexed %d techniques into RAG vector store", len(techniques))
            return len(techniques)
        except Exception as e:
            log.warning("RAG indexing failed: %s", e)
            return 0

    def query(self, text: str, k: int = 3) -> list[dict]:
        """Search for relevant MITRE techniques by semantic similarity.

        Args:
            text: Query text (user question or alert description).
            k: Number of results to return.

        Returns:
            List of dicts with 'id', 'document', 'distance' keys.
        """
        col = self._ensure()
        if col is None:
            return []
        try:
            if col.count() == 0:
                return []
            res = col.query(query_texts=[text], n_results=k)
            out = []
            for i, doc in enumerate(res["documents"][0]):
                out.append({"id": res["ids"][0][i], "document": doc,
                            "distance": res["distances"][0][i]})
            return out
        except Exception as e:
            log.warning("RAG query failed: %s", e)
            return []

    def count(self) -> int:
        """Number of indexed documents."""
        col = self._ensure()
        return col.count() if col else 0
