from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import chromadb
from chromadb.config import Settings as ChromaSettings

from ..config import settings

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Document:
    doc_id: str
    text: str
    metadata: dict[str, str]


@dataclass(slots=True)
class RetrievedChunk:
    doc_id: str
    text: str
    metadata: dict[str, str]
    distance: float


class VectorStore:
    def __init__(self, persist_dir: Path, collection_name: str) -> None:
        persist_dir.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(
            path=str(persist_dir),
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def count(self) -> int:
        return int(self._collection.count())

    def upsert(self, docs: list[Document], embeddings: list[list[float]]) -> None:
        if not docs:
            return
        self._collection.upsert(
            ids=[d.doc_id for d in docs],
            documents=[d.text for d in docs],
            metadatas=[d.metadata for d in docs],
            embeddings=embeddings,
        )

    def query(self, embedding: list[float], top_k: int) -> list[RetrievedChunk]:
        result = self._collection.query(
            query_embeddings=[embedding],
            n_results=top_k,
        )
        ids = (result.get("ids") or [[]])[0]
        docs = (result.get("documents") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        dists = (result.get("distances") or [[]])[0]
        return [
            RetrievedChunk(
                doc_id=doc_id,
                text=text,
                metadata=dict(meta or {}),
                distance=float(distance),
            )
            for doc_id, text, meta, distance in zip(ids, docs, metas, dists, strict=True)
        ]


_store: VectorStore | None = None


def get_store() -> VectorStore:
    global _store
    if _store is None:
        _store = VectorStore(settings.rag_store_dir, settings.rag_collection)
    return _store
