from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from ..config import settings
from .embeddings import get_embedder
from .scrapers import fetch_all_advisory_feeds, fetch_lolbas
from .store import Document, get_store

logger = logging.getLogger(__name__)

_state = {"last_run": None, "running": False}
_state_lock = asyncio.Lock()


def _chunk_text(text: str, chunk_size: int, overlap: int) -> list[str]:
    if len(text) <= chunk_size:
        return [text]
    step = max(chunk_size - overlap, 1)
    chunks: list[str] = []
    start = 0
    while start < len(text):
        chunks.append(text[start : start + chunk_size])
        start += step
    return chunks


def _split_document(doc: Document) -> list[Document]:
    pieces = _chunk_text(doc.text, settings.rag_chunk_size, settings.rag_chunk_overlap)
    if len(pieces) == 1:
        return [doc]
    out: list[Document] = []
    for index, piece in enumerate(pieces):
        out.append(
            Document(
                doc_id=f"{doc.doc_id}:c{index}",
                text=piece,
                metadata={**doc.metadata, "chunk": str(index)},
            )
        )
    return out


async def run_ingestion_cycle() -> dict[str, int]:
    async with _state_lock:
        if _state["running"]:
            logger.info("ingestion cycle already running, skipping")
            return {"skipped": 1}
        _state["running"] = True
    try:
        logger.info("ingestion cycle starting")
        lolbas_docs = await fetch_lolbas()
        advisory_docs = await fetch_all_advisory_feeds(settings.advisory_feed_urls)
        raw_docs = lolbas_docs + advisory_docs

        chunks: list[Document] = []
        for doc in raw_docs:
            chunks.extend(_split_document(doc))

        if not chunks:
            logger.warning("no documents fetched this cycle")
            _state["last_run"] = datetime.now(UTC).isoformat()
            return {"chunks": 0, "documents": 0}

        embedder = get_embedder()
        embeddings = await embedder.encode([c.text for c in chunks])
        store = get_store()
        store.upsert(chunks, embeddings)
        _state["last_run"] = datetime.now(UTC).isoformat()
        logger.info("ingestion done: %d documents, %d chunks", len(raw_docs), len(chunks))
        return {"documents": len(raw_docs), "chunks": len(chunks)}
    finally:
        _state["running"] = False


def status() -> dict[str, object]:
    store = get_store()
    return {
        "chunks_in_store": store.count(),
        "last_run": _state["last_run"],
        "running": _state["running"],
        "refresh_hours": settings.rag_refresh_hours,
    }
