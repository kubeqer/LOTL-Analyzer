from __future__ import annotations

import asyncio
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from ..config import settings
from .embeddings import get_embedder
from .ingest import run_ingestion_cycle
from .store import RetrievedChunk, get_store

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


async def query(question: str, top_k: int | None = None) -> list[RetrievedChunk]:
    if not question.strip():
        return []
    embedder = get_embedder()
    [vector] = await embedder.encode([question])
    store = get_store()
    return store.query(vector, top_k or settings.rag_top_k)


async def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        return
    store = get_store()
    if store.count() == 0:
        logger.info("RAG store empty; seeding in background")
        asyncio.create_task(run_ingestion_cycle())
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        run_ingestion_cycle,
        trigger=IntervalTrigger(hours=settings.rag_refresh_hours),
        id="rag_refresh",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.start()
    _scheduler = scheduler
    logger.info("RAG scheduler started (every %dh)", settings.rag_refresh_hours)


async def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is None:
        return
    _scheduler.shutdown(wait=False)
    _scheduler = None
