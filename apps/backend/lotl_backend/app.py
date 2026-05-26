from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI

from .buffer import HostWindowBuffer
from .detectors.ml_detector import get_detector as get_ml_detector
from .detectors.yara_detector import get_detector as get_yara_detector
from .pipeline import detect_lotl_attack
from .rag.ingest import run_ingestion_cycle
from .rag.ingest import status as rag_status
from .rag.service import start_scheduler, stop_scheduler
from .schema import IngestPayload

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("lotl_backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.buffer = HostWindowBuffer(on_window_close=detect_lotl_attack)
    try:
        get_yara_detector()
    except Exception as error:
        logger.error("YARA detector failed to load: %s", error)
    try:
        get_ml_detector()
    except Exception as error:
        logger.error("ML detector failed to load: %s", error)
    await start_scheduler()
    logger.info("backend ready")
    try:
        yield
    finally:
        await stop_scheduler()
        await app.state.buffer.shutdown()


app = FastAPI(title="LOTL-Analyzer Backend", lifespan=lifespan)


def _host_key(payload: IngestPayload) -> str:
    if payload.host_ip:
        return payload.host_ip
    for event in payload.events:
        if event.computer:
            return event.computer
    return "unknown"


@app.post("/ingest", status_code=200)
async def ingest(payload: IngestPayload) -> dict[str, object]:
    host_key = _host_key(payload)
    await app.state.buffer.add(host_key, payload.events)
    return {"accepted": len(payload.events), "host": host_key}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/rag/status")
async def rag_status_endpoint() -> dict[str, object]:
    return rag_status()


@app.post("/rag/refresh", status_code=202)
async def rag_refresh(background_tasks: BackgroundTasks) -> dict[str, str]:
    background_tasks.add_task(run_ingestion_cycle)
    return {"status": "scheduled"}
