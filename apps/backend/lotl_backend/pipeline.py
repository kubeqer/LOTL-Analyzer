from __future__ import annotations

import asyncio
import logging
from typing import Any

from .alerts import generate_alert, send_alert
from .detectors.ml_detector import detect_ml
from .detectors.rag_detector import detect_rag
from .detectors.yara_detector import detect_yara
from .schema import SysmonEvents

logger = logging.getLogger(__name__)


async def detect_lotl_attack(sysmon_events: SysmonEvents) -> None:
    if not sysmon_events.events:
        return

    detector_context: dict[str, Any] = {
        "host": sysmon_events.host_key,
        "events": len(sysmon_events.events),
    }

    is_detected_yara, yara_hits = await asyncio.to_thread(detect_yara, sysmon_events)
    detector_context["yara_hits"] = yara_hits
    detected_by = "yara"

    if not is_detected_yara:
        is_detected_ml, ml_score = await asyncio.to_thread(detect_ml, sysmon_events)
        detector_context["ml_score"] = ml_score
        detected_by = "ml"

        if not is_detected_ml:
            is_detected_rag, rag_verdict = await detect_rag(sysmon_events)
            detector_context.update(rag_verdict)
            detected_by = "llm_rag"

            if not is_detected_rag:
                logger.info(
                    "host=%s clean (events=%d, ml_score=%.3f)",
                    sysmon_events.host_key,
                    len(sysmon_events.events),
                    ml_score,
                )
                return

    logger.info(
        "host=%s ATTACK detected by %s (events=%d)",
        sysmon_events.host_key,
        detected_by,
        len(sysmon_events.events),
    )
    alert = await generate_alert(sysmon_events, detected_by, detector_context)
    await send_alert(alert)
