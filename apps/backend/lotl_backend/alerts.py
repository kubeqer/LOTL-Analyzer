from __future__ import annotations

import json
import logging
from datetime import UTC
from typing import Any

import httpx

from .config import settings
from .llm import chat_json
from .schema import Alert, SysmonEvents

logger = logging.getLogger(__name__)

MAX_EVENTS_IN_REPORT_PROMPT = 60

REPORT_SYSTEM = (
    "You are a senior detection engineer writing an incident report for a Sysmon event window "
    "that the cascade has classified as a Living-off-the-Land attack. Produce a JSON object with "
    "keys: description (string, 2-4 sentences explaining the technique), "
    "mitre_ids (array of MITRE ATT&CK technique IDs, e.g. ['T1059.001']), "
    "technique (short name), "
    "involved_processes (array of {parent, image, command_line}), "
    "recommended_response (string, 1-3 actionable bullet-style sentences)."
)

REPORT_USER_TEMPLATE = (
    "Context from prior detectors:\n{detector_context}\n\n"
    "Sysmon window (host={host}, {count} events):\n{events}\n\n"
    "Write the JSON report."
)


def _summarize_event(event_data: dict[str, str]) -> str:
    image = event_data.get("Image", "")
    parent = event_data.get("ParentImage", "")
    cmdline = event_data.get("CommandLine", "")
    return f"parent={parent} image={image} cmd={cmdline}"


def _events_block(window: SysmonEvents) -> str:
    selected = window.events[:MAX_EVENTS_IN_REPORT_PROMPT]
    lines = [f"[eid={e.event_id} t={e.time_created}] {_summarize_event(e.data)}" for e in selected]
    if len(window.events) > MAX_EVENTS_IN_REPORT_PROMPT:
        lines.append(f"... ({len(window.events) - MAX_EVENTS_IN_REPORT_PROMPT} more truncated)")
    return "\n".join(lines)


def _fallback_processes(window: SysmonEvents) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for event in window.events:
        image = event.data.get("Image", "")
        parent = event.data.get("ParentImage", "")
        key = (parent, image)
        if not image or key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "parent": parent,
                "image": image,
                "command_line": event.data.get("CommandLine", ""),
            }
        )
    return out[:20]


async def generate_alert(
    window: SysmonEvents,
    detected_by: str,
    detector_context: dict[str, Any],
) -> Alert:
    user_prompt = REPORT_USER_TEMPLATE.format(
        detector_context=json.dumps(detector_context, default=str)[:4000],
        host=window.host_key,
        count=len(window.events),
        events=_events_block(window),
    )
    try:
        raw = await chat_json(REPORT_SYSTEM, user_prompt)
        report = json.loads(raw)
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as error:
        logger.warning("alert report generation failed: %s", error)
        report = {}

    return Alert(
        host_key=window.host_key,
        detected_by=detected_by,
        technique=str(report.get("technique", "") or ""),
        mitre_ids=list(report.get("mitre_ids", []) or []),
        description=str(report.get("description", "") or "LOTL attack detected"),
        recommended_response=str(
            report.get("recommended_response", "") or "Isolate host and review process chain."
        ),
        involved_processes=list(
            report.get("involved_processes", []) or _fallback_processes(window)
        ),
        rationale=str(detector_context.get("rationale", "") or ""),
        raw_event_count=len(window.events),
    )


def _to_ecs(alert: Alert) -> dict[str, Any]:
    timestamp = alert.detected_at.astimezone(UTC).isoformat()
    return {
        "@timestamp": timestamp,
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection"],
            "type": ["info"],
            "module": "lotl-analyzer",
            "dataset": "lotl.cascade",
            "reason": alert.description,
        },
        "host": {
            "name": alert.host_key,
            "id": alert.host_key,
        },
        "rule": {
            "name": alert.technique or "LOTL Attack",
            "description": alert.description,
            "ruleset": alert.detected_by,
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "technique": [{"id": mid, "name": alert.technique} for mid in alert.mitre_ids],
            "tactic": [],
        },
        "process": {
            "involved": alert.involved_processes,
        },
        "lotl": {
            "detected_by": alert.detected_by,
            "rationale": alert.rationale,
            "recommended_response": alert.recommended_response,
            "raw_event_count": alert.raw_event_count,
        },
        "message": alert.description,
        "tags": ["lotl", "sysmon", alert.detected_by],
    }


async def send_alert(alert: Alert) -> bool:
    ecs = _to_ecs(alert)
    url = f"{settings.elasticsearch_url.rstrip('/')}/{settings.elasticsearch_index}/_doc"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=ecs)
            response.raise_for_status()
        logger.info("alert shipped host=%s detector=%s", alert.host_key, alert.detected_by)
        return True
    except httpx.HTTPError as error:
        logger.error("ELK shipping failed: %s", error)
        return False
