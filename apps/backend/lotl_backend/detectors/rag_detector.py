from __future__ import annotations

import json
import logging

from ..llm import chat_json
from ..rag.service import query as rag_query
from ..schema import SysmonEvents

logger = logging.getLogger(__name__)

MAX_EVENTS_IN_PROMPT = 40
RAG_QUESTION_TEMPLATE = "Living-off-the-Land techniques relevant to: {summary}"

SYSTEM_PROMPT = (
    "You are a security analyst classifying Sysmon event windows for Living-off-the-Land (LOTL) "
    "attacks on Windows. Answer ONLY from the provided knowledge context and the events. "
    "Respond with a single JSON object with keys: "
    "is_attack (boolean), confidence (number 0-1), technique (string), mitre_ids (array of strings), "
    "rationale (string). If the context does not cover the events, set is_attack=false."
)

USER_TEMPLATE = (
    "KNOWLEDGE CONTEXT:\n{context}\n\n"
    "SYSMON EVENT WINDOW (host={host}, {count} events):\n{events}\n\n"
    "Decide whether this window represents a LOTL attack. Return JSON only."
)


def _summarize_event(event_data: dict[str, str]) -> str:
    image = event_data.get("Image", "")
    parent = event_data.get("ParentImage", "")
    cmdline = event_data.get("CommandLine", "")
    parent_cmd = event_data.get("ParentCommandLine", "")
    return f"parent={parent} ({parent_cmd}) -> image={image} ({cmdline})"


def _events_block(window: SysmonEvents) -> str:
    selected = window.events[:MAX_EVENTS_IN_PROMPT]
    lines = []
    for event in selected:
        lines.append(
            f"[eid={event.event_id} t={event.time_created}] {_summarize_event(event.data)}"
        )
    if len(window.events) > MAX_EVENTS_IN_PROMPT:
        lines.append(f"... ({len(window.events) - MAX_EVENTS_IN_PROMPT} more events truncated)")
    return "\n".join(lines)


def _window_summary(window: SysmonEvents) -> str:
    binaries = set()
    for event in window.events:
        for key in ("Image", "ParentImage", "OriginalFileName"):
            value = event.data.get(key, "").lower()
            if value:
                binaries.add(value.rsplit("\\", 1)[-1])
    return ", ".join(sorted(binaries)[:20])


async def detect_rag(window: SysmonEvents) -> tuple[bool, dict[str, object]]:
    summary = _window_summary(window)
    chunks = await rag_query(RAG_QUESTION_TEMPLATE.format(summary=summary))
    context_block = "\n\n---\n\n".join(
        f"[{i + 1}] (source={c.metadata.get('source', '?')}) {c.text}" for i, c in enumerate(chunks)
    )
    user_prompt = USER_TEMPLATE.format(
        context=context_block or "(no knowledge context available)",
        host=window.host_key,
        count=len(window.events),
        events=_events_block(window),
    )
    try:
        raw = await chat_json(SYSTEM_PROMPT, user_prompt)
        verdict = json.loads(raw)
    except Exception as error:
        logger.warning("LLM verdict failed: %s", error)
        return False, {"error": str(error)}

    is_attack = bool(verdict.get("is_attack", False))
    payload: dict[str, object] = {
        "confidence": float(verdict.get("confidence", 0.0) or 0.0),
        "technique": str(verdict.get("technique", "") or ""),
        "mitre_ids": list(verdict.get("mitre_ids", []) or []),
        "rationale": str(verdict.get("rationale", "") or ""),
        "sources": [c.metadata for c in chunks],
    }
    return is_attack, payload
