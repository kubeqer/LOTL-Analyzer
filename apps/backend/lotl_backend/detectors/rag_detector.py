from __future__ import annotations

import json
import logging

import httpx

from ..config import settings
from ..llm import chat_json
from ..rag.service import query as rag_query
from ..schema import SysmonEvent, SysmonEvents

logger = logging.getLogger(__name__)

MAX_EVENTS_IN_PROMPT = 40
MAX_FIELD_CHARS = 300
RAG_QUESTION_TEMPLATE = "Living-off-the-Land techniques relevant to: {summary}"

EVENT_KIND = {
    1: "ProcessCreate",
    3: "NetworkConnect",
    7: "ImageLoad",
    8: "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryKey",
    13: "RegistrySetValue",
    14: "RegistryRename",
    22: "DNSQuery",
    23: "FileDelete",
    25: "ProcessTampering",
    26: "FileDelete",
}

EVENT_FIELDS = {
    1: ("ParentImage", "ParentCommandLine", "Image", "CommandLine", "User", "IntegrityLevel"),
    3: ("Image", "DestinationIp", "DestinationPort", "DestinationHostname"),
    7: ("Image", "ImageLoaded", "Signed"),
    8: ("SourceImage", "TargetImage", "StartFunction"),
    10: ("SourceImage", "TargetImage", "GrantedAccess", "CallTrace"),
    11: ("Image", "TargetFilename"),
    12: ("Image", "EventType", "TargetObject"),
    13: ("Image", "TargetObject", "Details"),
    14: ("Image", "TargetObject"),
    22: ("Image", "QueryName", "QueryResults"),
    23: ("Image", "TargetFilename"),
    25: ("Image", "TargetFilename"),
    26: ("Image", "TargetFilename"),
}

DEFAULT_FIELDS = ("Image", "TargetObject", "TargetFilename", "CommandLine")
SUMMARY_KEYS = ("Image", "ParentImage", "OriginalFileName", "SourceImage", "TargetImage")

SYSTEM_PROMPT = (
    "You are a senior Windows threat-detection analyst triaging Sysmon event windows for "
    "Living-off-the-Land (LOTL) attacks. Treat the knowledge context as supporting reference "
    "material and combine it with your own expertise in Windows attack techniques, including "
    "LSASS and credential access, Active Directory reconnaissance, DCSync, AD CS abuse, "
    "shadow-copy deletion, event-log clearing, defense evasion, and persistence. "
    "Judge what the events actually do, not the mere presence of a built-in binary. "
    "Routine activity from signed, common software such as browsers, Office applications, "
    "collaboration and sync clients, updaters, package managers, and developer tooling is benign "
    "unless the events show concrete malicious behavior such as encoded or obfuscated commands, "
    "suspicious process ancestry, credential access, tampering with security tooling, or "
    "destructive actions. Set confidence high only when specific evidence supports the verdict; "
    "when the signal is weak or ambiguous, lower the confidence rather than guessing. "
    "Respond with a single JSON object with keys: is_attack (boolean), confidence (number 0-1), "
    "technique (string), mitre_ids (array of strings), rationale (string)."
)

USER_TEMPLATE = (
    "KNOWLEDGE CONTEXT:\n{context}\n\n"
    "SYSMON EVENT WINDOW (host={host}, {count} events):\n{events}\n\n"
    "Decide whether this window represents a LOTL attack. Return JSON only."
)

VERDICT_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["is_attack", "confidence", "technique", "mitre_ids", "rationale"],
    "properties": {
        "is_attack": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "technique": {"type": "string"},
        "mitre_ids": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
    },
}


def _summarize_event(event: SysmonEvent) -> str:
    fields = EVENT_FIELDS.get(event.event_id, DEFAULT_FIELDS)
    kind = EVENT_KIND.get(event.event_id, f"eid{event.event_id}")
    parts = []
    for key in fields:
        value = event.data.get(key, "")
        if value:
            parts.append(f"{key}={value[:MAX_FIELD_CHARS]}")
    return f"{kind} " + " ".join(parts) if parts else kind


def _events_block(window: SysmonEvents) -> str:
    selected = window.events[:MAX_EVENTS_IN_PROMPT]
    lines = [f"[t={event.time_created}] {_summarize_event(event)}" for event in selected]
    if len(window.events) > MAX_EVENTS_IN_PROMPT:
        lines.append(f"... ({len(window.events) - MAX_EVENTS_IN_PROMPT} more events truncated)")
    return "\n".join(lines)


def _window_summary(window: SysmonEvents) -> str:
    binaries = set()
    for event in window.events:
        for key in SUMMARY_KEYS:
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
        raw = await chat_json(
            SYSTEM_PROMPT, user_prompt, json_schema=VERDICT_SCHEMA, schema_name="verdict"
        )
        verdict = json.loads(raw)
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as error:
        logger.warning("LLM verdict failed: %s", error)
        return False, {"error": str(error)}

    confidence = float(verdict.get("confidence", 0.0) or 0.0)
    is_attack = bool(verdict.get("is_attack", False)) and confidence >= settings.llm_min_confidence
    payload: dict[str, object] = {
        "confidence": confidence,
        "technique": str(verdict.get("technique", "") or ""),
        "mitre_ids": list(verdict.get("mitre_ids", []) or []),
        "rationale": str(verdict.get("rationale", "") or ""),
        "sources": [c.metadata for c in chunks],
    }
    return is_attack, payload
