from __future__ import annotations

import logging
from typing import Any

from openai import AsyncOpenAI

from .config import settings

logger = logging.getLogger(__name__)

JSON_CHAT_TEMPERATURE = 0.0
TEXT_CHAT_TEMPERATURE = 0.2

_client: AsyncOpenAI | None = None


def get_client() -> AsyncOpenAI:
    global _client
    if _client is None:
        _client = AsyncOpenAI(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
            timeout=settings.llm_timeout_seconds,
        )
    return _client


def _reasoning_kwargs(reasoning_effort: str | None) -> dict[str, Any]:
    effort = reasoning_effort or settings.llm_reasoning_effort
    if not effort:
        return {}
    return {"reasoning_effort": effort}


def _response_format(json_schema: dict[str, Any] | None, schema_name: str) -> dict[str, Any]:
    if json_schema is None:
        return {"type": "json_object"}
    return {
        "type": "json_schema",
        "json_schema": {"name": schema_name, "strict": True, "schema": json_schema},
    }


async def chat_json(
    system: str,
    user: str,
    *,
    json_schema: dict[str, Any] | None = None,
    schema_name: str = "response",
    reasoning_effort: str | None = None,
) -> str:
    client = get_client()
    response = await client.chat.completions.create(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=JSON_CHAT_TEMPERATURE,
        response_format=_response_format(json_schema, schema_name),
        **_reasoning_kwargs(reasoning_effort),
    )
    if not response.choices:
        return "{}"
    return response.choices[0].message.content or "{}"


async def chat_text(
    system: str,
    user: str,
    *,
    reasoning_effort: str | None = None,
) -> str:
    client = get_client()
    response = await client.chat.completions.create(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=TEXT_CHAT_TEMPERATURE,
        **_reasoning_kwargs(reasoning_effort),
    )
    if not response.choices:
        return ""
    return response.choices[0].message.content or ""
