from __future__ import annotations

import logging

from openai import AsyncOpenAI

from .config import settings

logger = logging.getLogger(__name__)

_client: AsyncOpenAI | None = None


def get_client() -> AsyncOpenAI:
    global _client
    if _client is None:
        _client = AsyncOpenAI(
            base_url=settings.llm_base_url,
            api_key="not-needed",
            timeout=settings.llm_timeout_seconds,
        )
    return _client


async def chat_json(system: str, user: str) -> str:
    client = get_client()
    response = await client.chat.completions.create(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.0,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content or "{}"


async def chat_text(system: str, user: str) -> str:
    client = get_client()
    response = await client.chat.completions.create(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
    )
    return response.choices[0].message.content or ""
