from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable

import feedparser
import httpx
from bs4 import BeautifulSoup

from ..config import settings
from .store import Document

logger = logging.getLogger(__name__)

LOTL_KEYWORDS = (
    "living off the land",
    "lolbas",
    "lolbin",
    "lotl",
    "powershell",
    "wmic",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "mshta",
    "wscript",
    "cscript",
    "schtasks",
    "psexec",
    "dual-use",
    "dual use",
    "trusted binary",
)

REQUEST_TIMEOUT = 30.0


def _sha1(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def _matches_lotl(text: str) -> bool:
    haystack = text.lower()
    return any(keyword in haystack for keyword in LOTL_KEYWORDS)


async def fetch_lolbas() -> list[Document]:
    url = settings.lolbas_url
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.get(url)
            response.raise_for_status()
            entries = response.json()
    except Exception as error:
        logger.warning("LOLBAS fetch failed: %s", error)
        return []

    documents: list[Document] = []
    for entry in entries:
        name = str(entry.get("Name") or "").strip()
        if not name:
            continue
        description = str(entry.get("Description") or "")
        commands = entry.get("Commands") or []
        for index, command in enumerate(commands):
            command_text = str(command.get("Command") or "")
            command_desc = str(command.get("Description") or "")
            usecase = str(command.get("UseCase") or "")
            mitre_ids = ", ".join(
                str(mid).strip() for mid in (command.get("MitreID") or []) if str(mid).strip()
            )
            body = (
                f"LOLBin: {name}\n"
                f"Binary description: {description}\n"
                f"Command: {command_text}\n"
                f"Use case: {usecase}\n"
                f"Notes: {command_desc}\n"
                f"MITRE ATT&CK: {mitre_ids}\n"
            )
            doc_id = _sha1(f"lolbas:{name}:{index}:{command_text}")
            documents.append(
                Document(
                    doc_id=doc_id,
                    text=body,
                    metadata={
                        "source": "lolbas",
                        "name": name,
                        "mitre_ids": mitre_ids,
                        "url": str(entry.get("url") or ""),
                    },
                )
            )
    logger.info("LOLBAS: %d documents", len(documents))
    return documents


async def fetch_advisory_feed(url: str) -> list[Document]:
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            raw = response.text
    except Exception as error:
        logger.warning("advisory feed %s failed: %s", url, error)
        return []

    parsed = feedparser.parse(raw)
    documents: list[Document] = []
    for entry in parsed.entries:
        title = str(getattr(entry, "title", ""))
        link = str(getattr(entry, "link", ""))
        summary_html = str(getattr(entry, "summary", "") or getattr(entry, "description", ""))
        body_text = BeautifulSoup(summary_html, "html.parser").get_text(separator=" ", strip=True)
        combined = f"{title}\n{body_text}"
        if not _matches_lotl(combined):
            continue
        doc_id = _sha1(f"advisory:{link or title}")
        documents.append(
            Document(
                doc_id=doc_id,
                text=f"Advisory: {title}\nLink: {link}\n\n{body_text}",
                metadata={
                    "source": "advisory",
                    "feed": url,
                    "title": title,
                    "url": link,
                    "published": str(getattr(entry, "published", "")),
                },
            )
        )
    logger.info("advisory feed %s: %d LOTL-matching documents", url, len(documents))
    return documents


async def fetch_all_advisory_feeds(urls: Iterable[str]) -> list[Document]:
    out: list[Document] = []
    for url in urls:
        out.extend(await fetch_advisory_feed(url))
    return out
