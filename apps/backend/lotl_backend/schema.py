from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SysmonEvent(BaseModel):
    record_id: int = 0
    event_id: int = 0
    level: int = 4
    provider: str = "Microsoft-Windows-Sysmon"
    channel: str = "Microsoft-Windows-Sysmon/Operational"
    computer: str = ""
    time_created: str = ""
    data: dict[str, str] = Field(default_factory=dict)


class IngestPayload(BaseModel):
    agent: str = ""
    version: str = ""
    host_ip: str | None = None
    events: list[SysmonEvent] = Field(default_factory=list)


@dataclass(slots=True)
class SysmonEvents:
    host_key: str
    events: list[SysmonEvent] = field(default_factory=list)
    window_started_at: datetime = field(default_factory=_utc_now)

    def __len__(self) -> int:
        return len(self.events)


@dataclass(slots=True)
class Alert:
    host_key: str
    detected_by: str
    technique: str
    mitre_ids: list[str]
    description: str
    recommended_response: str
    involved_processes: list[dict[str, str]]
    rationale: str
    raw_event_count: int
    detected_at: datetime = field(default_factory=_utc_now)
