from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path

import yaml

from .schema import SysmonRecord

logger = logging.getLogger(__name__)

EPOCH = datetime(1970, 1, 1)


def _parse_time(raw: str | None) -> datetime:
    if not raw:
        return EPOCH
    cleaned = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        try:
            parsed = datetime.strptime(cleaned, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            logger.debug("unparseable timestamp: %r", raw)
            return EPOCH
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _stringify(value: object) -> str:
    return "" if value is None else str(value)


def _stringify_dict(payload: object) -> dict[str, str]:
    if not isinstance(payload, dict):
        return {}
    return {str(k): _stringify(v) for k, v in payload.items() if v is not None}


MANIFEST_FILENAMES = (
    "manifest.yml",
    "manifest.yaml",
    "manifest.json",
    "manifest.jsonl",
    "metadata.json",
)


def _extract_techniques(raw_list: object) -> list[str]:
    technique_ids: list[str] = []
    if not isinstance(raw_list, list):
        return technique_ids
    for entry in raw_list:
        raw = entry.get("technique") if isinstance(entry, dict) else entry
        if raw is None:
            continue
        technique_ids.append(str(raw))
    return technique_ids


def _read_manifest(capture_dir: Path) -> tuple[list[str], bool]:
    for candidate in MANIFEST_FILENAMES:
        manifest = capture_dir / candidate
        if not manifest.exists():
            continue
        try:
            text = manifest.read_text(encoding="utf-8")
        except OSError:
            continue
        if manifest.suffix in (".json", ".jsonl"):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
        else:
            try:
                payload = yaml.safe_load(text)
            except yaml.YAMLError:
                continue
        if not isinstance(payload, dict):
            continue
        raw = payload.get("attack_mappings") or payload.get("techniques") or []
        return _extract_techniques(raw), bool(payload.get("malicious", True))
    return [], False


def load_agent_jsonl(path: Path, capture_id: str | None = None) -> Iterator[SysmonRecord]:
    capture_dir = path.parent
    capture_techs, capture_malicious = _read_manifest(capture_dir)
    cid = capture_id or capture_dir.name
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            yield SysmonRecord(
                record_id=int(payload.get("record_id", 0)),
                event_id=int(payload.get("event_id", 0)),
                level=int(payload.get("level", 4)),
                provider=payload.get("provider", "Microsoft-Windows-Sysmon"),
                channel=payload.get("channel", "Microsoft-Windows-Sysmon/Operational"),
                computer=payload.get("computer", ""),
                time_created=_parse_time(payload.get("time_created")),
                data=_stringify_dict(payload.get("data")),
                capture_id=cid,
                capture_techniques=tuple(payload.get("capture_techniques") or capture_techs),
                capture_is_malicious=bool(payload.get("capture_is_malicious", capture_malicious)),
            )


def load_mordor_jsonl(path: Path, capture_id: str | None = None) -> Iterator[SysmonRecord]:
    capture_dir = path.parent
    capture_techs, capture_malicious = _read_manifest(capture_dir)
    cid = capture_id or capture_dir.name
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            winlog = payload.get("winlog") or {}
            event_data = winlog.get("event_data") or {}
            host = payload.get("host") or {}
            yield SysmonRecord(
                record_id=int(winlog.get("record_id") or payload.get("@timestamp_record", 0) or 0),
                event_id=int(winlog.get("event_id") or payload.get("event_id") or 0),
                level=int(winlog.get("level") or 4),
                provider=winlog.get("provider_name", "Microsoft-Windows-Sysmon"),
                channel=winlog.get("channel", "Microsoft-Windows-Sysmon/Operational"),
                computer=winlog.get("computer_name", host.get("name", "")),
                time_created=_parse_time(payload.get("@timestamp")),
                data=_stringify_dict(event_data),
                capture_id=cid,
                capture_techniques=tuple(capture_techs),
                capture_is_malicious=capture_malicious,
            )


def load_attack_data_jsonl(path: Path, capture_id: str | None = None) -> Iterator[SysmonRecord]:
    capture_dir = path.parent
    capture_techs, capture_malicious = _read_manifest(capture_dir)
    cid = capture_id or capture_dir.name
    sysmon_keys = {
        "Image",
        "OriginalFileName",
        "CommandLine",
        "ParentImage",
        "ParentCommandLine",
        "ProcessGuid",
        "ParentProcessGuid",
        "User",
        "IntegrityLevel",
        "Hashes",
        "TargetFilename",
        "DestinationIp",
        "DestinationPort",
    }
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            data = {
                k: _stringify(payload[k])
                for k in sysmon_keys
                if k in payload and payload[k] is not None
            }
            yield SysmonRecord(
                record_id=int(payload.get("RecordNumber") or payload.get("record_id") or 0),
                event_id=int(payload.get("EventID") or payload.get("event_id") or 0),
                level=int(payload.get("Level") or 4),
                provider=payload.get("SourceName", "Microsoft-Windows-Sysmon"),
                channel=payload.get("LogName", "Microsoft-Windows-Sysmon/Operational"),
                computer=payload.get("ComputerName", ""),
                time_created=_parse_time(payload.get("TimeCreated") or payload.get("_time")),
                data=data,
                capture_id=cid,
                capture_techniques=tuple(capture_techs),
                capture_is_malicious=capture_malicious,
            )


def load_evtx_jsonl(path: Path, capture_id: str | None = None) -> Iterator[SysmonRecord]:
    capture_dir = path.parent
    capture_techs, capture_malicious = _read_manifest(capture_dir)
    cid = capture_id or capture_dir.name
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            event = payload.get("Event") or {}
            system = event.get("System") or {}
            event_data = event.get("EventData") or {}
            event_id_raw = system.get("EventID")
            if isinstance(event_id_raw, dict):
                event_id_raw = event_id_raw.get("#text") or event_id_raw.get("Value") or 0
            time_created_raw = system.get("TimeCreated")
            if isinstance(time_created_raw, dict):
                attrs = time_created_raw.get("#attributes") or {}
                time_created_raw = attrs.get("SystemTime") or time_created_raw.get("SystemTime")
            provider_raw = system.get("Provider")
            if isinstance(provider_raw, dict):
                attrs = provider_raw.get("#attributes") or {}
                provider_name = attrs.get("Name") or provider_raw.get("Name", "")
            else:
                provider_name = str(provider_raw or "Microsoft-Windows-Sysmon")
            data = {
                str(k): _stringify(v)
                for k, v in event_data.items()
                if v is not None and not isinstance(v, dict)
            }
            yield SysmonRecord(
                record_id=int(system.get("EventRecordID") or 0),
                event_id=int(event_id_raw or 0),
                level=int(system.get("Level") or 4),
                provider=provider_name,
                channel=str(system.get("Channel") or "Microsoft-Windows-Sysmon/Operational"),
                computer=str(system.get("Computer") or ""),
                time_created=_parse_time(time_created_raw),
                data=data,
                capture_id=cid,
                capture_techniques=tuple(capture_techs),
                capture_is_malicious=capture_malicious,
            )


_DIALECT_LOADERS = {
    "agent": load_agent_jsonl,
    "mordor": load_mordor_jsonl,
    "attack_data": load_attack_data_jsonl,
    "evtx": load_evtx_jsonl,
}


def load_capture(path: Path, dialect: str = "agent") -> Iterator[SysmonRecord]:
    loader = _DIALECT_LOADERS.get(dialect)
    if loader is None:
        raise ValueError(f"unknown dialect: {dialect!r} (expected one of {list(_DIALECT_LOADERS)})")
    yield from loader(path)


def load_directory(root: Path, dialect: str = "agent") -> Iterator[SysmonRecord]:
    for jsonl_path in sorted(root.rglob("*.jsonl")):
        if jsonl_path.name in MANIFEST_FILENAMES:
            continue
        capture_id = jsonl_path.parent.relative_to(root).as_posix() or jsonl_path.stem
        yield from _DIALECT_LOADERS[dialect](jsonl_path, capture_id=capture_id)


def load_all(paths: Iterable[tuple[Path, str]]) -> list[SysmonRecord]:
    records: list[SysmonRecord] = []
    for path, dialect in paths:
        before = len(records)
        if path.is_dir():
            records.extend(load_directory(path, dialect=dialect))
        else:
            records.extend(load_capture(path, dialect=dialect))
        logger.info(
            "loaded %d records from %s (dialect=%s); cumulative=%d",
            len(records) - before,
            path,
            dialect,
            len(records),
        )
    return records
