from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path

from .schema import SysmonRecord


def _parse_time(raw: str | None) -> datetime:
    if not raw:
        return datetime.fromtimestamp(0)
    cleaned = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        try:
            parsed = datetime.strptime(cleaned, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            return datetime.fromtimestamp(0)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


MANIFEST_FILENAMES = (
    "manifest.yml",
    "manifest.yaml",
    "manifest.json",
    "manifest.jsonl",
    "metadata.json",
)


def _read_manifest(capture_dir: Path) -> tuple[list[str], bool]:
    """Return (technique_ids, is_malicious_capture) if a manifest is present."""
    for candidate in MANIFEST_FILENAMES:
        manifest = capture_dir / candidate
        if manifest.exists():
            try:
                text = manifest.read_text(encoding="utf-8")
            except OSError:
                continue
            if manifest.suffix in (".json", ".jsonl"):
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    continue
                techniques = payload.get("attack_mappings") or payload.get("techniques") or []
                technique_ids = [
                    str(t.get("technique") if isinstance(t, dict) else t) for t in techniques
                ]
                return technique_ids, bool(payload.get("malicious", True))
            technique_ids = []
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("- T") and stripped[2:].split(".")[0].isdigit() is False:
                    pass
                if stripped.startswith(("technique:", "- technique:", "id:")):
                    value = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                    if value.startswith("T"):
                        technique_ids.append(value)
            return technique_ids, True
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
                data={str(k): str(v) for k, v in (payload.get("data") or {}).items()},
                capture_id=cid,
                capture_techniques=tuple(payload.get("capture_techniques") or capture_techs),
                capture_is_malicious=bool(payload.get("capture_is_malicious", capture_malicious)),
            )


def load_mordor_jsonl(path: Path, capture_id: str | None = None) -> Iterator[SysmonRecord]:
    """Load OTRF Mordor / Security-Datasets JSONL (Winlogbeat ECS schema)."""
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
            yield SysmonRecord(
                record_id=int(winlog.get("record_id") or payload.get("@timestamp_record", 0) or 0),
                event_id=int(winlog.get("event_id") or payload.get("event_id") or 0),
                level=int(winlog.get("level") or 4),
                provider=winlog.get("provider_name", "Microsoft-Windows-Sysmon"),
                channel=winlog.get("channel", "Microsoft-Windows-Sysmon/Operational"),
                computer=winlog.get("computer_name", payload.get("host", {}).get("name", "")),
                time_created=_parse_time(payload.get("@timestamp")),
                data={str(k): str(v) for k, v in event_data.items()},
                capture_id=cid,
                capture_techniques=tuple(capture_techs),
                capture_is_malicious=capture_malicious,
            )


def load_attack_data_jsonl(path: Path, capture_id: str | None = None) -> Iterator[SysmonRecord]:
    """Load Splunk attack_data JSON exports. EventData fields live at the top level."""
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
            data = {k: str(payload[k]) for k in sysmon_keys if k in payload}
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
    """Load JSONL emitted by ``omerbenamram/evtx`` (``evtx_dump -o jsonl``).

    Output shape: ``{"Event": {"System": {...}, "EventData": {...}}}``. Lift the
    relevant fields into our canonical layout.
    """
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
                time_created_raw = time_created_raw.get("#attributes", {}).get(
                    "SystemTime"
                ) or time_created_raw.get("SystemTime")
            provider_raw = system.get("Provider")
            if isinstance(provider_raw, dict):
                provider_name = provider_raw.get("#attributes", {}).get("Name") or provider_raw.get(
                    "Name", ""
                )
            else:
                provider_name = str(provider_raw or "Microsoft-Windows-Sysmon")
            # evtx_dump renders <Data Name="X">val</Data> into {"X": "val"} already.
            data = {str(k): str(v) for k, v in event_data.items() if not isinstance(v, dict)}
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
    """Load one ``.jsonl`` file in the given dialect."""
    loader = _DIALECT_LOADERS.get(dialect)
    if loader is None:
        raise ValueError(f"unknown dialect: {dialect!r} (expected one of {list(_DIALECT_LOADERS)})")
    yield from loader(path)


def load_directory(root: Path, dialect: str = "agent") -> Iterator[SysmonRecord]:
    """Recursively load every ``.jsonl`` capture under ``root``.

    Each subdirectory is treated as a distinct capture; that subdirectory's name
    becomes the ``capture_id``. This is what feeds GroupShuffleSplit later.
    """
    for jsonl_path in sorted(root.rglob("*.jsonl")):
        if jsonl_path.name in MANIFEST_FILENAMES:
            continue
        capture_id = jsonl_path.parent.relative_to(root).as_posix() or jsonl_path.stem
        yield from _DIALECT_LOADERS[dialect](jsonl_path, capture_id=capture_id)


def load_all(paths: Iterable[tuple[Path, str]]) -> list[SysmonRecord]:
    """Convenience: load multiple (path, dialect) sources into one list."""
    records: list[SysmonRecord] = []
    for path, dialect in paths:
        if path.is_dir():
            records.extend(load_directory(path, dialect=dialect))
        else:
            records.extend(load_capture(path, dialect=dialect))
    return records
