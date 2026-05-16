from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import PurePath, PureWindowsPath

from .lolbas import technique_intersects_lotl
from .schema import SYSMON_PROCESS_CREATE, SysmonRecord


def basename(path: str) -> str:
    if not path:
        return ""
    try:
        return PureWindowsPath(path).name.lower() or PurePath(path).name.lower()
    except ValueError:
        return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()


def label_records(records: Iterable[SysmonRecord]) -> list[int]:
    labels: list[int] = []
    for record in records:
        if record.event_id != SYSMON_PROCESS_CREATE:
            labels.append(0)
            continue
        if not record.capture_is_malicious:
            labels.append(0)
            continue
        if technique_intersects_lotl(list(record.capture_techniques)):
            labels.append(1)
        else:
            labels.append(0)
    return labels


def filter_process_creates(
    records: Sequence[SysmonRecord], labels: Sequence[int]
) -> tuple[list[SysmonRecord], list[int]]:
    kept_records: list[SysmonRecord] = []
    kept_labels: list[int] = []
    for record, label in zip(records, labels, strict=True):
        if record.event_id == SYSMON_PROCESS_CREATE:
            kept_records.append(record)
            kept_labels.append(label)
    return kept_records, kept_labels
