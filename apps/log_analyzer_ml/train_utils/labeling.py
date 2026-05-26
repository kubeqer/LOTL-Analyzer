from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import PureWindowsPath

from .lolbas import is_lolbin, technique_intersects_lotl
from .schema import SYSMON_PROCESS_CREATE, SysmonRecord


def basename(path: str) -> str:
    if not path:
        return ""
    try:
        return PureWindowsPath(path).name.lower()
    except ValueError:
        return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()


def _record_is_lolbin(record: SysmonRecord) -> bool:
    image = basename(record.image)
    if image and is_lolbin(image):
        return True
    original = record.original_file_name.lower()
    return bool(original and is_lolbin(original))


def label_records(records: Iterable[SysmonRecord]) -> list[int]:
    records_list = list(records)

    by_capture: dict[str, list[int]] = {}
    for idx, record in enumerate(records_list):
        if record.event_id != SYSMON_PROCESS_CREATE or not record.capture_is_malicious:
            continue
        by_capture.setdefault(record.capture_id, []).append(idx)

    labels = [0] * len(records_list)
    for indices in by_capture.values():
        techniques: set[str] = set()
        for idx in indices:
            techniques.update(records_list[idx].capture_techniques)
        capture_is_lotl = technique_intersects_lotl(list(techniques))

        roots: set[str] = set()
        for idx in indices:
            record = records_list[idx]
            if _record_is_lolbin(record):
                labels[idx] = 1
                if record.process_guid:
                    roots.add(record.process_guid)

        if not capture_is_lotl or not roots:
            continue

        descendants = set(roots)
        children_of: dict[str, list[int]] = {}
        for idx in indices:
            parent_guid = records_list[idx].parent_process_guid
            if parent_guid:
                children_of.setdefault(parent_guid, []).append(idx)

        frontier = set(roots)
        while frontier:
            next_frontier: set[str] = set()
            for parent in frontier:
                for child_idx in children_of.get(parent, ()):
                    child_guid = records_list[child_idx].process_guid
                    if child_guid and child_guid not in descendants:
                        descendants.add(child_guid)
                        next_frontier.add(child_guid)
            frontier = next_frontier

        for idx in indices:
            if records_list[idx].process_guid in descendants:
                labels[idx] = 1

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
