from __future__ import annotations

import logging
from pathlib import Path

import yara

from ..config import settings
from ..schema import SysmonEvent, SysmonEvents

logger = logging.getLogger(__name__)

SCAN_FIELDS = ("CommandLine", "ParentCommandLine", "Image", "ParentImage", "OriginalFileName")


class YaraDetector:
    def __init__(self, rules: yara.Rules) -> None:
        self._rules = rules

    @classmethod
    def from_dir(cls, rules_dir: Path) -> YaraDetector:
        rule_files = sorted(rules_dir.glob("*.yar")) + sorted(rules_dir.glob("*.yara"))
        if not rule_files:
            raise FileNotFoundError(f"no YARA rules in {rules_dir}")
        filepaths = {p.stem: str(p) for p in rule_files}
        compiled = yara.compile(filepaths=filepaths)
        logger.info("compiled %d YARA rule file(s) from %s", len(rule_files), rules_dir)
        return cls(compiled)

    def detect(self, window: SysmonEvents) -> tuple[bool, list[str]]:
        hits: set[str] = set()
        for event in window.events:
            payload = _event_payload(event)
            if not payload:
                continue
            matches = self._rules.match(data=payload.encode("utf-8", errors="ignore"))
            for match in matches:
                hits.add(match.rule)
        return (bool(hits), sorted(hits))


def _event_payload(event: SysmonEvent) -> str:
    parts = [event.data.get(field, "") for field in SCAN_FIELDS]
    return "\n".join(p for p in parts if p)


_detector: YaraDetector | None = None


def get_detector() -> YaraDetector:
    global _detector
    if _detector is None:
        _detector = YaraDetector.from_dir(settings.yara_rules_dir)
    return _detector


def detect_yara(window: SysmonEvents) -> tuple[bool, list[str]]:
    return get_detector().detect(window)
