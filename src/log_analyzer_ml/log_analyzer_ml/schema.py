from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SYSMON_PROCESS_CREATE = 1
SYSMON_NETWORK_CONNECT = 3
SYSMON_FILE_CREATE = 11


@dataclass(slots=True)
class SysmonRecord:
    record_id: int
    event_id: int
    time_created: datetime
    data: dict[str, str]
    computer: str = ""
    provider: str = "Microsoft-Windows-Sysmon"
    channel: str = "Microsoft-Windows-Sysmon/Operational"
    level: int = 4
    capture_id: str = ""
    capture_techniques: tuple[str, ...] = field(default_factory=tuple)
    capture_is_malicious: bool = False

    @property
    def image(self) -> str:
        return self.data.get("Image", "")

    @property
    def original_file_name(self) -> str:
        return self.data.get("OriginalFileName", "")

    @property
    def command_line(self) -> str:
        return self.data.get("CommandLine", "")

    @property
    def parent_command_line(self) -> str:
        return self.data.get("ParentCommandLine", "")

    @property
    def parent_image(self) -> str:
        return self.data.get("ParentImage", "")

    @property
    def process_guid(self) -> str:
        return self.data.get("ProcessGuid", "")

    @property
    def parent_process_guid(self) -> str:
        return self.data.get("ParentProcessGuid", "")
