from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import platform
from uuid import uuid4


@dataclass(slots=True)
class ScanRecord:
    scan_id: str
    target_url: str
    timestamp: str
    host_os: str
    status: str

    @classmethod
    def create(cls, target_url: str, created_at: datetime, initial_status: str) -> "ScanRecord":
        return cls(
            scan_id=str(uuid4()),
            target_url=target_url,
            timestamp=created_at.isoformat(),
            host_os=platform.system(),
            status=initial_status,
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class PreflightResult:
    docker_status: str
    available_memory_mb: int
    memory_ok: bool
    ai_key_present: bool


@dataclass(slots=True)
class SandboxResult:
    image: str
    container_id: str
    exit_code: int
    logs: str
    runtime_seconds: float
    warnings: list[str]
