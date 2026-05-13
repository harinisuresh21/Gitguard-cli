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
    coverage: str
    coverage_reason: str | None
    telemetry_events: list[dict[str, object]]
    progress_messages: list[str]
    entrypoint: str | None


@dataclass(slots=True)
class DependencyFinding:
    severity: str
    category: str
    package_name: str | None
    manifest_path: str
    message: str


@dataclass(slots=True)
class DependencyAnalysisResult:
    manifests: list[str]
    packages: list[str]
    findings: list[DependencyFinding]
    warnings: list[str]
    blocked: bool


@dataclass(slots=True)
class ObfuscationFinding:
    severity: str
    category: str
    file_path: str
    message: str
    snippet: str


@dataclass(slots=True)
class ObfuscationAnalysisResult:
    findings: list[ObfuscationFinding]
    warnings: list[str]


@dataclass(slots=True)
class AIAuditResult:
    verdict_recommendation: str
    reasoning: str
    evidence_summary: str
    raw_json: dict[str, object]
    model_name: str


@dataclass(slots=True)
class ScanAssessment:
    verdict: str
    summary: str
    evidence: list[str]
    coverage: str
