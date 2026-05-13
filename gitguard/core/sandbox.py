from __future__ import annotations

import platform
import time

import docker
from docker.errors import DockerException

from gitguard.core.models import SandboxResult
from gitguard.core.session import ScanSession

SANDBOX_IMAGE = "mcr.microsoft.com/playwright/python:v1.40.0-jammy"
SANDBOX_CLONE_TIMEOUT_SECONDS = 60
SANDBOX_MEMORY_LIMIT = "512m"
SANDBOX_CPU_LIMIT = 1_000_000_000
SANDBOX_USER = "pwuser"
SANDBOX_WORKDIR = "/workspace"


class SandboxError(RuntimeError):
    """Raised when the sandbox cannot complete successfully."""


class SandboxTimeoutError(SandboxError):
    """Raised when the sandbox runtime exceeds the hard timeout."""


def run_sandbox_clone(target_url: str, session: ScanSession) -> SandboxResult:
    client = docker.from_env(timeout=5)
    start_time = time.monotonic()
    try:
        client.images.pull(SANDBOX_IMAGE)
        container = client.containers.run(
            SANDBOX_IMAGE,
            command=_build_clone_command(),
            detach=True,
            environment={"TARGET_URL": target_url},
            user=SANDBOX_USER,
            working_dir=SANDBOX_WORKDIR,
            network_mode="bridge",
            read_only=True,
            tmpfs={"/tmp": "", SANDBOX_WORKDIR: ""},
            cap_drop=["ALL"],
            mem_limit=SANDBOX_MEMORY_LIMIT,
            nano_cpus=SANDBOX_CPU_LIMIT,
            volumes={},
        )
        session.register_container(container.id)
        exit_code = _wait_for_container(container, timeout_seconds=SANDBOX_CLONE_TIMEOUT_SECONDS)
        logs = _read_container_logs(container)
        runtime_seconds = time.monotonic() - start_time
        warnings = _build_isolation_warnings(logs)
        if exit_code != 0:
            raise SandboxError("Sandbox clone stage failed inside the container.")
        return SandboxResult(
            image=SANDBOX_IMAGE,
            container_id=container.id,
            exit_code=exit_code,
            logs=logs,
            runtime_seconds=runtime_seconds,
            warnings=warnings,
        )
    except DockerException as error:
        raise SandboxError(f"Docker sandbox error: {error}") from error
    finally:
        client.close()


def _build_clone_command() -> list[str]:
    clone_script = """
set -eu
mkdir -p /workspace
cd /workspace
git clone --depth 1 "$TARGET_URL" repo
printf 'GITGUARD_SANDBOX_EVENT clone_complete\\n'
"""
    return ["/bin/bash", "-lc", clone_script]


def _wait_for_container(container: object, timeout_seconds: int) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        container.reload()
        state = getattr(container, "status", "")
        if state == "exited":
            result = container.wait()
            status_code = result.get("StatusCode", 1)
            if isinstance(status_code, int):
                return status_code
            return 1
        time.sleep(1)

    try:
        container.remove(force=True)
    except DockerException:
        pass
    raise SandboxTimeoutError(
        f"Sandbox runtime exceeded {timeout_seconds} seconds and was forcefully terminated."
    )


def _read_container_logs(container: object) -> str:
    raw_logs = container.logs(stdout=True, stderr=True)
    if isinstance(raw_logs, bytes):
        return raw_logs.decode("utf-8", errors="replace")
    return str(raw_logs)


def _build_isolation_warnings(logs: str) -> list[str]:
    warnings: list[str] = []
    host_platform = platform.system().lower()
    if host_platform != "linux":
        warnings.append(
            "Private LAN egress blocking is not enforced on this host platform; "
            "sandbox is running in degraded isolation mode."
        )
    else:
        warnings.append(
            "Private LAN egress blocking is not enforced yet; sandbox is using Docker bridge "
            "networking with degraded isolation."
        )
    if "clone_complete" not in logs:
        warnings.append("Sandbox finished without the expected clone completion marker.")
    return warnings
