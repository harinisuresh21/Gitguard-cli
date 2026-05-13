from __future__ import annotations

import os

import docker
from docker.errors import DockerException
import psutil

from gitguard.core.models import PreflightResult

MINIMUM_FREE_MEMORY_BYTES = 1_000_000_000


class PreflightError(RuntimeError):
    """Raised when a host prerequisite is not met."""


def run_preflight_checks(require_ai_key: bool) -> PreflightResult:
    docker_status = _check_docker_daemon()
    available_memory_bytes = psutil.virtual_memory().available
    memory_ok = available_memory_bytes >= MINIMUM_FREE_MEMORY_BYTES
    if not memory_ok:
        available_mb = int(available_memory_bytes / (1024 * 1024))
        raise PreflightError(
            f"At least 1 GB of free memory is required; found {available_mb} MB."
        )

    ai_key_present = bool(os.getenv("GEMINI_API_KEY"))
    if require_ai_key and not ai_key_present:
        raise PreflightError("GEMINI_API_KEY is required for this command.")

    return PreflightResult(
        docker_status=docker_status,
        available_memory_mb=int(available_memory_bytes / (1024 * 1024)),
        memory_ok=memory_ok,
        ai_key_present=ai_key_present,
    )


def _check_docker_daemon() -> str:
    try:
        client = docker.from_env(timeout=5)
        client.ping()
        client.close()
    except DockerException as error:
        raise PreflightError(
            "Docker daemon not running or not reachable. Start Docker and try again."
        ) from error
    return "reachable"
