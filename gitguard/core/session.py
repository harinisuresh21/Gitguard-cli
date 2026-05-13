from __future__ import annotations

import json
import os
from pathlib import Path
import time

import docker
from docker.errors import DockerException, NotFound
import psutil

from gitguard.core.models import ScanRecord
from gitguard.core.state import get_active_scan_file

GLOBAL_SCAN_TIMEOUT_SECONDS = 120


class ConcurrentScanError(RuntimeError):
    """Raised when another GitGuard scan is already active."""


class ScanTimeoutError(RuntimeError):
    """Raised when a scan exceeds the allowed runtime."""


class ScanSession:
    def __init__(self, record: ScanRecord, timeout_seconds: int = GLOBAL_SCAN_TIMEOUT_SECONDS) -> None:
        self.record = record
        self.timeout_seconds = timeout_seconds
        self.started_at = time.monotonic()
        self.active_scan_file = get_active_scan_file()
        self.active_container_id: str | None = None

    def __enter__(self) -> "ScanSession":
        self._acquire_lock()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.cleanup()
        self._release_lock()

    def ensure_not_timed_out(self) -> None:
        if time.monotonic() - self.started_at > self.timeout_seconds:
            raise ScanTimeoutError(
                f"Global scan timeout exceeded after {self.timeout_seconds} seconds."
            )

    def register_container(self, container_id: str) -> None:
        self.active_container_id = container_id
        self._write_lock_file()

    def cleanup(self) -> None:
        if not self.active_container_id:
            return
        try:
            client = docker.from_env(timeout=5)
            try:
                container = client.containers.get(self.active_container_id)
                container.remove(force=True)
            except NotFound:
                return
            finally:
                client.close()
        except DockerException:
            return
        finally:
            self.active_container_id = None
            self._write_lock_file()

    def _acquire_lock(self) -> None:
        if self.active_scan_file.exists():
            lock_data = self._read_lock_file()
            active_pid = lock_data.get("pid")
            if isinstance(active_pid, int) and psutil.pid_exists(active_pid):
                raise ConcurrentScanError(
                    f"Another GitGuard scan is already active (PID {active_pid})."
                )
            self.active_scan_file.unlink(missing_ok=True)
        self._write_lock_file()

    def _release_lock(self) -> None:
        self.active_scan_file.unlink(missing_ok=True)

    def _write_lock_file(self) -> None:
        payload = {
            "scan_id": self.record.scan_id,
            "target_url": self.record.target_url,
            "pid": os.getpid(),
            "container_id": self.active_container_id,
        }
        self.active_scan_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _read_lock_file(self) -> dict[str, object]:
        try:
            content = self.active_scan_file.read_text(encoding="utf-8")
            data = json.loads(content)
        except (OSError, json.JSONDecodeError):
            return {}
        if isinstance(data, dict):
            return data
        return {}
