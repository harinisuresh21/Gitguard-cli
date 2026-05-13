from __future__ import annotations

import json
import platform
import time
from typing import Callable

import docker
from docker.errors import DockerException

from gitguard.core.models import SandboxResult
from gitguard.core.runtime_analysis import parse_sandbox_telemetry
from gitguard.core.session import ScanSession

SANDBOX_IMAGE = "mcr.microsoft.com/playwright/python:v1.40.0-jammy"
SANDBOX_CLONE_TIMEOUT_SECONDS = 180
SANDBOX_MEMORY_LIMIT = "512m"
SANDBOX_CPU_LIMIT = 1_000_000_000
SANDBOX_USER = "pwuser"
SANDBOX_WORKDIR = "/workspace"
SANDBOX_TMP_DIR = "/tmp"
SANDBOX_TOTAL_TIMEOUT_SECONDS = 360
SANDBOX_DYNAMIC_TIMEOUT_SECONDS = 120


class SandboxError(RuntimeError):
    """Raised when the sandbox cannot complete successfully."""

    def __init__(self, message: str, logs: str = "") -> None:
        super().__init__(message)
        self.logs = logs


class SandboxTimeoutError(SandboxError):
    """Raised when the sandbox runtime exceeds the hard timeout."""


def run_sandbox_clone(
    target_url: str,
    session: ScanSession,
    progress_callback: Callable[[str], None] | None = None,
) -> SandboxResult:
    client = docker.from_env(timeout=5)
    start_time = time.monotonic()
    try:
        _emit_progress(progress_callback, "Pulling sandbox image...")
        client.images.pull(SANDBOX_IMAGE)
        _emit_progress(progress_callback, "Sandbox image ready.")
        _emit_progress(progress_callback, "Starting sandbox container...")
        container = client.containers.run(
            SANDBOX_IMAGE,
            command=_build_clone_command(),
            detach=True,
            environment={"TARGET_URL": target_url},
            user=SANDBOX_USER,
            working_dir=SANDBOX_TMP_DIR,
            network_mode="bridge",
            read_only=True,
            tmpfs={SANDBOX_TMP_DIR: ""},
            cap_drop=["ALL"],
            mem_limit=SANDBOX_MEMORY_LIMIT,
            nano_cpus=SANDBOX_CPU_LIMIT,
            volumes={},
        )
        session.register_container(container.id)
        _emit_progress(progress_callback, f"Sandbox container started: {container.id[:12]}")
        exit_code = _wait_for_container(
            container,
            timeout_seconds=SANDBOX_TOTAL_TIMEOUT_SECONDS,
            progress_callback=progress_callback,
        )
        logs = _read_container_logs(container)
        runtime_seconds = time.monotonic() - start_time
        warnings = _build_isolation_warnings(logs)
        if exit_code != 0:
            raise SandboxError("Sandbox clone stage failed inside the container.", logs=logs)
        coverage, coverage_reason, telemetry_events, progress_messages, entrypoint = parse_sandbox_telemetry(logs)
        return SandboxResult(
            image=SANDBOX_IMAGE,
            container_id=container.id,
            exit_code=exit_code,
            logs=logs,
            runtime_seconds=runtime_seconds,
            warnings=warnings,
            coverage=coverage,
            coverage_reason=coverage_reason,
            telemetry_events=telemetry_events,
            progress_messages=progress_messages,
            entrypoint=entrypoint,
        )
    except DockerException as error:
        raise SandboxError(f"Docker sandbox error: {error}") from error
    finally:
        client.close()


def _build_clone_command() -> list[str]:
    clone_script = """
set -eu
printf 'GITGUARD_PROGRESS: Starting shallow clone\\n'
cd /tmp
timeout __CLONE_TIMEOUT__s git clone --depth 1 "$TARGET_URL" repo
printf 'GITGUARD_PROGRESS: Repository cloned into sandbox\\n'
cd /tmp/repo
python - <<'PY'
import json
import os

candidates = [
    "index.html",
    "public/index.html",
    "dist/index.html",
    "build/index.html",
]
entrypoint = next((path for path in candidates if os.path.exists(path)), None)
if entrypoint is None:
    print("GITGUARD_PROGRESS: No browser entrypoint detected; using static-only fallback", flush=True)
    print(json.dumps({"event": "coverage", "mode": "static_only", "reason": "unsupported_repo_type"}))
    raise SystemExit(0)

print(f"GITGUARD_PROGRESS: Browser entrypoint detected at {entrypoint}", flush=True)
print(json.dumps({"event": "coverage", "mode": "browser_dynamic", "entrypoint": entrypoint}))
PY
if [ -f index.html ] || [ -f public/index.html ] || [ -f dist/index.html ] || [ -f build/index.html ]; then
  printf 'GITGUARD_PROGRESS: Starting local HTTP server\\n'
  python -m http.server 8000 --bind 127.0.0.1 >/tmp/gitguard-http.log 2>&1 &
  HTTP_PID=$!
  printf 'GITGUARD_PROGRESS: Launching Playwright browser analysis\\n'
  timeout __DYNAMIC_TIMEOUT__s python - <<'PY'
import json
import random
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

entrypoint = None
for path in ("index.html", "public/index.html", "dist/index.html", "build/index.html"):
    if Path(path).exists():
        entrypoint = path
        break

base_url = f"http://127.0.0.1:8000/{entrypoint}" if entrypoint != "index.html" else "http://127.0.0.1:8000/"

def emit(payload):
    print(json.dumps(payload), flush=True)

with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    context.add_init_script(
        \"\"\"
Object.defineProperty(navigator, 'webdriver', {get: () => false});
\"\"\"
    )

    page = context.new_page()

    def on_request(request):
        headers = dict(request.headers)
        emit(
            {
                "event": "request",
                "url": request.url,
                "method": request.method,
                "headers": headers,
                "payload_size": len(request.post_data or ""),
            }
        )

    def on_console(message):
        text = message.text
        if text.startswith("GITGUARD_PERMISSION:"):
            emit({"event": "permission", "permission": text.split(":", 1)[1]})
        elif text.startswith("GITGUARD_FILE_NAV:"):
            emit({"event": "file_navigation", "url": text.split(":", 1)[1]})
        elif text.startswith("GITGUARD_WS:"):
            emit({"event": "websocket", "url": text.split(":", 1)[1]})
        else:
            emit({"event": "console", "message": text})

    page.on("request", on_request)
    page.on("console", on_console)

    page.add_init_script(
        \"\"\"
(() => {
  const wrapPermission = (name) => {
    const original = navigator.mediaDevices && navigator.mediaDevices[name];
    if (!original) return;
    navigator.mediaDevices[name] = async function(...args) {
      console.log('GITGUARD_PERMISSION:' + name);
      return original.apply(this, args);
    };
  };
  wrapPermission('getUserMedia');

  const OriginalWebSocket = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    console.log('GITGUARD_WS:' + url);
    return new OriginalWebSocket(url, protocols);
  };
  window.WebSocket.prototype = OriginalWebSocket.prototype;

  const originalAssign = window.location.assign.bind(window.location);
  window.location.assign = function(url) {
    if (String(url).startsWith('file://')) {
      console.log('GITGUARD_FILE_NAV:' + url);
    }
    return originalAssign(url);
  };
})();
\"\"\"
    )

    emit({"event": "progress", "message": "Navigating to application entrypoint"})
    page.goto(base_url, wait_until="domcontentloaded", timeout=15000)
    emit({"event": "progress", "message": "Page loaded; collecting runtime behavior"})
    page.wait_for_timeout(5000)
    for _ in range(4):
        page.mouse.move(random.randint(0, 800), random.randint(0, 600))
    page.mouse.wheel(0, 300)
    page.mouse.wheel(0, -150)
    emit({"event": "progress", "message": "Browser interaction sequence completed"})
    browser.close()
PY
  kill $HTTP_PID
fi
printf 'GITGUARD_PROGRESS: Sandbox analysis finished\\n'
printf 'GITGUARD_SANDBOX_EVENT clone_complete\\n'
"""
    clone_script = clone_script.replace("__CLONE_TIMEOUT__", str(SANDBOX_CLONE_TIMEOUT_SECONDS))
    clone_script = clone_script.replace("__DYNAMIC_TIMEOUT__", str(SANDBOX_DYNAMIC_TIMEOUT_SECONDS))
    return ["/bin/bash", "-lc", clone_script]


def _wait_for_container(
    container: object,
    timeout_seconds: int,
    progress_callback: Callable[[str], None] | None = None,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    emitted_progress_count = 0
    while time.monotonic() < deadline:
        emitted_progress_count = _emit_progress_from_logs(
            _read_container_logs(container), emitted_progress_count, progress_callback
        )
        container.reload()
        state = getattr(container, "status", "")
        if state == "exited":
            result = container.wait()
            _emit_progress(progress_callback, "Sandbox container exited.")
            status_code = result.get("StatusCode", 1)
            if isinstance(status_code, int):
                return status_code
            return 1
        time.sleep(1)

    try:
        logs = _read_container_logs(container)
        _emit_progress_from_logs(logs, emitted_progress_count, progress_callback)
        container.remove(force=True)
    except DockerException:
        logs = ""
    raise SandboxTimeoutError(
        f"Sandbox {_infer_timeout_phase(logs)} exceeded {timeout_seconds} seconds and was forcefully terminated.",
        logs=logs,
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


def _infer_timeout_phase(logs: str) -> str:
    if '"mode": "browser_dynamic"' in logs:
        return "dynamic analysis"
    return "clone/setup stage"


def _emit_progress(
    progress_callback: Callable[[str], None] | None,
    message: str,
) -> None:
    if progress_callback is not None:
        progress_callback(message)


def _emit_progress_from_logs(
    logs: str,
    emitted_progress_count: int,
    progress_callback: Callable[[str], None] | None,
) -> int:
    progress_lines: list[str] = []
    for line in logs.splitlines():
        stripped = line.strip()
        if stripped.startswith("GITGUARD_PROGRESS:"):
            progress_lines.append(stripped.split(":", 1)[1].strip())
            continue
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("event") != "progress":
            continue
        message = payload.get("message")
        if isinstance(message, str):
            progress_lines.append(message)

    for message in progress_lines[emitted_progress_count:]:
        _emit_progress(progress_callback, message)
    return len(progress_lines)
