from __future__ import annotations

import json

from gitguard.core.models import ScanAssessment, SandboxResult

ALLOWED_README_CHARS = 3000


def parse_sandbox_telemetry(
    logs: str,
) -> tuple[str, str | None, list[dict[str, object]], list[str], str | None]:
    coverage = "static_only"
    coverage_reason: str | None = None
    events: list[dict[str, object]] = []
    progress_messages: list[str] = []
    entrypoint: str | None = None
    for raw_line in logs.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("GITGUARD_PROGRESS:"):
            progress_messages.append(line.split(":", 1)[1].strip())
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("event") == "coverage":
            mode = payload.get("mode")
            if isinstance(mode, str):
                coverage = mode
            candidate_reason = payload.get("reason")
            if isinstance(candidate_reason, str):
                coverage_reason = candidate_reason
            candidate_entrypoint = payload.get("entrypoint")
            if isinstance(candidate_entrypoint, str):
                entrypoint = candidate_entrypoint
            continue
        if payload.get("event") == "progress":
            message = payload.get("message")
            if isinstance(message, str):
                progress_messages.append(message)
            continue
        events.append(payload)
    return coverage, coverage_reason, events, progress_messages, entrypoint


def assess_runtime_behavior(sandbox_result: SandboxResult) -> ScanAssessment:
    evidence: list[str] = []
    external_requests = _collect_external_requests(sandbox_result.telemetry_events)
    websocket_events = _collect_events(sandbox_result.telemetry_events, "websocket")
    permission_events = _collect_events(sandbox_result.telemetry_events, "permission")
    file_events = _collect_events(sandbox_result.telemetry_events, "file_navigation")

    if sandbox_result.coverage != "browser_dynamic":
        return ScanAssessment(
            verdict="SAFE",
            summary="No strong malicious indicators were found. Dynamic browser analysis did not run for this repository type.",
            evidence=["Dynamic coverage limited to static-only fallback."],
            coverage=sandbox_result.coverage,
        )

    if external_requests:
        evidence.extend(
            [
                f"Observed outbound request to {event.get('url', '<unknown>')} via {event.get('method', 'GET')}."
                for event in external_requests
            ]
        )
    if websocket_events:
        evidence.extend(
            [
                f"Observed WebSocket attempt to {event.get('url', '<unknown>')}."
                for event in websocket_events
            ]
        )
    if permission_events:
        evidence.extend(
            [
                f"Observed browser permission request for {event.get('permission', '<unknown>')}."
                for event in permission_events
            ]
        )
    if file_events:
        evidence.extend(
            [
                f"Observed file navigation attempt to {event.get('url', '<unknown>')}."
                for event in file_events
            ]
        )

    if file_events:
        return ScanAssessment(
            verdict="MALICIOUS",
            summary="The application attempted file-scheme navigation during browser execution.",
            evidence=evidence,
            coverage=sandbox_result.coverage,
        )
    if websocket_events or permission_events or external_requests:
        return ScanAssessment(
            verdict="SUSPICIOUS",
            summary="The application showed runtime behavior that warrants manual review.",
            evidence=evidence or ["Unexpected runtime activity was observed."],
            coverage=sandbox_result.coverage,
        )
    return ScanAssessment(
        verdict="SAFE",
        summary="No strong malicious indicators were found during dynamic browser analysis.",
        evidence=["No outbound requests, WebSocket attempts, or sensitive browser access were observed."],
        coverage=sandbox_result.coverage,
    )


def truncate_readme_text(value: str) -> str:
    if len(value) <= ALLOWED_README_CHARS:
        return value
    return value[:ALLOWED_README_CHARS]


def _collect_external_requests(events: list[dict[str, object]]) -> list[dict[str, object]]:
    external: list[dict[str, object]] = []
    for event in _collect_events(events, "request"):
        url = str(event.get("url", ""))
        if url.startswith("http://127.0.0.1") or url.startswith("http://localhost"):
            continue
        if url.startswith("https://127.0.0.1") or url.startswith("https://localhost"):
            continue
        external.append(event)
    return external


def _collect_events(events: list[dict[str, object]], event_name: str) -> list[dict[str, object]]:
    return [event for event in events if event.get("event") == event_name]
