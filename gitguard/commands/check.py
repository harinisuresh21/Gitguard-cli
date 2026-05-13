from __future__ import annotations

from collections import deque
from datetime import datetime, timezone

import typer
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from gitguard.core.dependency_guard import DependencyGuardError, run_dependency_guard
from gitguard.core.models import DependencyAnalysisResult, DependencyFinding, ScanAssessment, ScanRecord
from gitguard.core.preflight import PreflightError, run_preflight_checks
from gitguard.core.runtime_analysis import assess_runtime_behavior
from gitguard.core.sandbox import SandboxError, SandboxTimeoutError, run_sandbox_clone
from gitguard.core.session import (
    GLOBAL_SCAN_TIMEOUT_SECONDS,
    ConcurrentScanError,
    ScanSession,
    ScanTimeoutError,
)
from gitguard.core.state import append_scan_record, update_scan_record_status
from gitguard.core.validation import ValidationError, validate_repository_url
from gitguard.ui.console import console, print_error, print_section, print_success, print_warning


def check_command(url: str) -> None:
    record: ScanRecord | None = None
    assessment: ScanAssessment | None = None
    dependency_result: DependencyAnalysisResult | None = None
    preflight = None
    sandbox_result = None
    scans_file = None
    try:
        console.clear()
        print_section("GitGuard Check")
        with console.status("Validating target repository...", spinner="dots"):
            normalized_url = validate_repository_url(url)

        record = ScanRecord.create(
            target_url=normalized_url,
            created_at=datetime.now(timezone.utc),
            initial_status="initializing",
        )
        scans_file = append_scan_record(record)

        with ScanSession(record) as session:
            session.ensure_not_timed_out()
            with console.status("Verifying host prerequisites...", spinner="dots"):
                preflight = run_preflight_checks(require_ai_key=False)
            session.ensure_not_timed_out()
            update_scan_record_status(record.scan_id, "dependency_guard")
            with console.status("Running dependency guard...", spinner="dots"):
                dependency_result = run_dependency_guard(normalized_url)
            session.ensure_not_timed_out()
            if dependency_result.blocked:
                assessment = _build_dependency_only_assessment(dependency_result)
                update_scan_record_status(record.scan_id, assessment.verdict.lower())
                _render_scan_report(record, scans_file, preflight, assessment, dependency_result, None)
                raise typer.Exit(code=1)
            update_scan_record_status(record.scan_id, "launching_sandbox")
            sandbox_log_lines: deque[str] = deque(
                [
                    "Preparing sandbox launch...",
                    "Waiting for Docker image pull and container startup...",
                ],
                maxlen=12,
            )

            def on_sandbox_progress(message: str) -> None:
                sandbox_log_lines.append(message)
                live.update(_render_sandbox_progress_panel(sandbox_log_lines), refresh=True)

            with Live(
                _render_sandbox_progress_panel(sandbox_log_lines),
                console=console,
                refresh_per_second=4,
            ) as live:
                sandbox_result = run_sandbox_clone(
                    normalized_url,
                    session,
                    progress_callback=on_sandbox_progress,
                )
            session.ensure_not_timed_out()
            runtime_assessment = assess_runtime_behavior(sandbox_result)
            assessment = _merge_assessments(dependency_result, runtime_assessment)
            update_scan_record_status(record.scan_id, assessment.verdict.lower())
    except ValidationError as error:
        print_error(f"Validation failed: {error}")
        raise typer.Exit(code=1) from error
    except ConcurrentScanError as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "error")
        print_error(str(error))
        raise typer.Exit(code=1) from error
    except PreflightError as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "error")
        print_error(f"Environment check failed: {error}")
        raise typer.Exit(code=1) from error
    except DependencyGuardError as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "error")
        print_error(f"Dependency guard failed: {error}")
        raise typer.Exit(code=1) from error
    except ScanTimeoutError as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "timeout")
        print_error(str(error))
        raise typer.Exit(code=1) from error
    except SandboxTimeoutError as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "timeout")
        print_error(str(error))
        if error.logs.strip():
            console.print(
                Panel(
                    error.logs.strip(),
                    title="Sandbox Logs",
                    border_style="red",
                )
            )
        raise typer.Exit(code=1) from error
    except SandboxError as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "error")
        print_error(str(error))
        if error.logs.strip():
            console.print(
                Panel(
                    error.logs.strip(),
                    title="Sandbox Logs",
                    border_style="red",
                )
            )
        raise typer.Exit(code=1) from error
    except KeyboardInterrupt as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "interrupted")
        print_warning("Scan interrupted. Any active sandbox has been cleaned up.")
        raise typer.Exit(code=130) from error
    _render_scan_report(record, scans_file, preflight, assessment, dependency_result, sandbox_result)


__all__ = ["check_command"]


def _render_sandbox_progress_panel(lines: deque[str]) -> Panel:
    return Panel(
        "\n".join(f"- {escape(line)}" for line in lines),
        title="Sandbox Progress",
        border_style="cyan",
    )


def _render_scan_report(
    record: ScanRecord,
    scans_file,
    preflight,
    assessment: ScanAssessment,
    dependency_result: DependencyAnalysisResult | None,
    sandbox_result,
) -> None:
    table = Table(title="Scan Initialized")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Scan ID", record.scan_id)
    table.add_row("Repository", record.target_url)
    table.add_row("Status", assessment.verdict.lower())
    table.add_row("Verdict", assessment.verdict)
    table.add_row("Docker", preflight.docker_status)
    table.add_row("AI", "configured" if preflight.ai_key_present else "not configured")
    table.add_row("State File", str(scans_file))
    table.add_row("Timeout", f"{GLOBAL_SCAN_TIMEOUT_SECONDS} seconds")
    table.add_row("Coverage", assessment.coverage)
    if dependency_result is not None:
        table.add_row("Dependency Manifests", str(len(dependency_result.manifests)))
        table.add_row("Dependencies Parsed", str(len(dependency_result.packages)))
    if sandbox_result is not None and sandbox_result.coverage_reason:
        table.add_row("Coverage Detail", sandbox_result.coverage_reason)
    table.add_row("Concurrency", "single active scan enforced")
    if sandbox_result is not None:
        table.add_row("Sandbox Image", sandbox_result.image)
        table.add_row("Sandbox Exit Code", str(sandbox_result.exit_code))
        table.add_row("Sandbox Runtime", f"{sandbox_result.runtime_seconds:.1f}s")
        if sandbox_result.entrypoint:
            table.add_row("Entrypoint", sandbox_result.entrypoint)
    console.print(table)
    console.print(
        Panel(
            assessment.summary,
            title="Assessment",
            border_style="green" if assessment.verdict == "SAFE" else "yellow" if assessment.verdict == "SUSPICIOUS" else "red",
        )
    )
    if assessment.evidence:
        console.print(
            Panel(
                "\n".join(assessment.evidence),
                title="Evidence",
                border_style="cyan",
            )
        )
    if dependency_result is not None:
        console.print(
            Panel(
                _render_dependency_activity(dependency_result),
                title="Dependency Guard",
                border_style="blue",
            )
        )
        if dependency_result.findings:
            console.print(
                Panel(
                    "\n".join(_format_dependency_finding(finding) for finding in dependency_result.findings),
                    title="Dependency Findings",
                    border_style="red" if dependency_result.blocked else "yellow",
                )
            )
        if dependency_result.warnings:
            console.print(
                Panel(
                    "\n".join(dependency_result.warnings),
                    title="Dependency Warnings",
                    border_style="yellow",
                )
            )
    if sandbox_result is not None:
        console.print(
            Panel(
                _render_observed_activity(sandbox_result),
                title="Observed Activity",
                border_style="blue",
            )
        )
        if sandbox_result.progress_messages:
            console.print(
                Panel(
                    "\n".join(f"{index}. {escape(message)}" for index, message in enumerate(sandbox_result.progress_messages, start=1)),
                    title="Execution Trace",
                    border_style="magenta",
                )
            )
        if sandbox_result.warnings:
            console.print(
                Panel(
                    "\n".join(sandbox_result.warnings),
                    title="Isolation Warnings",
                    border_style="yellow",
                )
            )
        print_success("Dynamic runtime analysis completed and the container was cleaned up.")
        return
    print_success("Dependency guard completed before sandbox execution.")


def _render_observed_activity(sandbox_result) -> str:
    request_count = sum(1 for event in sandbox_result.telemetry_events if event.get("event") == "request")
    websocket_count = sum(1 for event in sandbox_result.telemetry_events if event.get("event") == "websocket")
    permission_count = sum(1 for event in sandbox_result.telemetry_events if event.get("event") == "permission")
    file_nav_count = sum(1 for event in sandbox_result.telemetry_events if event.get("event") == "file_navigation")
    lines = [
        f"Container runtime: {sandbox_result.runtime_seconds:.1f}s",
        f"HTTP requests observed: {request_count}",
        f"WebSocket attempts observed: {websocket_count}",
        f"Permission requests observed: {permission_count}",
        f"File navigation attempts observed: {file_nav_count}",
    ]
    if sandbox_result.coverage == "static_only":
        lines.append(
            f"Dynamic browser analysis skipped because coverage fell back to static_only"
            + (f" ({sandbox_result.coverage_reason})." if sandbox_result.coverage_reason else ".")
        )
    elif sandbox_result.entrypoint:
        lines.append(f"Dynamic browser analysis ran against entrypoint {sandbox_result.entrypoint}.")
    return "\n".join(lines)


def _render_dependency_activity(result: DependencyAnalysisResult) -> str:
    critical = sum(1 for finding in result.findings if finding.severity == "CRITICAL")
    high = sum(1 for finding in result.findings if finding.severity == "HIGH")
    medium = sum(1 for finding in result.findings if finding.severity == "MEDIUM")
    low = sum(1 for finding in result.findings if finding.severity == "LOW")
    lines = [
        f"Manifest files discovered: {len(result.manifests)}",
        f"Unique dependencies parsed: {len(result.packages)}",
        f"Critical findings: {critical}",
        f"High findings: {high}",
        f"Medium findings: {medium}",
        f"Low findings: {low}",
    ]
    if result.manifests:
        lines.append(f"Manifests: {', '.join(result.manifests)}")
    return "\n".join(lines)


def _format_dependency_finding(finding: DependencyFinding) -> str:
    package_detail = f" [{finding.package_name}]" if finding.package_name else ""
    return (
        f"{finding.severity} {finding.category}{package_detail} "
        f"({finding.manifest_path}): {finding.message}"
    )


def _build_dependency_only_assessment(result: DependencyAnalysisResult) -> ScanAssessment:
    return ScanAssessment(
        verdict="MALICIOUS",
        summary="Dependency guard found critical static indicators before sandbox execution.",
        evidence=[_format_dependency_finding(finding) for finding in result.findings],
        coverage="dependency_guard_only",
    )


def _merge_assessments(
    dependency_result: DependencyAnalysisResult | None,
    runtime_assessment: ScanAssessment,
) -> ScanAssessment:
    if dependency_result is None or not dependency_result.findings:
        return runtime_assessment

    static_evidence = [_format_dependency_finding(finding) for finding in dependency_result.findings]
    if any(finding.severity in {"CRITICAL", "HIGH"} for finding in dependency_result.findings):
        return ScanAssessment(
            verdict="MALICIOUS",
            summary="Static dependency analysis found malicious indicators before or alongside runtime analysis.",
            evidence=static_evidence + runtime_assessment.evidence,
            coverage=runtime_assessment.coverage,
        )
    if runtime_assessment.verdict == "MALICIOUS":
        return ScanAssessment(
            verdict="MALICIOUS",
            summary=runtime_assessment.summary,
            evidence=static_evidence + runtime_assessment.evidence,
            coverage=runtime_assessment.coverage,
        )
    return ScanAssessment(
        verdict="SUSPICIOUS",
        summary="Static dependency analysis found packages or metadata that warrant review.",
        evidence=static_evidence + runtime_assessment.evidence,
        coverage=runtime_assessment.coverage,
    )
