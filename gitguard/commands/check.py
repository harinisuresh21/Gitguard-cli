from __future__ import annotations

from collections import deque
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from gitguard.core.ai_audit import AIAuditError, load_readme_context, run_ai_audit
from gitguard.core.dependency_guard import (
    DependencyGuardError,
    analyze_dependency_manifests,
    cleanup_checkout,
    clone_repository_to_tempdir,
)
from gitguard.core.models import (
    AIAuditResult,
    DependencyAnalysisResult,
    DependencyFinding,
    ObfuscationAnalysisResult,
    ObfuscationFinding,
    ScanAssessment,
    ScanRecord,
)
from gitguard.core.obfuscation_review import analyze_obfuscation
from gitguard.core.preflight import PreflightError, run_preflight_checks
from gitguard.core.reporting import build_scan_report, render_scan_report_json, write_scan_report
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


def check_command(url: str, json_output: bool = False) -> None:
    record: ScanRecord | None = None
    assessment: ScanAssessment | None = None
    dependency_result: DependencyAnalysisResult | None = None
    obfuscation_result = ObfuscationAnalysisResult(findings=[], warnings=[])
    ai_audit_result: AIAuditResult | None = None
    ai_audit_warning: str | None = None
    preflight = None
    sandbox_result = None
    scans_file = None
    static_checkout_root: Path | None = None
    report_path: Path | None = None
    try:
        if not json_output:
            console.clear()
            print_section("GitGuard Check")
        with console.status("Validating target repository...", spinner="dots") if not json_output else nullcontext():
            normalized_url = validate_repository_url(url)

        record = ScanRecord.create(
            target_url=normalized_url,
            created_at=datetime.now(timezone.utc),
            initial_status="initializing",
        )
        scans_file = append_scan_record(record)

        with ScanSession(record) as session:
            session.ensure_not_timed_out()
            with console.status("Verifying host prerequisites...", spinner="dots") if not json_output else nullcontext():
                preflight = run_preflight_checks(require_ai_key=False)
            session.ensure_not_timed_out()
            update_scan_record_status(record.scan_id, "static_checkout")
            with console.status("Cloning repository for static analysis...", spinner="dots") if not json_output else nullcontext():
                static_checkout_root = clone_repository_to_tempdir(normalized_url)
            session.ensure_not_timed_out()
            update_scan_record_status(record.scan_id, "dependency_guard")
            with console.status("Running dependency guard...", spinner="dots") if not json_output else nullcontext():
                dependency_result = analyze_dependency_manifests(static_checkout_root)
            session.ensure_not_timed_out()
            update_scan_record_status(record.scan_id, "obfuscation_review")
            with console.status("Running obfuscation review...", spinner="dots") if not json_output else nullcontext():
                obfuscation_result = analyze_obfuscation(static_checkout_root)
            session.ensure_not_timed_out()
            if dependency_result.blocked:
                assessment = _build_dependency_only_assessment(dependency_result, obfuscation_result)
                ai_audit_result, ai_audit_warning = _attempt_ai_audit(
                    static_checkout_root,
                    dependency_result,
                    obfuscation_result,
                    assessment,
                    None,
                )
                update_scan_record_status(record.scan_id, assessment.verdict.lower())
                report_path = _emit_scan_report(
                    json_output,
                    record,
                    scans_file,
                    preflight,
                    assessment,
                    dependency_result,
                    obfuscation_result,
                    ai_audit_warning,
                    ai_audit_result,
                    None,
                )
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

            if json_output:
                sandbox_result = run_sandbox_clone(normalized_url, session)
            else:
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
            assessment = _merge_assessments(dependency_result, obfuscation_result, runtime_assessment)
            ai_audit_result, ai_audit_warning = _attempt_ai_audit(
                static_checkout_root,
                dependency_result,
                obfuscation_result,
                assessment,
                sandbox_result,
            )
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
    finally:
        if static_checkout_root is not None:
            cleanup_checkout(static_checkout_root)
    report_path = _emit_scan_report(
        json_output,
        record,
        scans_file,
        preflight,
        assessment,
        dependency_result,
        obfuscation_result,
        ai_audit_warning,
        ai_audit_result,
        sandbox_result,
    )


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
    obfuscation_result: ObfuscationAnalysisResult,
    ai_audit_warning: str | None,
    ai_audit_result: AIAuditResult | None,
    sandbox_result,
    report_path: Path | None,
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
    if report_path is not None:
        table.add_row("Report File", str(report_path))
    table.add_row("Coverage", assessment.coverage)
    if dependency_result is not None:
        table.add_row("Dependency Manifests", str(len(dependency_result.manifests)))
        table.add_row("Dependencies Parsed", str(len(dependency_result.packages)))
        table.add_row(
            "Dependencies by Ecosystem",
            ", ".join(
                f"{name}={count}" for name, count in sorted(dependency_result.package_count_by_ecosystem.items())
            ),
        )
    table.add_row("Obfuscation Findings", str(len(obfuscation_result.findings)))
    if ai_audit_result is not None:
        table.add_row("AI Model", ai_audit_result.model_name)
        table.add_row("AI Recommendation", ai_audit_result.verdict_recommendation)
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
    console.print(
        Panel(
            _render_obfuscation_activity(obfuscation_result),
            title="Obfuscation Review",
            border_style="blue",
        )
    )
    if obfuscation_result.findings:
        console.print(
            Panel(
                "\n".join(_format_obfuscation_finding(finding) for finding in obfuscation_result.findings),
                title="Obfuscation Findings",
                border_style="yellow",
            )
        )
    if obfuscation_result.warnings:
        console.print(
            Panel(
                "\n".join(obfuscation_result.warnings),
                title="Obfuscation Warnings",
                border_style="yellow",
            )
        )
    if ai_audit_result is not None:
        console.print(
            Panel(
                "\n".join(
                    [
                        f"Recommendation: {ai_audit_result.verdict_recommendation}",
                        f"Reasoning: {ai_audit_result.reasoning}",
                        f"Evidence Summary: {ai_audit_result.evidence_summary}",
                    ]
                ),
                title="AI Audit",
                border_style="magenta",
            )
        )
    elif ai_audit_warning:
        console.print(
            Panel(
                ai_audit_warning,
                title="AI Audit",
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


def _emit_scan_report(
    json_output: bool,
    record: ScanRecord,
    scans_file,
    preflight,
    assessment: ScanAssessment,
    dependency_result: DependencyAnalysisResult | None,
    obfuscation_result: ObfuscationAnalysisResult,
    ai_audit_warning: str | None,
    ai_audit_result: AIAuditResult | None,
    sandbox_result,
) -> Path:
    report = build_scan_report(
        record=record,
        scans_file=scans_file,
        preflight=preflight,
        assessment=assessment,
        dependency_result=dependency_result,
        obfuscation_result=obfuscation_result,
        ai_audit_warning=ai_audit_warning,
        ai_audit_result=ai_audit_result,
        sandbox_result=sandbox_result,
    )
    report_path = write_scan_report(record.scan_id, report)
    report["report_file"] = str(report_path)
    if json_output:
        console.print(render_scan_report_json(report))
    else:
        _render_scan_report(
            record,
            scans_file,
            preflight,
            assessment,
            dependency_result,
            obfuscation_result,
            ai_audit_warning,
            ai_audit_result,
            sandbox_result,
            report_path,
        )
    return report_path


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
        f"Python dependencies parsed: {result.package_count_by_ecosystem.get('python', 0)}",
        f"Node dependencies parsed: {result.package_count_by_ecosystem.get('node', 0)}",
        f"Critical findings: {critical}",
        f"High findings: {high}",
        f"Medium findings: {medium}",
        f"Low findings: {low}",
    ]
    if result.manifests:
        lines.append(f"Manifests: {', '.join(result.manifests)}")
    return "\n".join(lines)


def _render_obfuscation_activity(result: ObfuscationAnalysisResult) -> str:
    high = sum(1 for finding in result.findings if finding.severity == "HIGH")
    medium = sum(1 for finding in result.findings if finding.severity == "MEDIUM")
    low = sum(1 for finding in result.findings if finding.severity == "LOW")
    return "\n".join(
        [
            f"High findings: {high}",
            f"Medium findings: {medium}",
            f"Low findings: {low}",
        ]
    )


def _format_dependency_finding(finding: DependencyFinding) -> str:
    package_detail = f" [{finding.package_name}]" if finding.package_name else ""
    return (
        f"{finding.severity} {finding.category}{package_detail} "
        f"({finding.manifest_path}): {finding.message}"
    )


def _format_obfuscation_finding(finding: ObfuscationFinding) -> str:
    return (
        f"{finding.severity} {finding.category} "
        f"([{finding.file_path}]): {finding.message} "
        f"Snippet: {finding.snippet}"
    )


def _build_dependency_only_assessment(
    result: DependencyAnalysisResult,
    obfuscation_result: ObfuscationAnalysisResult,
) -> ScanAssessment:
    return ScanAssessment(
        verdict="MALICIOUS",
        summary="Dependency guard found critical static indicators before sandbox execution.",
        evidence=[
            *[_format_dependency_finding(finding) for finding in result.findings],
            *[_format_obfuscation_finding(finding) for finding in obfuscation_result.findings],
        ],
        coverage="dependency_guard_only",
    )


def _merge_assessments(
    dependency_result: DependencyAnalysisResult | None,
    obfuscation_result: ObfuscationAnalysisResult,
    runtime_assessment: ScanAssessment,
) -> ScanAssessment:
    static_evidence = [_format_obfuscation_finding(finding) for finding in obfuscation_result.findings]
    if dependency_result is not None:
        static_evidence = [
            *[_format_dependency_finding(finding) for finding in dependency_result.findings],
            *static_evidence,
        ]
    if not static_evidence:
        return runtime_assessment

    if runtime_assessment.verdict == "MALICIOUS":
        return ScanAssessment(
            verdict="MALICIOUS",
            summary=runtime_assessment.summary,
            evidence=static_evidence + runtime_assessment.evidence,
            coverage=runtime_assessment.coverage,
        )
    dependency_findings = dependency_result.findings if dependency_result is not None else []
    if any(finding.severity in {"CRITICAL", "HIGH"} for finding in dependency_findings):
        return ScanAssessment(
            verdict="MALICIOUS",
            summary="Static dependency analysis found malicious indicators before or alongside runtime analysis.",
            evidence=static_evidence + runtime_assessment.evidence,
            coverage=runtime_assessment.coverage,
        )
    if any(finding.severity == "HIGH" for finding in obfuscation_result.findings):
        return ScanAssessment(
            verdict="SUSPICIOUS",
            summary="Static obfuscation review found hidden payload patterns that warrant review.",
            evidence=static_evidence + runtime_assessment.evidence,
            coverage=runtime_assessment.coverage,
        )
    if runtime_assessment.verdict == "SUSPICIOUS":
        return ScanAssessment(
            verdict="SUSPICIOUS",
            summary=runtime_assessment.summary,
            evidence=static_evidence + runtime_assessment.evidence,
            coverage=runtime_assessment.coverage,
        )
    if obfuscation_result.findings:
        return ScanAssessment(
            verdict="SUSPICIOUS",
            summary="Static obfuscation review found encoded or hidden payload indicators that warrant review.",
            evidence=static_evidence + runtime_assessment.evidence,
            coverage=runtime_assessment.coverage,
        )
    return ScanAssessment(
        verdict="SUSPICIOUS",
        summary="Static dependency analysis found packages or metadata that warrant review.",
        evidence=static_evidence + runtime_assessment.evidence,
        coverage=runtime_assessment.coverage,
    )


def _attempt_ai_audit(
    static_checkout_root: Path,
    dependency_result: DependencyAnalysisResult,
    obfuscation_result: ObfuscationAnalysisResult,
    runtime_assessment: ScanAssessment,
    sandbox_result,
) -> tuple[AIAuditResult | None, str | None]:
    readme_text = load_readme_context(static_checkout_root)
    try:
        return (
            run_ai_audit(
                readme_text=readme_text,
                dependency_result=dependency_result,
                obfuscation_result=obfuscation_result,
                runtime_assessment=runtime_assessment,
                sandbox_result=sandbox_result,
            ),
            None,
        )
    except AIAuditError as error:
        return None, f"Optional AI audit was skipped: {error}"
