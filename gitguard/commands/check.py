from __future__ import annotations

from datetime import datetime, timezone

import typer
from rich.panel import Panel
from rich.table import Table

from gitguard.core.models import ScanRecord
from gitguard.core.preflight import PreflightError, run_preflight_checks
from gitguard.core.sandbox import SandboxError, SandboxTimeoutError, run_sandbox_clone
from gitguard.core.session import ConcurrentScanError, ScanSession, ScanTimeoutError
from gitguard.core.state import append_scan_record, update_scan_record_status
from gitguard.core.validation import ValidationError, validate_repository_url
from gitguard.ui.console import console, print_error, print_section, print_success, print_warning


def check_command(url: str) -> None:
    record: ScanRecord | None = None
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
            update_scan_record_status(record.scan_id, "launching_sandbox")
            with console.status("Launching isolated sandbox...", spinner="dots"):
                sandbox_result = run_sandbox_clone(normalized_url, session)
            session.ensure_not_timed_out()
            update_scan_record_status(record.scan_id, "sandbox_completed")
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
    except ScanTimeoutError as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "timeout")
        print_error(str(error))
        raise typer.Exit(code=1) from error
    except SandboxTimeoutError as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "timeout")
        print_error(str(error))
        raise typer.Exit(code=1) from error
    except SandboxError as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "error")
        print_error(str(error))
        raise typer.Exit(code=1) from error
    except KeyboardInterrupt as error:
        if record is not None:
            update_scan_record_status(record.scan_id, "interrupted")
        print_warning("Scan interrupted. Any active sandbox has been cleaned up.")
        raise typer.Exit(code=130) from error

    table = Table(title="Scan Initialized")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Scan ID", record.scan_id)
    table.add_row("Repository", record.target_url)
    table.add_row("Status", "sandbox_completed")
    table.add_row("Docker", preflight.docker_status)
    table.add_row("AI", "configured" if preflight.ai_key_present else "not configured")
    table.add_row("State File", str(scans_file))
    table.add_row("Timeout", "120 seconds")
    table.add_row("Concurrency", "single active scan enforced")
    table.add_row("Sandbox Image", sandbox_result.image)
    table.add_row("Sandbox Exit Code", str(sandbox_result.exit_code))
    table.add_row("Sandbox Runtime", f"{sandbox_result.runtime_seconds:.1f}s")
    console.print(table)
    if sandbox_result.warnings:
        console.print(
            Panel(
                "\n".join(sandbox_result.warnings),
                title="Isolation Warnings",
                border_style="yellow",
            )
        )
    print_success("Sandbox clone completed and the container was cleaned up.")


__all__ = ["check_command"]
