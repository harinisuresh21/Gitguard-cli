from __future__ import annotations

import typer
from rich.table import Table

from gitguard.core.preflight import PreflightError, run_preflight_checks
from gitguard.ui.console import console, print_error, print_section, print_success


def verify_env_command() -> None:
    try:
        console.clear()
        print_section("GitGuard Environment Verification")
        with console.status("Running environment checks...", spinner="dots"):
            result = run_preflight_checks(require_ai_key=False)
    except PreflightError as error:
        print_error(f"Environment check failed: {error}")
        raise typer.Exit(code=1) from error

    table = Table(title="GitGuard Environment")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="white")
    table.add_row("Docker daemon", result.docker_status)
    table.add_row("Free memory", f"{result.available_memory_mb} MB")
    table.add_row("Minimum memory", "ok" if result.memory_ok else "insufficient")
    table.add_row("Gemini API key", "configured" if result.ai_key_present else "not configured")
    console.print(table)
    print_success("Environment checks passed.")


__all__ = ["verify_env_command"]
