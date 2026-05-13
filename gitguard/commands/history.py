from __future__ import annotations

from datetime import datetime

from rich.table import Table

from gitguard.core.state import load_scan_records
from gitguard.ui.console import console, print_error, print_section, print_warning


def history_command(limit: int) -> None:
    records = load_scan_records(limit=limit)
    if not records:
        print_warning("No scans found yet. Run `gitguard check <url>` first.")
        return

    print_section("Recent Scans")
    table = Table()
    table.add_column("Timestamp", style="cyan")
    table.add_column("Repository", style="white", overflow="fold")
    table.add_column("Status", style="magenta")
    table.add_column("Scan ID", style="green")

    for record in records:
        table.add_row(
            _format_timestamp(record.get("timestamp", "")),
            str(record.get("target_url", "")),
            str(record.get("status", "")),
            str(record.get("scan_id", "")),
        )
    console.print(table)


def _format_timestamp(value: str) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


__all__ = ["history_command"]
