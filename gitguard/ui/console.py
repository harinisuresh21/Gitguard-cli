from rich.console import Console
from rich.panel import Panel

console = Console()


def print_error(message: str) -> None:
    console.print(f"[bold red]{message}[/bold red]")


def print_warning(message: str) -> None:
    console.print(f"[bold yellow]{message}[/bold yellow]")


def print_success(message: str) -> None:
    console.print(f"[bold green]{message}[/bold green]")


def print_section(title: str) -> None:
    console.print(Panel.fit(title, border_style="cyan", padding=(0, 2)))
