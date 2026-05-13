from __future__ import annotations

import typer

from gitguard.commands.check import check_command
from gitguard.commands.history import history_command
from gitguard.commands.verify_env import verify_env_command

app = typer.Typer(
    add_completion=False,
    help="GitGuard repository risk assessment CLI.",
    no_args_is_help=True,
)


@app.command("check")
def check(
    url: str,
    json_output: bool = typer.Option(False, "--json", help="Print the final scan report as JSON."),
) -> None:
    check_command(url, json_output=json_output)


@app.command("doctor")
def doctor() -> None:
    verify_env_command()


@app.command("verify-env", hidden=True)
def verify_env() -> None:
    verify_env_command()


@app.command("history")
def history(limit: int = typer.Option(10, min=1, help="Number of scans to display.")) -> None:
    history_command(limit=limit)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
