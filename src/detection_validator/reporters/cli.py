"""Rich-powered CLI reporter."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table


class CLIReporter:
    """Print validation results as a Rich table to stdout."""

    def __init__(self) -> None:
        self.console = Console()

    def report(self, results: list) -> None:
        table = Table(title="Validation Results", show_header=True)
        table.add_column("Rule ID", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Technique")
        table.add_column("Details")

        for result in results:
            status = "[green]PASS[/]" if getattr(result, "passed", False) else "[red]FAIL[/]"
            table.add_row(
                getattr(result, "rule_id", "?"),
                status,
                getattr(result, "technique_id", ""),
                getattr(result, "error", "") or "",
            )

        self.console.print(table)
