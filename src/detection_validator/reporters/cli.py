"""Rich-powered CLI summary reporter."""

from __future__ import annotations

from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box


_TACTIC_NAMES = {
    "T1003": "Credential Access",  "T1027": "Defense Evasion",
    "T1046": "Discovery",          "T1059": "Execution",
    "T1068": "Privilege Escalation", "T1071": "Command & Control",
    "T1078": "Defense Evasion",    "T1110": "Credential Access",
    "T1190": "Initial Access",     "T1218": "Defense Evasion",
    "T1499": "Impact",             "T1505": "Persistence",
    "T1547": "Persistence",        "T1552": "Credential Access",
    "T1574": "Privilege Escalation",
}


def _tactic(tid: str) -> str:
    return _TACTIC_NAMES.get(tid.split(".")[0], "Other")


def report(results: list[dict], console: Console | None = None) -> None:
    """Print a full validation summary to *console* (defaults to stdout)."""
    if console is None:
        console = Console()

    if not results:
        console.print("[yellow]No results to report.[/]")
        return

    likely   = [r for r in results if r.get("status") == "likely_fires"]
    partial  = [r for r in results if r.get("status") == "keyword_partial"]
    no_match = [r for r in results if r.get("status") == "no_keyword_match"]
    errors   = [r for r in results if r.get("status") == "error"]
    skipped  = [r for r in results if r.get("status") == "skip"]
    # Backward-compat: count legacy "pass"/"fail" statuses if present
    likely  += [r for r in results if r.get("status") == "pass"]
    no_match += [r for r in results if r.get("status") == "fail"]
    total    = len(results)
    covered_count = len(likely) + len(partial)
    pass_pct = round(covered_count / total * 100) if total else 0

    covered_techs: set[str] = set()
    for r in likely + partial:
        covered_techs.update(r.get("techniques") or [])

    all_techs: set[str] = set()
    for r in results:
        all_techs.update(r.get("techniques") or [])

    # ── Summary panel ─────────────────────────────────────────────────────────
    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary_lines = [
        f"[bold]Rules:[/]            {total}",
        f"[green]Likely fires:[/]    {len(likely)} ({pass_pct}%)",
        f"[yellow]Keyword partial:[/] {len(partial)}",
        f"[red]No keyword match:[/]{len(no_match)}",
        f"[yellow]Error:[/]           {len(errors)}",
        f"[dim]Skip:[/]             {len(skipped)}",
        "",
        f"[bold]Techniques:[/]      {len(covered_techs)} covered / {len(all_techs)} total",
        f"[dim]Generated:[/]       {generated}",
    ]
    console.print(Panel("\n".join(summary_lines), title="Static Coverage Analysis", expand=False))
    console.print()

    # ── Failing rules ─────────────────────────────────────────────────────────
    if no_match or errors:
        tbl = Table(show_header=True, header_style="bold", box=box.SIMPLE, padding=(0, 1))
        tbl.add_column("Rule", style="white", max_width=40)
        tbl.add_column("Techniques", style="cyan", max_width=28)
        tbl.add_column("SIEM", width=11)
        tbl.add_column("Status", width=20)
        tbl.add_column("Detail", style="dim", max_width=40)

        for r in no_match + errors:
            status = r.get("status", "no_keyword_match")
            icon = "[red]✗ NO_KEYWORD_MATCH[/]" if status in ("no_keyword_match", "fail") else "[yellow]! ERROR[/]"
            tech_str = ", ".join((r.get("techniques") or [])[:3])
            detail = r.get("error") or r.get("query") or ""
            tbl.add_row(
                r.get("name", r.get("rule_id", "?"))[:40],
                tech_str,
                r.get("siem", ""),
                icon,
                str(detail)[:40],
            )

        console.print("[bold red]Rules with no keyword match[/]")
        console.print(tbl)

    # ── Tactic coverage ───────────────────────────────────────────────────────
    tactic_map: dict[str, dict] = {}
    for tid in all_techs:
        tac = _tactic(tid)
        if tac not in tactic_map:
            tactic_map[tac] = {"covered": set(), "total": set()}
        tactic_map[tac]["total"].add(tid)
        if tid in covered_techs:
            tactic_map[tac]["covered"].add(tid)

    if tactic_map:
        tbl2 = Table(show_header=True, header_style="bold", box=box.SIMPLE, padding=(0, 1))
        tbl2.add_column("Tactic", style="white", min_width=24)
        tbl2.add_column("Coverage", width=12)
        tbl2.add_column("Techniques covered", style="green", max_width=50)

        for tac, data in sorted(tactic_map.items()):
            n_cov = len(data["covered"])
            n_tot = len(data["total"])
            pct = round(n_cov / n_tot * 100) if n_tot else 0
            cov_str = ", ".join(sorted(data["covered"])) or "—"
            color = "green" if pct == 100 else "yellow" if pct > 0 else "red"
            tbl2.add_row(tac, f"[{color}]{n_cov}/{n_tot} ({pct}%)[/]", cov_str)

        console.print("[bold]ATT&CK Tactic Coverage[/]")
        console.print(tbl2)

    # ── Rules with coverage (compact) ────────────────────────────────────────
    if likely or partial:
        names = ", ".join(r.get("name", "?") for r in likely + partial)
        console.print(
            f"\n[bold green]Rules with coverage ({len(likely) + len(partial)}):[/] [dim]{names}[/]"
        )
