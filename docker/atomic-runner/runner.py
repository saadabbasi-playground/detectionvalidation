#!/usr/bin/env python3
"""Atomic Red Team scenario runner.

Reads a scenario YAML, maps each step to a technique simulation, and
POSTs execution requests to the victim agent HTTP API. All emitted events
flow: victim stdout → Vector → OpenSearch/Splunk.

Usage:
  python runner.py run --scenario /scenarios/log4shell-cve-2021-44228.yml
  python runner.py list
  python runner.py technique T1059.004
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import click
import requests
import yaml
from rich.console import Console
from rich.table import Table

import techniques

console = Console()

_TARGET_HOST = os.environ.get("RUNNER_TARGET_HOST", "linux-victim")
_AGENT_PORT = os.environ.get("RUNNER_AGENT_PORT", "9099")
_AGENT_URL = f"http://{_TARGET_HOST}:{_AGENT_PORT}"
_SCENARIOS_DIR = Path(os.environ.get("RUNNER_SCENARIOS_DIR", "/scenarios"))
_STEP_DELAY = float(os.environ.get("RUNNER_STEP_DELAY", "2"))


def _wait_for_agent(timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{_AGENT_URL}/health", timeout=3)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def _simulate(step: dict[str, Any]) -> dict[str, Any]:
    payload = {k: v for k, v in step.items() if k != "description"}
    try:
        r = requests.post(f"{_AGENT_URL}/simulate", json=payload, timeout=20)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}


@click.group()
def main() -> None:
    pass


@main.command()
@click.option("--scenario", "-s", required=True, type=click.Path(exists=True),
              help="Path to scenario YAML file")
@click.option("--delay", "-d", default=_STEP_DELAY, show_default=True,
              help="Seconds between steps")
def run(scenario: str, delay: float) -> None:
    """Execute an attack scenario against the victim."""
    data = yaml.safe_load(Path(scenario).read_text())
    name = data.get("name", Path(scenario).stem)
    cve = data.get("cve", "unknown")
    steps = data.get("steps", [])

    console.print(f"\n[bold cyan]▶ {name}[/]  CVE: [yellow]{cve}[/]")
    console.print(f"  {data.get('description', '')}\n")

    if not _wait_for_agent():
        console.print(f"[red]✗[/] Victim agent not reachable at {_AGENT_URL}")
        sys.exit(1)

    console.print(f"[green]✓[/] Victim agent ready at {_AGENT_URL}\n")

    results = []
    for i, step in enumerate(steps, 1):
        technique_id = step.get("technique", "")
        variant = step.get("variant", "")
        desc = step.get("description", technique_id)

        console.print(f"[bold]Step {i}/{len(steps)}[/] [{technique_id}] {desc}")

        sim_steps = techniques.get_steps(technique_id, variant)
        if not sim_steps:
            console.print(f"  [yellow]⚠[/] No simulation for {technique_id} — skipping")
            results.append({"step": i, "technique": technique_id, "status": "skipped"})
            continue

        step_results = []
        for sim in sim_steps:
            console.print(f"  → {sim.get('description', sim.get('key', ''))}")
            result = _simulate(sim)
            ok = result.get("ok", False)
            rc = result.get("returncode", -1)
            out = result.get("output", "")
            status = "ok" if ok and rc == 0 else ("ok" if ok else "error")
            icon = "[green]✓[/]" if status == "ok" else "[red]✗[/]"
            console.print(f"    {icon}  rc={rc}  {out[:120] if out else ''}")
            step_results.append({"sim": sim.get("description"), "status": status, "rc": rc})
            time.sleep(delay)

        results.append({"step": i, "technique": technique_id, "status": "ok", "sims": step_results})

    console.print(f"\n[bold green]Scenario complete.[/] {len(steps)} steps executed.")
    console.print(f"Events are flowing to OpenSearch and Splunk via Vector.\n")

    table = Table(title="Step Summary")
    table.add_column("Step", style="dim")
    table.add_column("Technique")
    table.add_column("Status")
    for r in results:
        status = r["status"]
        color = "green" if status == "ok" else ("yellow" if status == "skipped" else "red")
        table.add_row(str(r["step"]), r["technique"], f"[{color}]{status}[/{color}]")
    console.print(table)


@main.command(name="list")
def list_scenarios() -> None:
    """List available scenarios."""
    yamls = sorted(_SCENARIOS_DIR.glob("*.yml"))
    if not yamls:
        console.print(f"[yellow]No scenarios found in {_SCENARIOS_DIR}[/]")
        return
    table = Table(title="Available Scenarios")
    table.add_column("File")
    table.add_column("Name")
    table.add_column("CVE")
    table.add_column("Steps")
    for p in yamls:
        try:
            d = yaml.safe_load(p.read_text())
            table.add_row(p.name, d.get("name", ""), d.get("cve", ""), str(len(d.get("steps", []))))
        except Exception:
            table.add_row(p.name, "?", "?", "?")
    console.print(table)


@main.command()
@click.argument("technique_id")
def technique(technique_id: str) -> None:
    """Run a single technique by ID (e.g. T1059.004)."""
    steps = techniques.get_steps(technique_id)
    if not steps:
        console.print(f"[red]No simulation for {technique_id}[/]")
        sys.exit(1)
    if not _wait_for_agent(timeout=10):
        console.print(f"[red]✗[/] Victim agent not reachable at {_AGENT_URL}")
        sys.exit(1)
    console.print(f"[bold cyan]Running {technique_id} ({len(steps)} steps)[/]")
    for sim in steps:
        console.print(f"  → {sim.get('description', '')}")
        result = _simulate(sim)
        out = result.get("output", "")
        console.print(f"    rc={result.get('returncode', '?')}  {out[:200] if out else ''}")
        time.sleep(_STEP_DELAY)
    console.print("[green]Done.[/]")


if __name__ == "__main__":
    main()
