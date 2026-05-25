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
@click.option("--siem", default="opensearch", show_default=True, help="Target SIEM backend.")
@click.option("--output", default="stdout", show_default=True, help="Report output destination.")
@click.option("--format", "fmt", default="cli", show_default=True,
              type=click.Choice(["cli", "json", "html", "sarif", "slack"]))
def validate(rules: str, siem: str, output: str, fmt: str) -> None:
    """Validate detection rules against live or synthetic attack telemetry."""
    console.print(f"[cyan]Validating rules in:[/] {rules}  siem={siem}  format={fmt}")
    console.print("[yellow]TODO: implement validation pipeline[/]")


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
@click.option("--watch", is_flag=True, default=False,
              help="After the run, show the attack events that landed in OpenSearch.")
@click.option("--delay", default=1.5, show_default=True,
              help="Seconds between attack steps.")
def attack(
    cve_id: str | None,
    scenario_file: str | None,
    victim: str,
    agent_port: str,
    watch: bool,
    delay: float,
) -> None:
    """Simulate a CVE-based attack against the Linux victim container.

    Runs the atomic-runner against dv-linux-victim, which executes the
    technique simulations and emits structured events that flow through
    Vector into OpenSearch and Splunk.

    \b
    Prerequisites:
      docker build --platform linux/arm64 -t detection-validator/linux-victim:dev docker/linux-victim/
      docker build --platform linux/arm64 -t detection-validator/atomic-runner:dev docker/atomic-runner/
      docker run -d --name dv-linux-victim --network detectval-lab ...

    \b
    Examples:
      dv attack --cve CVE-2021-44228
      dv attack --cve CVE-2021-34527 --watch
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
    elif scenario_file:
        scenario_in_container = scenario_file
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
        err_console.print("  Start it with:  docker run -d --name dv-linux-victim \\")
        err_console.print("    --network detectval-lab -p 9099:9099 \\")
        err_console.print("    detection-validator/linux-victim:dev")
        raise SystemExit(1)

    # ── run the atomic-runner container ─────────────────────────────────────
    console.print(f"\n[bold cyan]⚔  Running attack scenario[/]  cve={cve_id or scenario_file}")
    console.print(f"   Victim: [yellow]{victim}[/]  agent: {agent_url}\n")

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
