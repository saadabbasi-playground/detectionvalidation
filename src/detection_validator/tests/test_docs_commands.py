"""
Three-layer test suite that keeps CLI code and README in sync.

Layer 1 — every registered command answers --help exit 0.
Layer 2 — every ``dv …`` invocation in README.md maps to a registered command.
Layer 3 — offline end-to-end smoke tests against examples/.
"""
from __future__ import annotations

import json
import re
import textwrap
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from detection_validator.cli import main
import click

# ── Helpers ──────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).parents[3]
_EXAMPLES_SIGMA = _REPO_ROOT / "examples" / "detections" / "sigma"
_LOG4SHELL = str(_EXAMPLES_SIGMA / "log4shell_jndi_injection.yml")

_runner = CliRunner()


def _collect_commands(grp: click.Group, prefix: str = "dv") -> list[str]:
    """Recursively enumerate all leaf and group command paths."""
    result: list[str] = []
    for name, cmd in sorted(grp.commands.items()):
        path = f"{prefix} {name}"
        result.append(path)
        if isinstance(cmd, click.Group):
            result.extend(_collect_commands(cmd, path))
    return result


def _extract_dv_commands(text: str) -> set[str]:
    """
    Extract all ``dv <sub> [<sub2>]`` invocations from fenced code blocks
    in *text* (Markdown).  Only collects the command path — options and
    arguments are stripped.
    """
    # Only look inside fenced code blocks to reduce false positives.
    fence_re = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
    # Matches lines that start with an optional shell prompt then "dv ".
    cmd_re = re.compile(
        r"(?:^|\n)\s*(?:\$\s*)?(?:\.venv/bin/)?(dv(?:\s+[a-z][a-z0-9_-]*){1,3})",
    )
    found: set[str] = set()
    for block in fence_re.finditer(text):
        for m in cmd_re.finditer(block.group(1)):
            raw = m.group(1).strip()
            # Keep only the first three tokens (dv + up to two sub-commands).
            tokens = raw.split()[:3]
            # Drop tokens that look like flag/argument values.
            clean: list[str] = []
            for tok in tokens:
                if tok.startswith("-"):
                    break
                clean.append(tok)
            if len(clean) >= 2:
                found.add(" ".join(clean))
    return found


# ── Layer 1 — registered commands have working --help ────────────────────────

REGISTERED_COMMANDS = _collect_commands(main)


@pytest.mark.parametrize("cmd_path", REGISTERED_COMMANDS)
def test_registered_command_help(cmd_path: str) -> None:
    """Every registered command must return exit 0 for --help."""
    tokens = cmd_path.split()[1:]  # drop leading "dv"
    result = _runner.invoke(main, tokens + ["--help"])
    assert result.exit_code == 0, (
        f"`{cmd_path} --help` exited {result.exit_code}:\n{result.output}"
    )


# ── Layer 2 — README invocations map to registered commands ──────────────────

_README = _REPO_ROOT / "README.md"
_README_TEXT = _README.read_text(encoding="utf-8") if _README.exists() else ""
DOC_COMMANDS = _extract_dv_commands(_README_TEXT)

# Remove the bare "dv" entry if it slipped through.
DOC_COMMANDS.discard("dv")

# Commands that appear in README in a context that isn't a real registered
# command (shell-script ./dv aliases shown for illustration).
_KNOWN_UNREGISTERED: set[str] = set()


def _longest_registered_prefix(cmd_path: str) -> str | None:
    """Return the longest registered prefix that matches *cmd_path*."""
    # Try longest-first: "dv siem add" before "dv siem" before "dv".
    candidates = sorted(REGISTERED_COMMANDS, key=len, reverse=True)
    for reg in candidates:
        if cmd_path == reg or cmd_path.startswith(reg + " "):
            return reg
    return None


@pytest.mark.parametrize("cmd_path", sorted(DOC_COMMANDS))
def test_documented_command_is_registered(cmd_path: str) -> None:
    """Every ``dv …`` in README must resolve to a registered command path."""
    if cmd_path in _KNOWN_UNREGISTERED:
        pytest.skip(f"{cmd_path!r} is a known shell-script alias, not a Python command")
    match = _longest_registered_prefix(cmd_path)
    assert match is not None, (
        f"README documents `{cmd_path}` but no matching registered command found.\n"
        f"Registered commands:\n"
        + "\n".join(f"  {c}" for c in sorted(REGISTERED_COMMANDS))
    )


# ── Layer 3 — offline end-to-end smoke tests ─────────────────────────────────


class TestOfflineSmoke:
    """Run real CLI commands against examples/ with no SIEM or network."""

    def _invoke(self, *args: str) -> click.testing.Result:
        return _runner.invoke(main, list(args), catch_exceptions=False)

    # -- lint ------------------------------------------------------------------

    def test_lint_sigma_dir(self) -> None:
        result = self._invoke("lint", str(_EXAMPLES_SIGMA))
        assert result.exit_code == 0
        assert "Linted:" in result.output

    def test_lint_min_score_flag(self) -> None:
        result = self._invoke("lint", str(_EXAMPLES_SIGMA), "--min-score", "50")
        assert result.exit_code == 0

    # -- query -----------------------------------------------------------------

    def test_query_single_rule(self) -> None:
        result = self._invoke("query", _LOG4SHELL)
        assert result.exit_code == 0
        assert "opensearch" in result.output.lower() or "lucene" in result.output.lower()

    def test_query_splunk_backend(self) -> None:
        result = self._invoke("query", _LOG4SHELL, "--siem", "splunk")
        assert result.exit_code == 0

    # -- ingest → map → enrich → badge → navigator pipeline -------------------

    def test_ingest_sigma_dir(self, tmp_path: Path) -> None:
        out = tmp_path / "canonical.jsonl"
        result = self._invoke("ingest", str(_EXAMPLES_SIGMA), "-o", str(out))
        assert result.exit_code == 0, result.output
        assert "Ingested:" in result.output
        lines = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        assert len(lines) >= 1

    def test_map_canonical(self, tmp_path: Path) -> None:
        canon = tmp_path / "canonical.jsonl"
        mapped = tmp_path / "mapped.jsonl"
        self._invoke("ingest", str(_EXAMPLES_SIGMA), "-o", str(canon))
        result = self._invoke("map", "-i", str(canon), "-o", str(mapped))
        assert result.exit_code == 0, result.output
        assert "Mapped:" in result.output

    def test_enrich(self, tmp_path: Path) -> None:
        canon = tmp_path / "canonical.jsonl"
        mapped = tmp_path / "mapped.jsonl"
        enriched = tmp_path / "enriched.jsonl"
        self._invoke("ingest", str(_EXAMPLES_SIGMA), "-o", str(canon))
        self._invoke("map", "-i", str(canon), "-o", str(mapped))
        result = self._invoke("enrich", "-i", str(mapped), "-o", str(enriched))
        assert result.exit_code == 0, result.output
        assert "Enriched:" in result.output

    def test_badge(self, tmp_path: Path) -> None:
        canon = tmp_path / "canonical.jsonl"
        mapped = tmp_path / "mapped.jsonl"
        badge_out = tmp_path / "badge.svg"
        self._invoke("ingest", str(_EXAMPLES_SIGMA), "-o", str(canon))
        self._invoke("map", "-i", str(canon), "-o", str(mapped))
        result = self._invoke("badge", "-d", str(mapped), "-o", str(badge_out))
        assert result.exit_code == 0, result.output
        assert badge_out.exists()

    def test_navigator(self, tmp_path: Path) -> None:
        canon = tmp_path / "canonical.jsonl"
        mapped = tmp_path / "mapped.jsonl"
        nav_out = tmp_path / "nav.json"
        self._invoke("ingest", str(_EXAMPLES_SIGMA), "-o", str(canon))
        self._invoke("map", "-i", str(canon), "-o", str(mapped))
        result = self._invoke("navigator", "-d", str(mapped), "-o", str(nav_out))
        assert result.exit_code == 0, result.output
        assert nav_out.exists()

    # -- gaps ------------------------------------------------------------------

    def test_gaps_requires_attack_cache(self, tmp_path: Path) -> None:
        """dv gaps exits 0 when ATT&CK cache is populated; skip otherwise."""
        from detection_validator.mappers.attack_mapper import _DEFAULT_CACHE_DIR

        stix_gz = _DEFAULT_CACHE_DIR / "enterprise-attack.json.gz"
        if not stix_gz.exists():
            pytest.skip("ATT&CK cache not populated — run `dv intel update --source attack`")
        canon = tmp_path / "canonical.jsonl"
        mapped = tmp_path / "mapped.jsonl"
        self._invoke("ingest", str(_EXAMPLES_SIGMA), "-o", str(canon))
        self._invoke("map", "-i", str(canon), "-o", str(mapped))
        result = self._invoke("gaps", "-d", str(mapped))
        assert result.exit_code == 0, result.output
        assert "Gap analysis:" in result.output

    # -- match -----------------------------------------------------------------

    def test_match_empty_events(self, tmp_path: Path) -> None:
        events = tmp_path / "empty.jsonl"
        events.write_text("")
        result = self._invoke("match", "--events", str(events), str(_EXAMPLES_SIGMA))
        assert result.exit_code == 0, result.output
        assert "Results:" in result.output

    def test_match_json_output(self, tmp_path: Path) -> None:
        events = tmp_path / "empty.jsonl"
        events.write_text("")
        out = tmp_path / "results.json"
        result = self._invoke(
            "match", "--events", str(events), str(_EXAMPLES_SIGMA),
            "--format", "json", "-o", str(out),
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(out.read_text())
        assert isinstance(payload, list)

    # -- report ----------------------------------------------------------------

    def test_report_empty_results(self) -> None:
        result = _runner.invoke(main, ["report"], input="[]")
        assert result.exit_code == 0
        assert "No results" in result.output

    def test_report_from_match_output(self, tmp_path: Path) -> None:
        events = tmp_path / "empty.jsonl"
        events.write_text("")
        results = tmp_path / "results.json"
        self._invoke(
            "match", "--events", str(events), str(_EXAMPLES_SIGMA),
            "--format", "json", "-o", str(results),
        )
        result = self._invoke("report", "--results", str(results))
        assert result.exit_code == 0, result.output

    # -- migrate ---------------------------------------------------------------

    def test_migrate_sigma_to_splunk(self, tmp_path: Path) -> None:
        out = tmp_path / "splunk.conf"
        result = self._invoke(
            "migrate", "sigma", "splunk",
            "--rules", str(_EXAMPLES_SIGMA),
            "--output", str(out),
        )
        assert result.exit_code == 0, result.output
        assert "Migrated:" in result.output
        assert out.exists()

    def test_migrate_sigma_to_kql(self, tmp_path: Path) -> None:
        out = tmp_path / "kql.txt"
        result = self._invoke(
            "migrate", "sigma", "kql",
            "--rules", str(_EXAMPLES_SIGMA),
            "--output", str(out),
        )
        assert result.exit_code == 0, result.output

    # -- SIEM-dependent commands fail gracefully (no traceback) ----------------

    def test_validate_no_siem_exits_gracefully(self) -> None:
        """dv validate without a SIEM should exit 0 with ERRORs, not a traceback."""
        result = _runner.invoke(
            main,
            ["validate", str(_EXAMPLES_SIGMA)],
            env={"DV_OPENSEARCH_URL": "", "OPENSEARCH_INITIAL_ADMIN_PASSWORD": ""},
            catch_exceptions=False,
        )
        # Exits 0 — every rule gets an ERROR verdict, but process succeeds.
        assert result.exit_code == 0
        assert "Results:" in result.output
        assert "Traceback" not in result.output

    def test_deploy_no_siem_exits_1(self) -> None:
        """dv deploy without a SIEM should exit 1 with a helpful message."""
        result = _runner.invoke(
            main,
            ["deploy", str(_EXAMPLES_SIGMA)],
            env={"DV_OPENSEARCH_URL": "", "OPENSEARCH_INITIAL_ADMIN_PASSWORD": ""},
        )
        assert result.exit_code == 1
        assert "No OpenSearch connection configured" in result.output
        assert "Traceback" not in result.output
