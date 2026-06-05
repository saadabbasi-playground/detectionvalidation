"""Tests for the comprehensive HTML reporter.

All tests are fully offline — no OpenSearch, no network, no ATT&CK KB required.
The ATT&CK-dependent sections (heatmap, gap list) are tested via ReportData
built directly; the gather_report_data() path is tested with a tmp rules dir.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from detection_validator.reporters.html import (
    ReportData,
    RuleSummary,
    build,
    build_full,
    gather_report_data,
    write_report,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

_SIGMA_LSASS = """\
title: LSASS Memory Dump
id: aaaaaaaa-bbbb-cccc-dddd-000000000001
status: experimental
description: Detects LSASS credential dumping
author: test
date: 2024-01-01
tags:
  - attack.credential_access
  - attack.T1003.001
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
  condition: selection
falsepositives:
  - AV tools
level: high
"""

_SIGMA_BASH = """\
title: Unix Shell Execution
id: aaaaaaaa-bbbb-cccc-dddd-000000000002
status: experimental
description: Detects bash script execution
author: test
date: 2024-01-01
tags:
  - attack.execution
  - attack.T1059.004
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: EXECVE
    a0|contains: bash
  condition: selection
level: medium
"""

_SIGMA_NO_ATTACK = """\
title: Orphan Rule
id: aaaaaaaa-bbbb-cccc-dddd-000000000003
status: experimental
description: No ATT&CK tags
author: test
date: 2024-01-01
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: suspicious
  condition: selection
level: low
"""


def _make_rules_dir(tmp_path: Path, rules: dict[str, str] | None = None) -> Path:
    """Write synthetic Sigma rules to tmp_path/rules/."""
    rd = tmp_path / "rules"
    rd.mkdir()
    if rules is None:
        rules = {
            "lsass.yml": _SIGMA_LSASS,
            "bash.yml": _SIGMA_BASH,
            "orphan.yml": _SIGMA_NO_ATTACK,
        }
    for name, content in rules.items():
        (rd / name).write_text(content, encoding="utf-8")
    return rd


def _make_report_data(
    posture: float = 72.5,
    n_rules: int = 3,
    n_gaps: int = 2,
    kb: bool = False,
) -> ReportData:
    rules = [
        RuleSummary(
            rule_id=f"aaa-{i}",
            name=f"Rule {i}",
            path=f"rules/rule{i}.yml",
            techniques=["T1059.004"] if i == 0 else ["T1003.001"],
            lint_score=90 - i * 15,
            lint_findings=[{"severity": "warning", "code": "DV-L001", "message": "Missing ATT&CK tag"}] if i == 2 else [],
            queries={"opensearch": f"Image:bash_{i}", "splunk": f"search Image=bash_{i}"} if i < 2 else {},
            query_errors={"elastic": "backend error"} if i == 2 else {},
        )
        for i in range(n_rules)
    ]
    gaps = [
        {
            "technique_id": f"T105{i}.00{i}",
            "name": f"Gap Technique {i}",
            "tactic": "execution",
            "score": 85.0 - i * 20,
            "prevalence": 30 - i * 5,
            "reasons": [f"Reason {i}"],
        }
        for i in range(n_gaps)
    ]
    tactic_groups: dict = {}
    if kb:
        tactic_groups = {
            "execution": [
                {"id": "T1059", "name": "Command Scripting", "covered": True, "partial": False, "gap_score": 0},
                {"id": "T1106", "name": "Native API", "covered": False, "partial": False, "gap_score": 85},
                {"id": "T1129", "name": "Shared Modules", "covered": False, "partial": True, "gap_score": 30},
            ],
            "impact": [
                {"id": "T1498", "name": "DDoS", "covered": False, "partial": False, "gap_score": 0},
            ],
        }
    return ReportData(
        generated_at="2024-06-05T12:00:00Z",
        rules_dir="/tmp/rules",
        posture_score=posture,
        rules=rules,
        gaps=gaps,
        covered_techniques=["T1059.004", "T1003.001"],
        tactic_groups=tactic_groups,
        kb_available=kb,
    )


# ── build_full: structure ─────────────────────────────────────────────────────


class TestBuildFull:
    def test_returns_string(self):
        data = _make_report_data()
        result = build_full(data)
        assert isinstance(result, str)

    def test_valid_html_structure(self):
        html = build_full(_make_report_data())
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_no_external_requests(self):
        html = build_full(_make_report_data())
        # No http/https URLs that would trigger external requests
        external = re.findall(r'(?:src|href)\s*=\s*["\']https?://', html)
        assert external == [], f"Found external URLs: {external}"

    def test_no_framework_imports(self):
        html = build_full(_make_report_data())
        for forbidden in ("cdn.jsdelivr", "unpkg.com", "googleapis", "bootstrap", "jquery", "react", "vue"):
            assert forbidden not in html, f"Found forbidden dependency: {forbidden}"

    def test_posture_score_embedded(self):
        html = build_full(_make_report_data(posture=72.5))
        assert "72" in html  # rounded in SVG text

    def test_posture_score_ring_svg(self):
        html = build_full(_make_report_data(posture=55.0))
        assert "<svg" in html
        assert "stroke-dashoffset" in html

    def test_rule_names_embedded(self):
        html = build_full(_make_report_data())
        for i in range(3):
            assert f"Rule {i}" in html

    def test_techniques_embedded(self):
        html = build_full(_make_report_data())
        assert "T1059.004" in html
        assert "T1003.001" in html

    def test_lint_scores_embedded(self):
        html = build_full(_make_report_data())
        # Scores 90, 75, 60 should appear
        assert "90" in html
        assert "75" in html

    def test_gap_list_present(self):
        html = build_full(_make_report_data(n_gaps=3))
        assert "Priority" in html
        assert "Gap Technique" in html

    def test_gap_list_empty_message(self):
        html = build_full(_make_report_data(n_gaps=0))
        assert "No gaps found" in html

    def test_siem_query_snippets_present(self):
        html = build_full(_make_report_data())
        assert "opensearch" in html
        assert "splunk" in html
        assert "Image:bash_0" in html

    def test_query_copy_button(self):
        html = build_full(_make_report_data())
        assert "copy-btn" in html
        assert "copyQuery" in html

    def test_no_queries_message(self):
        data = _make_report_data()
        for r in data.rules:
            r.queries = {}
            r.query_errors = {}
        html = build_full(data)
        assert "No SIEM queries" in html

    def test_lint_findings_embedded(self):
        html = build_full(_make_report_data())
        assert "DV-L001" in html
        assert "Missing ATT&amp;CK tag" in html  # & is HTML-escaped in rendered output

    def test_timestamp_embedded(self):
        html = build_full(_make_report_data())
        assert "2024-06-05T12:00:00Z" in html

    def test_rules_dir_embedded(self):
        html = build_full(_make_report_data())
        assert "/tmp/rules" in html


class TestBuildFullHeatmap:
    def test_heatmap_absent_when_no_kb(self):
        html = build_full(_make_report_data(kb=False))
        assert "dv intel update" in html
        assert 'id="panel-' not in html  # tac panel divs only rendered when KB is available

    def test_heatmap_present_with_kb(self):
        html = build_full(_make_report_data(kb=True))
        assert "tac-tab" in html
        assert "cell-covered" in html

    def test_covered_cell_class(self):
        html = build_full(_make_report_data(kb=True))
        assert "cell-covered" in html

    def test_gap_high_cell_class(self):
        html = build_full(_make_report_data(kb=True))
        assert "cell-gap-high" in html

    def test_partial_cell_class(self):
        html = build_full(_make_report_data(kb=True))
        assert "cell-partial" in html

    def test_tactic_tabs_js(self):
        html = build_full(_make_report_data(kb=True))
        assert "showTac" in html
        assert "function showTac" in html

    def test_tactic_names_in_tabs(self):
        html = build_full(_make_report_data(kb=True))
        assert "Execution" in html
        assert "Impact" in html


# ── Score color logic ──────────────────────────────────────────────────────────

class TestScoreColor:
    def test_green_high_score(self):
        from detection_validator.reporters.html import _score_color
        assert _score_color(80) == "#4ade80"

    def test_amber_medium_score(self):
        from detection_validator.reporters.html import _score_color
        assert _score_color(55) == "#f59e0b"

    def test_red_low_score(self):
        from detection_validator.reporters.html import _score_color
        assert _score_color(20) == "#f87171"

    def test_boundary_70(self):
        from detection_validator.reporters.html import _score_color
        assert _score_color(70) == "#4ade80"

    def test_boundary_40(self):
        from detection_validator.reporters.html import _score_color
        assert _score_color(40) == "#f59e0b"


# ── write_report ──────────────────────────────────────────────────────────────


class TestWriteReport:
    def test_creates_file(self, tmp_path):
        out = tmp_path / "reports" / "report.html"
        write_report(_make_report_data(), out)
        assert out.exists()

    def test_creates_parent_dirs(self, tmp_path):
        out = tmp_path / "deep" / "nested" / "report.html"
        write_report(_make_report_data(), out)
        assert out.exists()

    def test_file_content_is_html(self, tmp_path):
        out = tmp_path / "report.html"
        write_report(_make_report_data(), out)
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_file_encoding_utf8(self, tmp_path):
        out = tmp_path / "report.html"
        data = _make_report_data()
        data.rules[0].name = "Règle d'accès — naïve"
        write_report(data, out)
        content = out.read_text(encoding="utf-8")
        assert "Règle" in content


# ── gather_report_data ────────────────────────────────────────────────────────


class TestGatherReportData:
    def test_basic_structure(self, tmp_path):
        rd = _make_rules_dir(tmp_path)
        data = gather_report_data(rd)
        assert isinstance(data, ReportData)
        assert data.posture_score >= 0
        assert data.posture_score <= 100
        assert len(data.rules) == 3

    def test_rules_have_lint_scores(self, tmp_path):
        rd = _make_rules_dir(tmp_path)
        data = gather_report_data(rd)
        for r in data.rules:
            assert 0 <= r.lint_score <= 100

    def test_orphan_rule_has_no_techniques(self, tmp_path):
        rd = _make_rules_dir(tmp_path)
        data = gather_report_data(rd)
        orphan = next((r for r in data.rules if "orphan" in r.path or not r.techniques), None)
        assert orphan is not None

    def test_covered_techniques_populated(self, tmp_path):
        rd = _make_rules_dir(tmp_path, {"lsass.yml": _SIGMA_LSASS})
        data = gather_report_data(rd)
        assert "T1003.001" in data.covered_techniques

    def test_no_external_kb_required(self, tmp_path):
        rd = _make_rules_dir(tmp_path)
        # Must complete without raising even if KB is absent
        data = gather_report_data(rd)
        assert data is not None

    def test_empty_rules_dir(self, tmp_path):
        rd = tmp_path / "empty"
        rd.mkdir()
        data = gather_report_data(rd)
        assert data.rules == []
        assert data.posture_score == 0.0

    def test_generated_at_is_iso(self, tmp_path):
        rd = _make_rules_dir(tmp_path)
        data = gather_report_data(rd)
        assert "T" in data.generated_at and "Z" in data.generated_at

    def test_rules_dir_recorded(self, tmp_path):
        rd = _make_rules_dir(tmp_path)
        data = gather_report_data(rd)
        assert str(rd) == data.rules_dir

    def test_queries_attempted(self, tmp_path):
        rd = _make_rules_dir(tmp_path, {"lsass.yml": _SIGMA_LSASS})
        data = gather_report_data(rd)
        rule = data.rules[0]
        # Either queries or errors present — generate_queries never returns empty list
        assert rule.queries or rule.query_errors

    def test_findings_captured(self, tmp_path):
        rd = _make_rules_dir(tmp_path, {"orphan.yml": _SIGMA_NO_ATTACK})
        data = gather_report_data(rd)
        rule = data.rules[0]
        # DV-L001: missing ATT&CK tag
        codes = [f["code"] for f in rule.lint_findings]
        assert "DV-L001" in codes


# ── Backward-compatible build() ───────────────────────────────────────────────


class TestBackwardCompatBuild:
    _RESULTS = [
        {
            "rule_id": "abc",
            "name": "My Rule",
            "techniques": ["T1059"],
            "siem": "opensearch",
            "hits": 5,
            "status": "likely_fires",
            "error": None,
            "samples": [],
        },
        {
            "rule_id": "def",
            "name": "Bad Rule",
            "techniques": ["T1003"],
            "siem": "elastic",
            "hits": 0,
            "status": "no_keyword_match",
            "error": None,
            "samples": [],
        },
    ]

    def test_returns_string(self):
        assert isinstance(build(self._RESULTS), str)

    def test_contains_rule_name(self):
        html = build(self._RESULTS)
        assert "My Rule" in html
        assert "Bad Rule" in html

    def test_contains_badge_likely_fires(self):
        html = build(self._RESULTS)
        assert "LIKELY FIRES" in html

    def test_contains_badge_no_keyword(self):
        html = build(self._RESULTS)
        assert "NO KEYWORD MATCH" in html

    def test_technique_cells(self):
        html = build(self._RESULTS)
        assert "T1059" in html
        assert "T1003" in html

    def test_no_external_requests(self):
        html = build(self._RESULTS)
        assert "cdn." not in html
        assert "https://" not in html

    def test_empty_results(self):
        html = build([])
        assert "<!DOCTYPE html>" in html
        assert "No results" in html

    def test_pass_rate_shown(self):
        html = build(self._RESULTS)
        assert "50%" in html


# ── CLI: dv report --html ─────────────────────────────────────────────────────


class TestCLIReportHtml:
    def test_html_flag_creates_file(self, tmp_path):
        from detection_validator.cli import main

        rd = _make_rules_dir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["report", "--html", "--rules-dir", str(rd)],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        report_path = Path("reports") / "detectval-report.html"
        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_html_flag_shows_posture_score(self, tmp_path):
        from detection_validator.cli import main

        rd = _make_rules_dir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["report", "--html", "--rules-dir", str(rd)])
        assert result.exit_code == 0
        assert "/100" in result.output

    def test_missing_rules_dir_exits_1(self, tmp_path):
        from detection_validator.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["report", "--html", "--rules-dir", str(tmp_path / "nonexistent")],
        )
        assert result.exit_code == 1

    def test_no_html_flag_reads_stdin(self, tmp_path):
        from detection_validator.cli import main
        import json

        results = [{"rule_id": "x", "name": "X", "techniques": [], "siem": "os",
                    "hits": 0, "status": "likely_fires", "error": None, "samples": []}]
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["report", "--format", "html", "--output", str(tmp_path / "out.html")],
            input=json.dumps(results),
        )
        assert result.exit_code == 0
        assert (tmp_path / "out.html").exists()
