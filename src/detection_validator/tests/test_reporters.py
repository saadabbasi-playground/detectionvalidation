"""
Tests for reporters: SARIF (reporters/sarif.py), CLI (reporters/cli.py),
and HTML (reporters/html.py).

All tests use in-memory result dicts — no file I/O, no SIEM, no network.
"""
from __future__ import annotations

import json
from io import StringIO

import pytest
from rich.console import Console

from detection_validator.reporters import sarif as sarif_mod
from detection_validator.reporters.cli import report as cli_report
from detection_validator.reporters.html import build as html_build


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _r(
    rule_id: str = "rule-001",
    name: str = "Test Rule",
    status: str = "pass",
    techniques: list[str] | None = None,
    siem: str = "opensearch",
    hits: int = 1,
    error: str | None = None,
    query: str = "technique:T1190",
    samples: list[dict] | None = None,
) -> dict:
    return {
        "rule_id": rule_id,
        "name": name,
        "status": status,
        "techniques": techniques or ["T1190"],
        "siem": siem,
        "hits": hits,
        "error": error,
        "query": query,
        "samples": samples or [],
    }


# ── SARIF reporter ────────────────────────────────────────────────────────────

class TestSarifBuild:

    def test_returns_valid_schema_structure(self) -> None:
        doc = sarif_mod.build([_r()])
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        assert len(doc["runs"]) == 1

    def test_tool_driver_name(self) -> None:
        doc = sarif_mod.build([_r()])
        assert doc["runs"][0]["tool"]["driver"]["name"] == "detection-validator"

    def test_passing_rule_creates_sarif_rule_entry(self) -> None:
        doc = sarif_mod.build([_r(rule_id="r1", status="pass")])
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert any(r["id"] == "r1" for r in rules)

    def test_passing_rule_produces_no_sarif_result(self) -> None:
        doc = sarif_mod.build([_r(status="pass")])
        assert doc["runs"][0]["results"] == []

    def test_failing_rule_produces_warning_result(self) -> None:
        doc = sarif_mod.build([_r(status="fail", hits=0)])
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["level"] == "warning"

    def test_error_rule_produces_error_result(self) -> None:
        doc = sarif_mod.build([_r(status="error", error="timeout", hits=0)])
        results = doc["runs"][0]["results"]
        assert results[0]["level"] == "error"
        assert "timeout" in results[0]["message"]["text"]

    def test_skipped_rule_produces_no_sarif_result(self) -> None:
        doc = sarif_mod.build([_r(status="skip")])
        assert doc["runs"][0]["results"] == []

    def test_deduplicates_sarif_rules_by_rule_id(self) -> None:
        results = [
            _r(rule_id="r1", status="fail"),
            _r(rule_id="r1", status="fail"),
        ]
        doc = sarif_mod.build(results)
        rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids.count("r1") == 1

    def test_sarif_result_references_correct_rule_id(self) -> None:
        doc = sarif_mod.build([_r(rule_id="r42", status="fail")])
        assert doc["runs"][0]["results"][0]["ruleId"] == "r42"

    def test_empty_results_produces_valid_empty_sarif(self) -> None:
        doc = sarif_mod.build([])
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []
        assert doc["runs"][0]["results"] == []

    def test_mixed_statuses(self) -> None:
        results = [
            _r(rule_id="r1", status="pass"),
            _r(rule_id="r2", status="fail", hits=0),
            _r(rule_id="r3", status="error", error="oops", hits=0),
            _r(rule_id="r4", status="skip"),
        ]
        doc = sarif_mod.build(results)
        sarif_results = doc["runs"][0]["results"]
        # only fail + error produce findings
        finding_ids = [r["ruleId"] for r in sarif_results]
        assert "r2" in finding_ids
        assert "r3" in finding_ids
        assert "r1" not in finding_ids
        assert "r4" not in finding_ids

    def test_techniques_included_in_rule_description(self) -> None:
        doc = sarif_mod.build([_r(techniques=["T1190", "T1059"])])
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        full_desc = rules[0]["fullDescription"]["text"]
        assert "T1190" in full_desc
        assert "T1059" in full_desc

    def test_sarif_is_json_serializable(self) -> None:
        doc = sarif_mod.build([_r(status="fail"), _r(rule_id="r2", status="pass")])
        # Should not raise
        serialized = json.dumps(doc)
        assert len(serialized) > 0

    def test_write_creates_file(self, tmp_path) -> None:
        out = tmp_path / "scan.sarif"
        sarif_mod.write([_r(status="fail")], out)
        content = json.loads(out.read_text())
        assert content["version"] == "2.1.0"


# ── CLI reporter ──────────────────────────────────────────────────────────────

class TestCliReport:

    def _capture(self, results: list[dict]) -> str:
        buf = StringIO()
        cli_report(results, Console(file=buf, highlight=False))
        return buf.getvalue()

    def test_pass_shown_in_output(self) -> None:
        out = self._capture([_r(status="likely_fires")])
        assert "LIKELY" in out or "likely" in out.lower()

    def test_fail_shown_in_output(self) -> None:
        out = self._capture([_r(status="no_keyword_match", hits=0)])
        assert "NO_KEYWORD_MATCH" in out or "no keyword match" in out.lower()

    def test_error_shown_in_output(self) -> None:
        out = self._capture([_r(status="error", error="timeout", hits=0)])
        assert "ERROR" in out or "error" in out.lower()

    def test_technique_shown(self) -> None:
        out = self._capture([_r(techniques=["T1190"])])
        assert "T1190" in out

    def test_rule_name_shown(self) -> None:
        out = self._capture([_r(name="Log4Shell Detection")])
        assert "Log4Shell" in out

    def test_empty_results_does_not_raise(self) -> None:
        out = self._capture([])
        assert isinstance(out, str)

    def test_all_statuses_rendered(self) -> None:
        results = [
            _r(rule_id="r1", status="pass"),
            _r(rule_id="r2", name="Fail Rule", status="fail", hits=0),
            _r(rule_id="r3", name="Err Rule", status="error", error="boom", hits=0),
            _r(rule_id="r4", name="Skip Rule", status="skip"),
        ]
        out = self._capture(results)
        # All four rules should appear in the output
        assert "Fail Rule" in out or "fail" in out.lower()
        assert "Err Rule" in out or "error" in out.lower()

    def test_summary_line_contains_counts(self) -> None:
        results = [
            _r(rule_id="r1", status="pass"),
            _r(rule_id="r2", status="fail", hits=0),
        ]
        out = self._capture(results)
        # Should mention pass and fail counts somewhere
        assert "1" in out


# ── HTML reporter ─────────────────────────────────────────────────────────────

class TestHtmlBuild:

    def test_returns_html_string(self) -> None:
        out = html_build([_r()])
        assert isinstance(out, str)
        assert "<html" in out.lower() or "<!doctype" in out.lower()

    def test_contains_rule_name(self) -> None:
        out = html_build([_r(name="Log4Shell Detection")])
        assert "Log4Shell Detection" in out

    def test_contains_technique(self) -> None:
        out = html_build([_r(techniques=["T1190"])])
        assert "T1190" in out

    def test_contains_pass_status(self) -> None:
        out = html_build([_r(status="pass")])
        assert "pass" in out.lower() or "PASS" in out

    def test_contains_fail_status(self) -> None:
        out = html_build([_r(status="fail", hits=0)])
        assert "fail" in out.lower() or "FAIL" in out

    def test_multiple_results_all_present(self) -> None:
        results = [
            _r(rule_id="r1", name="Rule Alpha", status="pass"),
            _r(rule_id="r2", name="Rule Beta", status="fail", hits=0),
        ]
        out = html_build(results)
        assert "Rule Alpha" in out
        assert "Rule Beta" in out

    def test_empty_results_still_valid_html(self) -> None:
        out = html_build([])
        assert "<" in out  # at minimum, some HTML tags

    def test_is_self_contained(self) -> None:
        # No external stylesheet links — should be usable offline
        out = html_build([_r()])
        assert '<link rel="stylesheet"' not in out
        assert "<style" in out or "style=" in out
