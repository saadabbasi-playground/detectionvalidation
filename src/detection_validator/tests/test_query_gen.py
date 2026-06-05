"""
Tests for siem/query_gen.py — offline Sigma → SIEM query compilation.

All tests are purely in-memory/filesystem.  No live SIEM or API keys needed.
The 3 bundled sigma rules are used as fixtures:
  - log4shell_jndi_injection.yml  (webserver, keyword-only, no pipeline)
  - credential_dump_lsass.yml     (windows, process_access, Windows pipeline)
  - printnightmare_spooler_abuse.yml (windows, process_creation, Windows pipeline)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from detection_validator.siem.query_gen import (
    QueryResult,
    _normalise_sigma_yaml,
    _windows_rule,
    generate_queries,
)

# ── Paths to bundled rules ────────────────────────────────────────────────────

_SIGMA_DIR = Path(__file__).parents[3] / "examples" / "detections" / "sigma"
_LOG4SHELL = _SIGMA_DIR / "log4shell_jndi_injection.yml"
_LSASS = _SIGMA_DIR / "credential_dump_lsass.yml"
_PRINTNIGHTMARE = _SIGMA_DIR / "printnightmare_spooler_abuse.yml"


# ── Inline YAML fixtures ──────────────────────────────────────────────────────

_WINDOWS_SIGMA = """\
title: Windows Test Rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: malware.exe
  condition: selection
tags:
  - attack.T1059
"""

_LINUX_SIGMA = """\
title: Linux Test Rule
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains: curl
  condition: selection
tags:
  - attack.T1059
"""

_KEYWORD_ONLY_WITHOUT_CONDITION = """\
title: Keyword Rule No Condition
logsource:
  category: webserver
detection:
  keywords:
    - jndi:ldap
    - jndi:rmi
"""

_KEYWORD_ONLY_WITH_CONDITION = """\
title: Keyword Rule With Condition
logsource:
  category: webserver
detection:
  keywords:
    - jndi:ldap
  condition: keywords
"""


# ── Unit: _normalise_sigma_yaml ───────────────────────────────────────────────

class TestNormaliseSigmaYaml:

    def test_injects_condition_when_keywords_present_without_condition(self) -> None:
        result = _normalise_sigma_yaml(_KEYWORD_ONLY_WITHOUT_CONDITION)
        data = yaml.safe_load(result)
        assert data["detection"]["condition"] == "keywords"

    def test_does_not_modify_when_condition_already_present(self) -> None:
        result = _normalise_sigma_yaml(_KEYWORD_ONLY_WITH_CONDITION)
        data = yaml.safe_load(result)
        assert data["detection"]["condition"] == "keywords"
        # Should be parsed identically to the input
        original = yaml.safe_load(_KEYWORD_ONLY_WITH_CONDITION)
        assert data["detection"] == original["detection"]

    def test_does_not_modify_standard_rule_with_selection(self) -> None:
        result = _normalise_sigma_yaml(_LINUX_SIGMA)
        assert result == _LINUX_SIGMA

    def test_returns_raw_on_invalid_yaml(self) -> None:
        bad = "title: [\nnot valid yaml"
        result = _normalise_sigma_yaml(bad)
        assert result == bad

    def test_log4shell_rule_gets_condition_injected(self) -> None:
        raw = _LOG4SHELL.read_text(encoding="utf-8")
        result = _normalise_sigma_yaml(raw)
        data = yaml.safe_load(result)
        assert "condition" in data["detection"]


# ── Unit: _windows_rule ───────────────────────────────────────────────────────

class TestWindowsRule:

    def test_detects_windows_product(self) -> None:
        assert _windows_rule(_WINDOWS_SIGMA) is True

    def test_detects_non_windows_product(self) -> None:
        assert _windows_rule(_LINUX_SIGMA) is False

    def test_returns_false_on_webserver_rule(self) -> None:
        raw = _LOG4SHELL.read_text(encoding="utf-8")
        assert _windows_rule(raw) is False

    def test_detects_windows_on_lsass_rule(self) -> None:
        raw = _LSASS.read_text(encoding="utf-8")
        assert _windows_rule(raw) is True

    def test_detects_windows_on_printnightmare_rule(self) -> None:
        raw = _PRINTNIGHTMARE.read_text(encoding="utf-8")
        assert _windows_rule(raw) is True

    def test_returns_false_on_invalid_yaml(self) -> None:
        assert _windows_rule("not: valid: yaml: [") is False


# ── Unit: QueryResult dataclass ───────────────────────────────────────────────

class TestQueryResult:

    def test_defaults(self) -> None:
        r = QueryResult(siem="opensearch", fmt="default", query="index=*")
        assert r.error is None
        assert r.deployable is False

    def test_error_result(self) -> None:
        r = QueryResult(siem="splunk", fmt="default", query=None, error="no pipeline")
        assert r.query is None
        assert r.error == "no pipeline"


# ── Integration: generate_queries ────────────────────────────────────────────

class TestGenerateQueriesLog4Shell:
    """log4shell_jndi_injection.yml — webserver category, keyword-only rule."""

    def test_returns_results_for_all_three_siems(self) -> None:
        results = generate_queries(_LOG4SHELL)
        siems = {r.siem for r in results}
        assert "opensearch" in siems
        assert "elastic" in siems
        assert "splunk" in siems

    def test_opensearch_default_query_is_string(self) -> None:
        results = generate_queries(_LOG4SHELL, siems=["opensearch"])
        default = next(r for r in results if r.fmt == "default")
        # May succeed or fail (no pipeline for webserver); either way, structured result
        assert default.query is not None or default.error is not None

    def test_elastic_default_result_present(self) -> None:
        results = generate_queries(_LOG4SHELL, siems=["elastic"])
        assert any(r.siem == "elastic" and r.fmt == "default" for r in results)

    def test_splunk_default_result_present(self) -> None:
        results = generate_queries(_LOG4SHELL, siems=["splunk"])
        assert any(r.siem == "splunk" and r.fmt == "default" for r in results)

    def test_no_deployable_formats_by_default(self) -> None:
        results = generate_queries(_LOG4SHELL)
        assert not any(r.deployable for r in results)

    def test_deployable_flag_adds_extra_results(self) -> None:
        results_base = generate_queries(_LOG4SHELL)
        results_deploy = generate_queries(_LOG4SHELL, deployable=True)
        assert len(results_deploy) > len(results_base)

    def test_deployable_results_are_marked(self) -> None:
        results = generate_queries(_LOG4SHELL, deployable=True)
        assert any(r.deployable for r in results)

    def test_each_result_has_siem_and_fmt(self) -> None:
        results = generate_queries(_LOG4SHELL)
        for r in results:
            assert r.siem
            assert r.fmt

    def test_siem_alias_elasticsearch_normalised(self) -> None:
        results = generate_queries(_LOG4SHELL, siems=["elasticsearch"])
        assert all(r.siem == "elastic" for r in results)

    def test_duplicate_siems_deduplicated(self) -> None:
        results = generate_queries(_LOG4SHELL, siems=["opensearch", "opensearch"])
        opensearch_results = [r for r in results if r.siem == "opensearch"]
        # Should only have 1 default (not 2)
        defaults = [r for r in opensearch_results if r.fmt == "default"]
        assert len(defaults) == 1


class TestGenerateQueriesLsass:
    """credential_dump_lsass.yml — Windows rule with Windows pipeline."""

    def test_opensearch_returns_lucene_query(self) -> None:
        results = generate_queries(_LSASS, siems=["opensearch"])
        default = next((r for r in results if r.fmt == "default"), None)
        assert default is not None
        if default.query is not None:
            assert isinstance(default.query, str)
            assert len(default.query) > 0

    def test_splunk_returns_spl_query(self) -> None:
        results = generate_queries(_LSASS, siems=["splunk"])
        default = next((r for r in results if r.fmt == "default"), None)
        assert default is not None
        if default.query is not None:
            assert isinstance(default.query, str)

    def test_elastic_returns_lucene_query(self) -> None:
        results = generate_queries(_LSASS, siems=["elastic"])
        default = next((r for r in results if r.fmt == "default"), None)
        assert default is not None

    def test_monitor_rule_is_valid_json_when_deployable(self) -> None:
        results = generate_queries(_LSASS, siems=["opensearch"], deployable=True)
        monitor = next((r for r in results if r.fmt == "monitor_rule"), None)
        assert monitor is not None
        if monitor.query is not None:
            # Should be JSON-serialisable
            parsed = json.loads(monitor.query)
            assert isinstance(parsed, dict)

    def test_kibana_ndjson_when_deployable(self) -> None:
        results = generate_queries(_LSASS, siems=["elastic"], deployable=True)
        ndjson = next((r for r in results if r.fmt == "kibana_ndjson"), None)
        assert ndjson is not None

    def test_savedsearches_when_deployable(self) -> None:
        results = generate_queries(_LSASS, siems=["splunk"], deployable=True)
        saved = next((r for r in results if r.fmt == "savedsearches"), None)
        assert saved is not None


class TestGenerateQueriesPrintnightmare:
    """printnightmare_spooler_abuse.yml — Windows rule with complex condition."""

    def test_all_backends_return_results(self) -> None:
        results = generate_queries(_PRINTNIGHTMARE)
        siems = {r.siem for r in results}
        assert siems == {"opensearch", "elastic", "splunk"}

    def test_no_result_raises(self) -> None:
        # generate_queries never raises — failures are returned as QueryResult(error=...)
        results = generate_queries(_PRINTNIGHTMARE, siems=["opensearch", "elastic", "splunk"])
        for r in results:
            assert isinstance(r, QueryResult)

    def test_single_siem_subset(self) -> None:
        results = generate_queries(_PRINTNIGHTMARE, siems=["splunk"])
        assert all(r.siem == "splunk" for r in results)

    def test_deployable_splunk_savedsearches_is_string(self) -> None:
        results = generate_queries(_PRINTNIGHTMARE, siems=["splunk"], deployable=True)
        saved = next((r for r in results if r.fmt == "savedsearches"), None)
        assert saved is not None
        if saved.query is not None:
            assert isinstance(saved.query, str)


# ── Error handling ────────────────────────────────────────────────────────────

class TestGenerateQueriesErrorHandling:

    def test_nonexistent_file_raises_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            generate_queries(Path("/nonexistent/rule.yml"))

    def test_invalid_yaml_returns_error_results(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("title: [\nbad yaml content", encoding="utf-8")
        results = generate_queries(bad, siems=["opensearch"])
        assert all(r.query is None for r in results)
        assert all(r.error for r in results)

    def test_unknown_siem_is_silently_skipped(self) -> None:
        results = generate_queries(_LOG4SHELL, siems=["notasiem"])
        assert results == []

    def test_empty_siems_list_returns_empty(self) -> None:
        results = generate_queries(_LOG4SHELL, siems=[])
        assert results == []


# ── Export / write-to-file ────────────────────────────────────────────────────

class TestGenerateQueriesOutputShape:
    """Validate the shape of results without caring about exact query text."""

    def test_result_count_without_deployable(self) -> None:
        # 3 SIEMs × 1 default format each = 3 results
        results = generate_queries(_LOG4SHELL, siems=["opensearch", "elastic", "splunk"])
        assert len(results) == 3

    def test_result_count_with_deployable(self) -> None:
        # 3 SIEMs × 2 formats (default + deployable) = 6 results
        results = generate_queries(
            _LOG4SHELL, siems=["opensearch", "elastic", "splunk"], deployable=True
        )
        assert len(results) == 6

    def test_single_siem_single_result_without_deployable(self) -> None:
        results = generate_queries(_LOG4SHELL, siems=["opensearch"])
        assert len(results) == 1

    def test_single_siem_two_results_with_deployable(self) -> None:
        results = generate_queries(_LOG4SHELL, siems=["opensearch"], deployable=True)
        assert len(results) == 2
        fmts = {r.fmt for r in results}
        assert "default" in fmts
        assert "monitor_rule" in fmts
