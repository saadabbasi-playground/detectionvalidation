"""Tests for validator/validate_live.py.

Covers:
  • VALIDATED_RECALL — rule fires on tagged attack events
  • MISSED            — telemetry present but rule query returns zero hits
  • NOT_VALIDATABLE   — source.ensure() raises NotAvailable
  • rule resolution   — load by path, load by UUID, not-found error
  • CLI smoke tests   — dv validate-live help; matching + non-matching rules
  • RECALL disclaimer — output must state this is not FP-rate testing

All OpenSearch calls and source.ensure() are mocked — tests run fully offline.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from detection_validator.normalizer.schema import (
    CanonicalDetection,
    DetectionFormat,
    DetectionLogic,
    MitreTechnique,
    Severity,
)
from detection_validator.telemetry.base import NotAvailable, TelemetryBatch, TelemetryEvent
from detection_validator.validator.validate_live import (
    LiveValidationResult,
    RecallVerdict,
    TechniqueResult,
    _run_os_query,
    resolve_rule,
    validate_live,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_LSASS_SIGMA = """\
title: LSASS Memory Dump via Task Manager
id: b3c5e9a1-72f4-4c9e-b8d3-125e4f6a7c8d
status: stable
description: Detects LSASS memory dump creation.
author: Security Operations
date: 2022/11/10
tags:
    - attack.credential-access
    - attack.T1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection_target:
        TargetImage|endswith: '\\lsass.exe'
    selection_type:
        GrantedAccess|contains:
            - '0x1FFFFF'
            - '0x1010'
            - '0x143A'
    filter_defender:
        SourceImage|startswith:
            - 'C:\\ProgramData\\Microsoft\\Windows Defender'
    condition: selection_target and selection_type and not filter_defender
falsepositives:
    - AV solutions
level: critical
"""

# A syntactically valid rule whose conditions will never match LSASS events
_MISS_SIGMA = """\
title: Totally Different Rule That Will Not Match
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: experimental
description: Looks for a very specific string that doesn't appear in OTRF data.
tags:
    - attack.credential-access
    - attack.T1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'xyzzy-nonexistent-string-99999'
    condition: selection
level: low
"""

_REPLAY_BATCH = TelemetryBatch(
    technique_id="T1003.001",
    source_name="otrf:lsass.json",
    fidelity="replay",
    events=[
        TelemetryEvent(
            technique_id="T1003.001",
            source_fidelity="replay",
            timestamp=__import__("datetime").datetime(2021, 9, 12, 14, 23, 1,
                                                     tzinfo=__import__("datetime").timezone.utc),
            EventID=10,
            Channel="Microsoft-Windows-Sysmon/Operational",
            Image=r"C:\Windows\System32\powershell.exe",
            CommandLine='powershell -c "Invoke-Mimikatz"',
            User="WORKSTATION01\\Administrator",
            extra={
                "GrantedAccess": "0x1010",
                "TargetImage": r"C:\Windows\system32\lsass.exe",
            },
        )
    ],
)


def _make_detection(sigma_yaml: str) -> CanonicalDetection:
    from detection_validator.parsers.sigma import SigmaParser

    parser = SigmaParser()
    return parser.parse(sigma_yaml)


def _mock_source(batch: TelemetryBatch | None = None, error: str | None = None):
    """Return a mock TelemetrySource that returns *batch* or raises NotAvailable."""
    src = MagicMock()
    src.describe.return_value = MagicMock(name="replay", fidelity="replay",
                                          supported_platforms=["windows"])
    if error:
        src.ensure.side_effect = NotAvailable(error)
    else:
        src.ensure.return_value = batch or _REPLAY_BATCH
    return src


# ── TechniqueResult / LiveValidationResult ────────────────────────────────────

class TestTechniqueResult:
    def test_defaults(self):
        tr = TechniqueResult(technique_id="T1003.001", verdict=RecallVerdict.VALIDATED_RECALL)
        assert tr.event_count == 0
        assert tr.match_count == 0
        assert tr.sample_events == []
        assert tr.not_available_reason is None

    def test_verdict_values(self):
        assert RecallVerdict.VALIDATED_RECALL == "VALIDATED_RECALL"
        assert RecallVerdict.MISSED == "MISSED"
        assert RecallVerdict.NOT_VALIDATABLE == "NOT_VALIDATABLE"


class TestLiveValidationResult:
    def _result(self, verdicts: list[RecallVerdict]) -> LiveValidationResult:
        r = LiveValidationResult(
            rule_id="x", rule_name="X", source_name="replay",
            platform="windows", os_url="http://localhost:9200",
        )
        for i, v in enumerate(verdicts):
            r.technique_results.append(
                TechniqueResult(technique_id=f"T{1000+i}", verdict=v)
            )
        return r

    def test_overall_validated_recall_wins(self):
        r = self._result([RecallVerdict.MISSED, RecallVerdict.VALIDATED_RECALL])
        assert r.overall_verdict == RecallVerdict.VALIDATED_RECALL

    def test_overall_missed_over_not_validatable(self):
        r = self._result([RecallVerdict.NOT_VALIDATABLE, RecallVerdict.MISSED])
        assert r.overall_verdict == RecallVerdict.MISSED

    def test_overall_not_validatable_when_only_option(self):
        r = self._result([RecallVerdict.NOT_VALIDATABLE])
        assert r.overall_verdict == RecallVerdict.NOT_VALIDATABLE

    def test_empty_results_not_validatable(self):
        r = LiveValidationResult(
            rule_id="x", rule_name="X", source_name="s",
            platform="windows", os_url="http://localhost:9200",
        )
        assert r.overall_verdict == RecallVerdict.NOT_VALIDATABLE


# ── resolve_rule ──────────────────────────────────────────────────────────────

class TestResolveRule:
    def test_load_by_path(self, tmp_path):
        rule_file = tmp_path / "lsass.yml"
        rule_file.write_text(_LSASS_SIGMA)
        det, path = resolve_rule(str(rule_file), tmp_path)
        assert det.name == "LSASS Memory Dump via Task Manager"
        assert path == rule_file

    def test_load_by_uuid(self, tmp_path):
        rule_file = tmp_path / "lsass.yml"
        rule_file.write_text(_LSASS_SIGMA)
        det, path = resolve_rule("b3c5e9a1-72f4-4c9e-b8d3-125e4f6a7c8d", tmp_path)
        assert det.name == "LSASS Memory Dump via Task Manager"

    def test_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError) as exc_info:
            resolve_rule("no-such-rule-at-all", tmp_path)
        assert "not found" in str(exc_info.value).lower()

    def test_returns_path_for_file(self, tmp_path):
        rule_file = tmp_path / "lsass.yml"
        rule_file.write_text(_LSASS_SIGMA)
        _, path = resolve_rule(str(rule_file), tmp_path)
        assert path is not None
        assert path.exists()


# ── _run_os_query ─────────────────────────────────────────────────────────────

class TestRunOsQuery:
    def _mock_urlopen(self, body: dict):
        """Context manager that pretends to be urlopen."""
        import io
        from unittest.mock import patch, MagicMock

        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.read.return_value = json.dumps(body).encode()
        return patch("urllib.request.urlopen", return_value=resp)

    def test_returns_count_and_samples(self):
        body = {
            "hits": {
                "total": {"value": 3},
                "hits": [
                    {"_source": {"Image": "powershell.exe"}},
                    {"_source": {"Image": "cmd.exe"}},
                ],
            }
        }
        with self._mock_urlopen(body):
            total, samples = _run_os_query(
                "telemetry-replay-t1003-001",
                {"term": {"technique_id": "T1003.001"}},
                "http://localhost:9200",
            )
        assert total == 3
        assert len(samples) == 2

    def test_404_returns_zero(self):
        import urllib.error

        with patch("urllib.request.urlopen",
                   side_effect=urllib.error.HTTPError(None, 404, "Not Found", {}, None)):
            total, samples = _run_os_query("missing-index", {}, "http://localhost:9200")
        assert total == 0
        assert samples == []

    def test_connection_error_raises(self):
        import urllib.error

        with patch("urllib.request.urlopen",
                   side_effect=urllib.error.URLError("connection refused")):
            with pytest.raises(ConnectionError) as exc_info:
                _run_os_query("idx", {}, "http://localhost:9200")
        assert "not reachable" in str(exc_info.value).lower()


# ── validate_live — VALIDATED_RECALL ─────────────────────────────────────────

class TestValidatedRecall:
    """Rule compiles to an OS query that returns hits on the replay events."""

    def _run(self, sigma_yaml: str, hit_count: int, tmp_path: Path) -> LiveValidationResult:
        rule_file = tmp_path / "rule.yml"
        rule_file.write_text(sigma_yaml)

        detection = _make_detection(sigma_yaml)
        source = _mock_source()

        os_body = {
            "hits": {
                "total": {"value": hit_count},
                "hits": [{"_source": {"technique_id": "T1003.001"}}] * min(hit_count, 3),
            }
        }

        with (
            patch("detection_validator.telemetry.indexer.bulk_index", return_value=(1, [])),
            patch("detection_validator.validator.validate_live._run_os_query",
                  return_value=(hit_count, [{"Image": "powershell.exe"}] * min(hit_count, 3))),
        ):
            return validate_live(
                detection=detection,
                source=source,
                rule_path=rule_file,
                platform="windows",
                os_url="http://localhost:9200",
            )

    def test_verdict_validated_recall(self, tmp_path):
        result = self._run(_LSASS_SIGMA, hit_count=3, tmp_path=tmp_path)
        assert result.overall_verdict == RecallVerdict.VALIDATED_RECALL

    def test_technique_populated(self, tmp_path):
        result = self._run(_LSASS_SIGMA, hit_count=3, tmp_path=tmp_path)
        tr = result.technique_results[0]
        assert tr.technique_id == "T1003.001"

    def test_match_count_stored(self, tmp_path):
        result = self._run(_LSASS_SIGMA, hit_count=3, tmp_path=tmp_path)
        assert result.technique_results[0].match_count == 3

    def test_event_count_stored(self, tmp_path):
        result = self._run(_LSASS_SIGMA, hit_count=3, tmp_path=tmp_path)
        assert result.technique_results[0].event_count == len(_REPLAY_BATCH)

    def test_index_name_correct(self, tmp_path):
        result = self._run(_LSASS_SIGMA, hit_count=3, tmp_path=tmp_path)
        assert result.technique_results[0].index == "telemetry-replay-t1003-001"

    def test_sample_events_present(self, tmp_path):
        result = self._run(_LSASS_SIGMA, hit_count=3, tmp_path=tmp_path)
        assert len(result.technique_results[0].sample_events) > 0


# ── validate_live — MISSED ────────────────────────────────────────────────────

class TestMissed:
    """Telemetry is present but the rule's query returns zero hits."""

    def _run(self, sigma_yaml: str, tmp_path: Path) -> LiveValidationResult:
        rule_file = tmp_path / "rule.yml"
        rule_file.write_text(sigma_yaml)
        detection = _make_detection(sigma_yaml)
        source = _mock_source()

        with (
            patch("detection_validator.telemetry.indexer.bulk_index", return_value=(1, [])),
            patch("detection_validator.validator.validate_live._run_os_query",
                  return_value=(0, [])),
        ):
            return validate_live(
                detection=detection,
                source=source,
                rule_path=rule_file,
                platform="windows",
                os_url="http://localhost:9200",
            )

    def test_verdict_missed(self, tmp_path):
        result = self._run(_MISS_SIGMA, tmp_path=tmp_path)
        assert result.overall_verdict == RecallVerdict.MISSED

    def test_match_count_is_zero(self, tmp_path):
        result = self._run(_MISS_SIGMA, tmp_path=tmp_path)
        assert result.technique_results[0].match_count == 0

    def test_event_count_nonzero(self, tmp_path):
        # events were indexed even though query missed
        result = self._run(_MISS_SIGMA, tmp_path=tmp_path)
        assert result.technique_results[0].event_count > 0

    def test_no_reason_set(self, tmp_path):
        result = self._run(_MISS_SIGMA, tmp_path=tmp_path)
        assert result.technique_results[0].not_available_reason is None


# ── validate_live — NOT_VALIDATABLE ──────────────────────────────────────────

class TestNotValidatable:
    def _run(self, reason: str, tmp_path: Path) -> LiveValidationResult:
        rule_file = tmp_path / "rule.yml"
        rule_file.write_text(_LSASS_SIGMA)
        detection = _make_detection(_LSASS_SIGMA)
        source = _mock_source(error=reason)

        return validate_live(
            detection=detection,
            source=source,
            rule_path=rule_file,
            platform="windows",
            os_url="http://localhost:9200",
        )

    def test_verdict_not_validatable(self, tmp_path):
        result = self._run("No OTRF dataset found for T1003.001", tmp_path)
        assert result.overall_verdict == RecallVerdict.NOT_VALIDATABLE

    def test_reason_stored(self, tmp_path):
        result = self._run("agent not running", tmp_path)
        tr = result.technique_results[0]
        assert tr.not_available_reason == "agent not running"

    def test_event_count_zero(self, tmp_path):
        result = self._run("no data", tmp_path)
        assert result.technique_results[0].event_count == 0

    def test_index_still_set(self, tmp_path):
        result = self._run("no data", tmp_path)
        # Index name is always computed, even when verdict is NOT_VALIDATABLE
        assert result.technique_results[0].index == "telemetry-replay-t1003-001"


# ── validate_live — rule with no techniques ───────────────────────────────────

class TestNoTechniques:
    _NO_TECH_SIGMA = """\
title: No Technique Rule
id: 11111111-2222-3333-4444-555555555555
status: experimental
tags: []
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: something
    condition: selection
level: low
"""

    def test_not_validatable_when_no_techniques(self, tmp_path):
        rule_file = tmp_path / "rule.yml"
        rule_file.write_text(self._NO_TECH_SIGMA)
        detection = _make_detection(self._NO_TECH_SIGMA)
        source = _mock_source()

        result = validate_live(
            detection=detection,
            source=source,
            rule_path=rule_file,
            platform="windows",
            os_url="http://localhost:9200",
        )
        assert result.overall_verdict == RecallVerdict.NOT_VALIDATABLE
        tr = result.technique_results[0]
        assert "no att&ck" in tr.not_available_reason.lower() or "no technique" in tr.not_available_reason.lower()


# ── validate_live — indexing failure ─────────────────────────────────────────

class TestIndexingFailure:
    def test_not_validatable_when_opensearch_down(self, tmp_path):
        rule_file = tmp_path / "rule.yml"
        rule_file.write_text(_LSASS_SIGMA)
        detection = _make_detection(_LSASS_SIGMA)
        source = _mock_source()

        with patch("detection_validator.telemetry.indexer.bulk_index",
                   side_effect=IndexError("OpenSearch not reachable")):
            result = validate_live(
                detection=detection,
                source=source,
                rule_path=rule_file,
                platform="windows",
                os_url="http://localhost:9200",
            )

        assert result.overall_verdict == RecallVerdict.NOT_VALIDATABLE
        assert "opensearch" in result.technique_results[0].not_available_reason.lower()


# ── CLI smoke tests ───────────────────────────────────────────────────────────

class TestCLIValidateLive:
    def test_help_text_contains_recall_disclaimer(self):
        from click.testing import CliRunner
        from detection_validator.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["validate-live", "--help"])
        assert result.exit_code == 0
        assert "RECALL" in result.output
        assert "false-positive" in result.output.lower()

    def test_validated_recall_exit_0(self, tmp_path):
        from click.testing import CliRunner
        from detection_validator.cli import main

        rule_file = tmp_path / "lsass.yml"
        rule_file.write_text(_LSASS_SIGMA)

        with (
            patch("detection_validator.telemetry.base.registry") as mock_reg,
            patch("detection_validator.telemetry.indexer.bulk_index", return_value=(1, [])),
            patch("detection_validator.validator.validate_live._run_os_query",
                  return_value=(3, [{"Image": "powershell.exe"}])),
        ):
            mock_reg.get.return_value = _mock_source()
            runner = CliRunner()
            result = runner.invoke(main, [
                "validate-live",
                "--rule-id", str(rule_file),
                "--source", "replay",
            ])

        assert result.exit_code == 0, result.output
        assert "VALIDATED_RECALL" in result.output

    def test_not_validatable_exit_1(self, tmp_path):
        from click.testing import CliRunner
        from detection_validator.cli import main

        rule_file = tmp_path / "lsass.yml"
        rule_file.write_text(_LSASS_SIGMA)

        with (
            patch("detection_validator.telemetry.base.registry") as mock_reg,
        ):
            mock_reg.get.return_value = _mock_source(error="No dataset found")
            runner = CliRunner()
            result = runner.invoke(main, [
                "validate-live",
                "--rule-id", str(rule_file),
                "--source", "replay",
            ])

        assert result.exit_code == 1

    def test_missed_exit_0(self, tmp_path):
        """MISSED is informative, not a CLI error — exit 0."""
        from click.testing import CliRunner
        from detection_validator.cli import main

        rule_file = tmp_path / "miss.yml"
        rule_file.write_text(_MISS_SIGMA)

        with (
            patch("detection_validator.telemetry.base.registry") as mock_reg,
            patch("detection_validator.telemetry.indexer.bulk_index", return_value=(1, [])),
            patch("detection_validator.validator.validate_live._run_os_query",
                  return_value=(0, [])),
        ):
            mock_reg.get.return_value = _mock_source()
            runner = CliRunner()
            result = runner.invoke(main, [
                "validate-live",
                "--rule-id", str(rule_file),
                "--source", "replay",
            ])

        assert result.exit_code == 0, result.output
        assert "MISSED" in result.output

    def test_output_contains_dashboards_url(self, tmp_path):
        from click.testing import CliRunner
        from detection_validator.cli import main

        rule_file = tmp_path / "lsass.yml"
        rule_file.write_text(_LSASS_SIGMA)

        with (
            patch("detection_validator.telemetry.base.registry") as mock_reg,
            patch("detection_validator.telemetry.indexer.bulk_index", return_value=(1, [])),
            patch("detection_validator.validator.validate_live._run_os_query",
                  return_value=(1, [])),
        ):
            mock_reg.get.return_value = _mock_source()
            runner = CliRunner()
            result = runner.invoke(main, [
                "validate-live",
                "--rule-id", str(rule_file),
                "--source", "replay",
            ])

        assert "5601" in result.output  # Dashboards URL

    def test_output_contains_recall_disclaimer(self, tmp_path):
        from click.testing import CliRunner
        from detection_validator.cli import main

        rule_file = tmp_path / "lsass.yml"
        rule_file.write_text(_LSASS_SIGMA)

        with (
            patch("detection_validator.telemetry.base.registry") as mock_reg,
            patch("detection_validator.telemetry.indexer.bulk_index", return_value=(1, [])),
            patch("detection_validator.validator.validate_live._run_os_query",
                  return_value=(1, [])),
        ):
            mock_reg.get.return_value = _mock_source()
            runner = CliRunner()
            result = runner.invoke(main, [
                "validate-live",
                "--rule-id", str(rule_file),
            ])

        # The output must explicitly mention this is RECALL, not FP rate
        out_lower = result.output.lower()
        assert "recall" in out_lower
        assert "false-positive" in out_lower or "false positive" in out_lower

    def test_unknown_rule_id_exits_1(self, tmp_path):
        from click.testing import CliRunner
        from detection_validator.cli import main

        runner = CliRunner()
        result = runner.invoke(main, [
            "validate-live",
            "--rule-id", "nonexistent-uuid-here",
            "--rules-dir", str(tmp_path),
        ])
        assert result.exit_code == 1
