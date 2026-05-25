"""
Tests for the six newly implemented CLI commands:
  dv migrate, dv badge, dv deploy, dv watch, dv siem, dv agent

Uses Click's CliRunner so commands run in-process with no subprocess
overhead. HTTP-calling commands are tested with unittest.mock.patch.
"""
from __future__ import annotations

import json
import re
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from detection_validator.cli import main
from detection_validator.normalizer.schema import (
    CanonicalDetection,
    DetectionFormat,
    DetectionLogic,
    MitreTechnique,
    Severity,
    ValidationStatus,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_SIGMA_DIR = Path(__file__).parents[3] / "examples" / "detections" / "sigma"
_LOG4SHELL = str(_SIGMA_DIR / "log4shell_jndi_injection.yml")
_NMAP = str(_SIGMA_DIR / "network_scan_nmap.yml")

runner = CliRunner()


def _detection_jsonl(
    *,
    technique_id: str = "T1190",
    tactic: str = "initial-access",
    status: ValidationStatus = ValidationStatus.PASSED,
    severity: Severity = Severity.HIGH,
    n: int = 1,
) -> str:
    """Return a JSONL string with `n` minimal CanonicalDetection objects."""
    lines = []
    for i in range(n):
        d = CanonicalDetection(
            name=f"Rule {i}",
            description="test",
            detection_logic=DetectionLogic(
                raw="", language="sigma",
                normalized_conditions=[], field_references=[],
            ),
            log_sources=[],
            mitre_techniques=[MitreTechnique(technique_id=technique_id, tactic=tactic)],
            severity=severity,
            source_format=DetectionFormat.SIGMA,
            validation_status=status,
        )
        lines.append(d.model_dump_json())
    return "\n".join(lines)


def _mock_urlopen(status: int = 200, body: bytes = b"{}"):
    """Return a context-manager mock that urllib.request.urlopen can be patched with."""
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return MagicMock(return_value=resp)


# ── dv migrate ────────────────────────────────────────────────────────────────

class TestMigrate:

    def test_sigma_to_kql_produces_kql(self) -> None:
        result = runner.invoke(main, ["migrate", "sigma", "kql", "--rules", _LOG4SHELL])
        assert result.exit_code == 0
        assert "technique:" in result.output

    def test_sigma_to_kql_includes_technique_ids(self) -> None:
        result = runner.invoke(main, ["migrate", "sigma", "kql", "--rules", _LOG4SHELL])
        assert "T1190" in result.output or "T1059" in result.output

    def test_sigma_to_splunk_produces_savedsearches_conf(self) -> None:
        result = runner.invoke(main, ["migrate", "sigma", "splunk", "--rules", _LOG4SHELL])
        assert result.exit_code == 0
        assert "search = index=dv-telemetry" in result.output

    def test_sigma_to_splunk_includes_rule_name(self) -> None:
        result = runner.invoke(main, ["migrate", "sigma", "splunk", "--rules", _LOG4SHELL])
        assert "Log4Shell" in result.output

    def test_sigma_to_splunk_includes_severity(self) -> None:
        result = runner.invoke(main, ["migrate", "sigma", "splunk", "--rules", _LOG4SHELL])
        assert "alert.severity" in result.output

    def test_sigma_to_sigma_round_trip_produces_yaml(self) -> None:
        result = runner.invoke(main, ["migrate", "sigma", "sigma", "--rules", _LOG4SHELL])
        assert result.exit_code == 0
        assert "title:" in result.output
        assert "detection:" in result.output

    def test_sigma_to_sigma_preserves_tags(self) -> None:
        result = runner.invoke(main, ["migrate", "sigma", "sigma", "--rules", _LOG4SHELL])
        assert "attack." in result.output

    def test_invalid_target_format_exits_1(self) -> None:
        result = runner.invoke(main, ["migrate", "sigma", "elastic", "--rules", _LOG4SHELL])
        assert result.exit_code == 1
        assert "not supported" in result.output.lower() or "not supported" in (result.stderr or "")

    def test_migrates_directory_of_rules(self) -> None:
        result = runner.invoke(main, ["migrate", "sigma", "kql", "--rules", str(_SIGMA_DIR)])
        assert result.exit_code == 0
        # Should have processed multiple rules
        assert result.output.count("technique:") >= 2

    def test_output_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "out.kql"
        result = runner.invoke(
            main, ["migrate", "sigma", "kql", "--rules", _LOG4SHELL, "-o", str(out)]
        )
        assert result.exit_code == 0
        assert out.exists()
        assert "technique:" in out.read_text()

    def test_no_rules_found_exits_1(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        result = runner.invoke(main, ["migrate", "sigma", "kql", "--rules", str(empty_dir)])
        assert result.exit_code == 1


# ── dv badge ─────────────────────────────────────────────────────────────────

class TestBadge:

    def test_json_format_returns_valid_json(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "corpus.jsonl"
        jsonl.write_text(_detection_jsonl(status=ValidationStatus.PASSED))
        result = runner.invoke(main, ["badge", "-d", str(jsonl), "--format", "json", "-o", "-"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "coverage_pct" in data
        assert "covered_techniques" in data
        assert "total_techniques" in data

    def test_json_reports_100_when_all_passed(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "corpus.jsonl"
        jsonl.write_text(_detection_jsonl(status=ValidationStatus.PASSED))
        result = runner.invoke(main, ["badge", "-d", str(jsonl), "--format", "json", "-o", "-"])
        data = json.loads(result.output)
        assert data["coverage_pct"] == 100.0

    def test_json_reports_zero_when_none_passed(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "corpus.jsonl"
        jsonl.write_text(_detection_jsonl(status=ValidationStatus.FAILED))
        result = runner.invoke(main, ["badge", "-d", str(jsonl), "--format", "json", "-o", "-"])
        data = json.loads(result.output)
        assert data["coverage_pct"] == 0.0
        assert data["color"] == "red"

    def test_json_color_green_at_high_coverage(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "corpus.jsonl"
        # 3 rules all passed with different techniques → coverage 100%
        lines = []
        for tid in ["T1190", "T1059", "T1046"]:
            d = CanonicalDetection(
                name=f"Rule {tid}", description="",
                detection_logic=DetectionLogic(raw="", language="sigma",
                                               normalized_conditions=[], field_references=[]),
                log_sources=[],
                mitre_techniques=[MitreTechnique(technique_id=tid, tactic="execution")],
                severity=Severity.MED, source_format=DetectionFormat.SIGMA,
                validation_status=ValidationStatus.PASSED,
            )
            lines.append(d.model_dump_json())
        jsonl.write_text("\n".join(lines))
        result = runner.invoke(main, ["badge", "-d", str(jsonl), "--format", "json", "-o", "-"])
        data = json.loads(result.output)
        assert data["color"] == "brightgreen"

    def test_svg_format_produces_svg(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "corpus.jsonl"
        jsonl.write_text(_detection_jsonl())
        out = tmp_path / "badge.svg"
        result = runner.invoke(main, ["badge", "-d", str(jsonl), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        svg = out.read_text()
        assert "<svg" in svg
        assert "</svg>" in svg

    def test_svg_contains_label(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "corpus.jsonl"
        jsonl.write_text(_detection_jsonl())
        out = tmp_path / "badge.svg"
        runner.invoke(main, ["badge", "-d", str(jsonl), "--label", "My Coverage", "-o", str(out)])
        assert "My Coverage" in out.read_text()

    def test_svg_contains_coverage_fraction(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "corpus.jsonl"
        jsonl.write_text(_detection_jsonl(status=ValidationStatus.PASSED))
        out = tmp_path / "badge.svg"
        runner.invoke(main, ["badge", "-d", str(jsonl), "-o", str(out)])
        svg = out.read_text()
        # Should contain something like "1/1 (100%)"
        assert re.search(r"\d+/\d+", svg)

    def test_empty_corpus_exits_cleanly(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "empty.jsonl"
        jsonl.write_text("")
        result = runner.invoke(main, ["badge", "-d", str(jsonl), "--format", "json", "-o", "-"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["coverage_pct"] == 0.0
        assert data["total_techniques"] == 0


# ── dv deploy ────────────────────────────────────────────────────────────────

class TestDeploy:

    def test_dry_run_opensearch_lists_rules(self) -> None:
        result = runner.invoke(
            main,
            ["deploy", str(_SIGMA_DIR), "--siem", "opensearch", "--dry-run"],
            env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test123"},
        )
        assert result.exit_code == 0
        assert "dry run" in result.output.lower()
        assert "Log4Shell" in result.output

    def test_dry_run_shows_techniques(self) -> None:
        result = runner.invoke(
            main,
            ["deploy", _LOG4SHELL, "--siem", "opensearch", "--dry-run"],
            env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test123"},
        )
        assert "T1190" in result.output or "T1059" in result.output

    def test_dry_run_splunk_lists_rules(self) -> None:
        result = runner.invoke(
            main,
            ["deploy", str(_SIGMA_DIR), "--siem", "splunk", "--dry-run"],
            env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test123"},
        )
        assert result.exit_code == 0
        assert "dry run" in result.output.lower()

    def test_dry_run_deploy_reports_success_count(self) -> None:
        result = runner.invoke(
            main,
            ["deploy", str(_SIGMA_DIR), "--siem", "opensearch", "--dry-run"],
            env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test123"},
        )
        assert "succeeded" in result.output

    def test_missing_password_exits_1_for_opensearch(self) -> None:
        result = runner.invoke(
            main,
            ["deploy", _LOG4SHELL, "--siem", "opensearch"],
            env={},
        )
        assert result.exit_code == 1

    def test_no_rules_exits_1(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        result = runner.invoke(
            main,
            ["deploy", str(empty), "--siem", "opensearch", "--dry-run"],
            env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test123"},
        )
        assert result.exit_code == 1

    @patch("urllib.request.urlopen")
    def test_live_deploy_opensearch_posts_monitor(self, mock_open) -> None:
        mock_open.return_value = _mock_urlopen(
            status=201,
            body=json.dumps({"_id": "monitor-001", "monitor": {}}).encode(),
        )()
        result = runner.invoke(
            main,
            ["deploy", _LOG4SHELL, "--siem", "opensearch"],
            env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test123"},
        )
        assert result.exit_code == 0
        assert mock_open.called
        # Verify it tried to POST to the alerting endpoint
        call_args = mock_open.call_args
        req = call_args[0][0]
        assert "_alerting/monitors" in req.full_url

    @patch("urllib.request.urlopen")
    def test_live_deploy_reports_failure_on_http_error(self, mock_open) -> None:
        import urllib.error
        mock_open.side_effect = urllib.error.HTTPError(
            url="", code=403, msg="Forbidden", hdrs=None, fp=BytesIO(b"auth error")
        )
        result = runner.invoke(
            main,
            ["deploy", _LOG4SHELL, "--siem", "opensearch"],
            env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test123"},
        )
        assert result.exit_code == 0  # doesn't abort, reports failure
        assert "failed" in result.output.lower() or "✗" in result.output


# ── dv siem ───────────────────────────────────────────────────────────────────

class TestSiem:

    @patch("urllib.request.urlopen")
    def test_status_opensearch_success(self, mock_open) -> None:
        body = json.dumps({
            "name": "dv-opensearch",
            "version": {"number": "2.11.0"},
        }).encode()
        mock_open.return_value = _mock_urlopen(status=200, body=body)()
        result = runner.invoke(main, ["siem", "status", "--type", "opensearch"],
                               env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test"})
        assert result.exit_code == 0
        assert "2.11.0" in result.output
        assert "✓" in result.output

    @patch("urllib.request.urlopen")
    def test_status_opensearch_auth_failure_shows_warning(self, mock_open) -> None:
        import urllib.error
        mock_open.side_effect = urllib.error.HTTPError(
            url="", code=401, msg="Unauthorized", hdrs=None, fp=BytesIO(b"")
        )
        result = runner.invoke(main, ["siem", "status", "--type", "opensearch"],
                               env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "wrong"})
        assert result.exit_code == 0
        assert "auth" in result.output.lower() or "401" in result.output

    @patch("urllib.request.urlopen")
    def test_status_opensearch_unreachable(self, mock_open) -> None:
        mock_open.side_effect = OSError("Connection refused")
        result = runner.invoke(main, ["siem", "status", "--type", "opensearch"],
                               env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test"})
        assert result.exit_code == 0
        assert "✗" in result.output or "not reachable" in result.output.lower()

    @patch("urllib.request.urlopen")
    def test_status_splunk_success(self, mock_open) -> None:
        mock_open.return_value = _mock_urlopen(status=200, body=b"<html></html>")()
        result = runner.invoke(main, ["siem", "status", "--type", "splunk"])
        assert result.exit_code == 0
        assert "✓" in result.output

    @patch("urllib.request.urlopen")
    def test_test_command_shows_events(self, mock_open) -> None:
        hits_body = json.dumps({
            "hits": {
                "total": {"value": 42},
                "hits": [
                    {"_source": {"technique": "T1190", "key": "network_connect",
                                 "exe": "/usr/bin/curl", "uid": "33",
                                 "timestamp": "2024-01-01T00:00:00Z"}}
                ],
            }
        }).encode()
        mock_open.return_value = _mock_urlopen(status=200, body=hits_body)()
        result = runner.invoke(main, ["siem", "test", "--type", "opensearch"],
                               env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test"})
        assert result.exit_code == 0
        assert "42" in result.output
        assert "T1190" in result.output

    @patch("urllib.request.urlopen")
    def test_test_command_handles_empty_results(self, mock_open) -> None:
        body = json.dumps({"hits": {"total": {"value": 0}, "hits": []}}).encode()
        mock_open.return_value = _mock_urlopen(status=200, body=body)()
        result = runner.invoke(main, ["siem", "test"],
                               env={"OPENSEARCH_INITIAL_ADMIN_PASSWORD": "test"})
        assert result.exit_code == 0
        assert "0" in result.output

    def test_siem_help_shows_subcommands(self) -> None:
        result = runner.invoke(main, ["siem", "--help"])
        assert "status" in result.output
        assert "test" in result.output


# ── dv agent ─────────────────────────────────────────────────────────────────

class TestAgent:

    @patch("urllib.request.urlopen")
    def test_status_reachable(self, mock_open) -> None:
        body = json.dumps({"status": "ok", "version": "1.0.0"}).encode()
        mock_open.return_value = _mock_urlopen(status=200, body=body)()
        result = runner.invoke(main, ["agent", "status", "--port", "9098"])
        assert result.exit_code == 0
        assert "✓" in result.output
        assert "9098" in result.output

    @patch("urllib.request.urlopen")
    def test_status_shows_health_fields(self, mock_open) -> None:
        body = json.dumps({"status": "ok", "uptime": "3h"}).encode()
        mock_open.return_value = _mock_urlopen(status=200, body=body)()
        result = runner.invoke(main, ["agent", "status"])
        assert result.exit_code == 0
        assert "uptime" in result.output or "ok" in result.output

    @patch("urllib.request.urlopen")
    def test_status_unreachable_shows_error(self, mock_open) -> None:
        mock_open.side_effect = OSError("Connection refused")
        result = runner.invoke(main, ["agent", "status", "--port", "9098"])
        assert result.exit_code == 0
        assert "✗" in result.output or "not reachable" in result.output.lower()

    @patch("urllib.request.urlopen")
    def test_logs_shows_events(self, mock_open) -> None:
        events = [
            {"technique": "T1190", "key": "network_connect",
             "cmd_output": "curl exploit", "timestamp": "2024-01-01T00:00:00Z"},
        ]
        mock_open.return_value = _mock_urlopen(status=200, body=json.dumps(events).encode())()
        result = runner.invoke(main, ["agent", "logs", "--port", "9098"])
        assert result.exit_code == 0
        assert "T1190" in result.output

    @patch("urllib.request.urlopen")
    def test_logs_empty_shows_no_events_message(self, mock_open) -> None:
        mock_open.return_value = _mock_urlopen(status=200, body=b"[]")()
        result = runner.invoke(main, ["agent", "logs"])
        assert result.exit_code == 0
        assert "no events" in result.output.lower()

    @patch("urllib.request.urlopen")
    def test_logs_404_shows_helpful_tip(self, mock_open) -> None:
        import urllib.error
        mock_open.side_effect = urllib.error.HTTPError(
            url="", code=404, msg="Not Found", hdrs=None, fp=BytesIO(b"")
        )
        result = runner.invoke(main, ["agent", "logs"])
        assert result.exit_code == 0
        # Should suggest an alternative (OpenSearch or vagrant ssh)
        assert "opensearch" in result.output.lower() or "vagrant" in result.output.lower()

    @patch("urllib.request.urlopen")
    def test_logs_unreachable_shows_vagrant_tip(self, mock_open) -> None:
        mock_open.side_effect = OSError("Connection refused")
        result = runner.invoke(main, ["agent", "logs"])
        assert result.exit_code == 0
        assert "vagrant" in result.output.lower()

    def test_agent_help_shows_subcommands(self) -> None:
        result = runner.invoke(main, ["agent", "--help"])
        assert "status" in result.output
        assert "logs" in result.output


# ── dv watch ─────────────────────────────────────────────────────────────────

class TestWatch:

    def test_watch_help_shows_options(self) -> None:
        result = runner.invoke(main, ["watch", "--help"])
        assert result.exit_code == 0
        assert "--events" in result.output
        assert "--interval" in result.output
        assert "--siem" in result.output

    def test_watch_exits_on_keyboard_interrupt(self, tmp_path: Path) -> None:
        # Write one event file and one sigma rule so there's something to validate
        events = tmp_path / "events.jsonl"
        events.write_text(
            json.dumps({"technique": "T1190", "timestamp": "2099-01-01T00:00:00Z"}) + "\n"
        )
        # Patch time.sleep to raise KeyboardInterrupt immediately
        with patch("time.sleep", side_effect=KeyboardInterrupt):
            result = runner.invoke(
                main,
                ["watch", str(_SIGMA_DIR), "--events", str(events), "--interval", "1"],
            )
        # Should exit cleanly (exit code 0) after KeyboardInterrupt
        assert result.exit_code == 0
        assert "Stopped" in result.output or "stopped" in result.output.lower()


# ── CVE dedup fix ─────────────────────────────────────────────────────────────

class TestCveDedup:

    def test_cves_to_models_deduplicates_mixed_formats(self) -> None:
        from detection_validator.parsers.base import cves_to_models
        refs = cves_to_models(["cve.2021.44228", "CVE-2021-44228", "CVE-2021-44228"])
        assert len(refs) == 1
        assert refs[0].cve_id == "CVE-2021-44228"

    def test_cves_to_models_keeps_distinct_ids(self) -> None:
        from detection_validator.parsers.base import cves_to_models
        refs = cves_to_models(["CVE-2021-44228", "CVE-2021-34527"])
        assert len(refs) == 2
        ids = {r.cve_id for r in refs}
        assert ids == {"CVE-2021-44228", "CVE-2021-34527"}

    def test_sigma_ingest_produces_no_duplicate_cve_refs(self) -> None:
        from detection_validator.parsers.sigma import SigmaParser
        parser = SigmaParser()
        d = parser.parse_file(_SIGMA_DIR / "log4shell_jndi_injection.yml")
        cve_ids = [r.cve_id for r in d.cve_references]
        assert len(cve_ids) == len(set(cve_ids)), f"Duplicate CVE refs: {cve_ids}"

    def test_all_sigma_fixtures_have_no_duplicate_cve_refs(self) -> None:
        from detection_validator.parsers.sigma import SigmaParser
        parser = SigmaParser()
        for yml in _SIGMA_DIR.glob("*.yml"):
            d = parser.parse_file(yml)
            cve_ids = [r.cve_id for r in d.cve_references]
            assert len(cve_ids) == len(set(cve_ids)), \
                f"{yml.name}: duplicate CVE refs {cve_ids}"
