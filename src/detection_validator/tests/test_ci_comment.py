"""Tests for detection_validator.ci.comment — PR comment renderer.

All tests are offline (no network, no SIEM).  Each test covers a distinct
render case: clean, coverage change, lint drop, regression, gaps, no-KB,
no-base.
"""

from __future__ import annotations

import pytest

from detection_validator.ci.comment import _MARKER, render_comment


# ── Snapshot factories ────────────────────────────────────────────────────────


def _snap(
    *,
    rule_count: int = 5,
    covered: list[str] | None = None,
    avg_lint: float = 85.0,
    lint_results: list[dict] | None = None,
    gaps: list[dict] | None = None,
    gaps_available: bool = True,
) -> dict:
    return {
        "rule_count": rule_count,
        "covered_techniques": covered if covered is not None else ["T1059.001", "T1003.001"],
        "avg_lint_score": avg_lint,
        "lint_results": lint_results or [],
        "gaps": gaps or [],
        "gaps_available": gaps_available,
    }


def _rule(name: str = "Test Rule", score: int = 90, findings: list | None = None) -> dict:
    return {"name": name, "path": f"rules/{name.lower().replace(' ', '_')}.yml",
            "score": score, "findings": findings or []}


def _finding(severity: str = "warning", code: str = "DV-L002", message: str = "No logsource") -> dict:
    return {"severity": severity, "code": code, "message": message}


def _gap(tid: str = "T1053.005", name: str = "Scheduled Task",
         tactic: str = "execution", score: float = 80.0,
         reasons: list[str] | None = None) -> dict:
    return {
        "technique_id": tid, "name": name, "tactic": tactic,
        "score": score, "reasons": reasons or ["Used by 54 groups"],
    }


# ── Marker ────────────────────────────────────────────────────────────────────


class TestMarker:
    def test_marker_present(self):
        md = render_comment(_snap())
        assert _MARKER in md

    def test_marker_at_start(self):
        md = render_comment(_snap())
        assert md.startswith(_MARKER)


# ── Header ────────────────────────────────────────────────────────────────────


class TestHeader:
    def test_rule_count(self):
        md = render_comment(_snap(rule_count=9))
        assert "9" in md

    def test_coverage_count(self):
        md = render_comment(_snap(covered=["T1059.001", "T1003.001", "T1078"]))
        assert "3" in md

    def test_avg_lint_score(self):
        md = render_comment(_snap(avg_lint=78.0))
        assert "78" in md

    def test_green_emoji_high_score(self):
        md = render_comment(_snap(avg_lint=90.0))
        assert "🟢" in md

    def test_yellow_emoji_medium_score(self):
        md = render_comment(_snap(avg_lint=60.0))
        assert "🟡" in md

    def test_red_emoji_low_score(self):
        md = render_comment(_snap(avg_lint=30.0))
        assert "🔴" in md

    def test_coverage_delta_positive(self):
        head = _snap(covered=["T1059.001", "T1003.001", "T1078"])
        base = _snap(covered=["T1059.001", "T1003.001"])
        md = render_comment(head, base)
        assert "+1" in md

    def test_coverage_delta_negative(self):
        head = _snap(covered=["T1059.001"])
        base = _snap(covered=["T1059.001", "T1003.001"])
        md = render_comment(head, base)
        assert "-1" in md

    def test_avg_lint_delta_positive(self):
        head = _snap(avg_lint=90.0)
        base = _snap(avg_lint=80.0)
        md = render_comment(head, base)
        assert "+10" in md

    def test_avg_lint_delta_negative(self):
        head = _snap(avg_lint=70.0)
        base = _snap(avg_lint=85.0)
        md = render_comment(head, base)
        assert "-15" in md


# ── Coverage section ──────────────────────────────────────────────────────────


class TestCoverageSection:
    def test_no_section_when_no_base(self):
        md = render_comment(_snap())
        assert "Coverage Changes" not in md

    def test_no_section_when_identical(self):
        snap = _snap(covered=["T1059.001"])
        md = render_comment(snap, snap)
        assert "Coverage Changes" not in md

    def test_added_techniques_listed(self):
        head = _snap(covered=["T1059.001", "T1003.001", "T1078"])
        base = _snap(covered=["T1059.001", "T1003.001"])
        md = render_comment(head, base)
        assert "T1078" in md
        assert "Added" in md

    def test_lost_techniques_listed(self):
        head = _snap(covered=["T1059.001"])
        base = _snap(covered=["T1059.001", "T1003.001"])
        md = render_comment(head, base)
        assert "T1003.001" in md
        assert "Lost" in md

    def test_both_added_and_lost(self):
        head = _snap(covered=["T1059.001", "T1078"])
        base = _snap(covered=["T1059.001", "T1003.001"])
        md = render_comment(head, base)
        assert "T1078" in md
        assert "T1003.001" in md


# ── Lint section ──────────────────────────────────────────────────────────────


class TestLintSection:
    def test_all_pass_message(self):
        rules = [_rule("Rule A", 90), _rule("Rule B", 80)]
        md = render_comment(_snap(lint_results=rules), min_lint_score=70)
        assert "All rules pass" in md

    def test_low_score_rule_shown(self):
        rules = [_rule("Log4Shell", 60, [_finding("error", "DV-L001", "No ATT&CK tag")])]
        md = render_comment(_snap(lint_results=rules), min_lint_score=70)
        assert "Log4Shell" in md
        assert "60" in md
        assert "DV-L001" in md

    def test_rule_above_threshold_not_shown(self):
        rules = [_rule("Good Rule", 90)]
        md = render_comment(_snap(lint_results=rules), min_lint_score=70)
        assert "Good Rule" not in md or "All rules pass" in md

    def test_regression_vs_base(self):
        head_rules = [_rule("LSASS Dump", 65)]
        base_rules = [_rule("LSASS Dump", 85)]
        head = _snap(lint_results=head_rules)
        base = _snap(lint_results=base_rules)
        md = render_comment(head, base, min_lint_score=100)  # threshold catches everything
        assert "LSASS Dump" in md
        assert "Regressions" in md
        assert "85" in md
        assert "65" in md

    def test_regression_shows_delta(self):
        head_rules = [_rule("Rule X", 60)]
        base_rules = [_rule("Rule X", 85)]
        head = _snap(lint_results=head_rules)
        base = _snap(lint_results=base_rules)
        md = render_comment(head, base, min_lint_score=100)
        assert "-25" in md

    def test_no_regression_for_improved_rule(self):
        head_rules = [_rule("Rule X", 90)]
        base_rules = [_rule("Rule X", 70)]
        head = _snap(lint_results=head_rules)
        base = _snap(lint_results=base_rules)
        md = render_comment(head, base, min_lint_score=100)
        assert "Regressions" not in md

    def test_new_rule_not_regression(self):
        head_rules = [_rule("New Rule", 75)]
        base_rules: list[dict] = []
        head = _snap(lint_results=head_rules)
        base = _snap(lint_results=base_rules)
        md = render_comment(head, base, min_lint_score=100)
        assert "Regressions" not in md

    def test_multiple_findings_shown(self):
        findings = [
            _finding("error", "DV-L001", "No ATT&CK tag"),
            _finding("warning", "DV-L002", "No logsource"),
        ]
        rules = [_rule("Multi", 55, findings)]
        md = render_comment(_snap(lint_results=rules), min_lint_score=70)
        assert "DV-L001" in md
        assert "DV-L002" in md


# ── Gaps section ──────────────────────────────────────────────────────────────


class TestGapsSection:
    def test_no_kb_message(self):
        md = render_comment(_snap(gaps=[], gaps_available=False))
        assert "dv intel update" in md

    def test_no_gaps_clean_message(self):
        md = render_comment(_snap(gaps=[], gaps_available=True))
        assert "No high-priority gaps" in md

    def test_gap_technique_shown(self):
        md = render_comment(_snap(gaps=[_gap()]))
        assert "T1053.005" in md
        assert "Scheduled Task" in md

    def test_gap_tactic_shown(self):
        md = render_comment(_snap(gaps=[_gap(tactic="execution")]))
        assert "Execution" in md  # label mapping applied

    def test_gap_priority_score_shown(self):
        md = render_comment(_snap(gaps=[_gap(score=80.0)]))
        assert "80" in md

    def test_gap_reason_shown(self):
        md = render_comment(_snap(gaps=[_gap(reasons=["Used by 54 groups"])]))
        assert "54 groups" in md

    def test_top_n_respected(self):
        gaps = [_gap(f"T{1000 + i}", f"Gap {i}") for i in range(15)]
        md = render_comment(_snap(gaps=gaps), top_n_gaps=5)
        # Only first 5 shown
        assert "top 5" in md

    def test_multiple_gaps(self):
        gaps = [_gap("T1053.005", "Scheduled Task"), _gap("T1047", "WMI")]
        md = render_comment(_snap(gaps=gaps))
        assert "T1053.005" in md
        assert "T1047" in md

    def test_tactic_label_mapping(self):
        md = render_comment(_snap(gaps=[_gap(tactic="credential-access")]))
        assert "Credential Access" in md

    def test_unknown_tactic_shown_raw(self):
        md = render_comment(_snap(gaps=[_gap(tactic="some-new-tactic")]))
        assert "some-new-tactic" in md


# ── No-base (first run) ───────────────────────────────────────────────────────


class TestNoBase:
    def test_renders_without_error(self):
        md = render_comment(_snap())
        assert isinstance(md, str) and len(md) > 0

    def test_no_coverage_section(self):
        md = render_comment(_snap())
        assert "Coverage Changes" not in md

    def test_no_regressions_section(self):
        rules = [_rule("Rule X", 60)]
        md = render_comment(_snap(lint_results=rules))
        assert "Regressions" not in md


# ── Footer ────────────────────────────────────────────────────────────────────


class TestFooter:
    def test_footer_present(self):
        md = render_comment(_snap())
        assert "Run locally" in md

    def test_dv_lint_command(self):
        md = render_comment(_snap(), rules_dir="detections/")
        assert "dv lint detections/" in md

    def test_dv_gaps_command(self):
        md = render_comment(_snap())
        assert "dv gaps" in md


# ── Integration: full renders ─────────────────────────────────────────────────


class TestFullRenders:
    def test_clean_pr(self):
        """No issues, no regressions, no gaps."""
        head = _snap(
            covered=["T1059.001", "T1003.001"],
            avg_lint=90.0,
            lint_results=[_rule("Rule A", 95), _rule("Rule B", 88)],
            gaps=[],
            gaps_available=True,
        )
        base = _snap(
            covered=["T1059.001", "T1003.001"],
            avg_lint=90.0,
            lint_results=[_rule("Rule A", 95), _rule("Rule B", 88)],
            gaps=[],
            gaps_available=True,
        )
        md = render_comment(head, base, min_lint_score=70)
        assert "All rules pass" in md
        assert "No high-priority gaps" in md
        assert "Lost" not in md
        assert "Regressions" not in md

    def test_coverage_regression_pr(self):
        """Technique coverage dropped."""
        head = _snap(covered=["T1059.001"])
        base = _snap(covered=["T1059.001", "T1003.001", "T1078"])
        md = render_comment(head, base)
        assert "-2" in md
        assert "Lost" in md
        assert "T1003.001" in md
        assert "T1078" in md

    def test_quality_drop_pr(self):
        """Lint score fell below threshold."""
        head = _snap(lint_results=[_rule("Noisy Rule", 55, [_finding("error", "DV-L004", "No condition")])])
        md = render_comment(head, None, min_lint_score=70)
        assert "Noisy Rule" in md
        assert "55" in md
        assert "DV-L004" in md

    def test_full_pr_with_all_issues(self):
        """Coverage loss + lint drop + regression + gaps all appear."""
        head = _snap(
            covered=["T1059.001"],
            avg_lint=60.0,
            lint_results=[_rule("Bad Rule", 50, [_finding("error", "DV-L001")])],
            gaps=[_gap("T1053.005", "Scheduled Task", score=80.0)],
            gaps_available=True,
        )
        base = _snap(
            covered=["T1059.001", "T1003.001"],
            avg_lint=80.0,
            lint_results=[_rule("Bad Rule", 80)],
        )
        md = render_comment(head, base, min_lint_score=70)
        assert "Lost" in md
        assert "T1003.001" in md
        assert "Bad Rule" in md
        assert "T1053.005" in md
        assert "Regressions" in md

    def test_no_infrastructure_required(self):
        """Comment renders without any network or SIEM calls."""
        head = _snap(gaps_available=False)
        md = render_comment(head)
        assert "dv intel update" in md
        assert _MARKER in md

    def test_first_run_no_base(self):
        """First time the action runs — no base comparison."""
        head = _snap(
            rule_count=3,
            covered=["T1059.001"],
            avg_lint=78.0,
            gaps=[_gap()],
            gaps_available=True,
        )
        md = render_comment(head, None)
        assert "3" in md
        assert "78" in md
        assert "T1053.005" in md
        assert "Coverage Changes" not in md
        assert "Regressions" not in md
