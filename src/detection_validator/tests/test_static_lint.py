"""Tests for validator/static_lint.py — structural rule quality checks."""
from __future__ import annotations

import pytest

from detection_validator.normalizer.schema import (
    CanonicalDetection,
    DetectionFormat,
    DetectionLogic,
    MitreTechnique,
    Severity,
)
from detection_validator.validator.linter import LintSeverity
from detection_validator.validator.static_lint import StaticLinter


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_detection(
    name: str = "Test Rule",
    description: str = "",
    techniques: list[str] | None = None,
    raw_logic: str = "",
) -> CanonicalDetection:
    techs = []
    for tid in (techniques or []):
        base = tid.split(".")[0]
        sub = tid if "." in tid else None
        techs.append(MitreTechnique(technique_id=base, sub_technique_id=sub, tactic="execution"))
    return CanonicalDetection(
        name=name,
        description=description,
        detection_logic=DetectionLogic(
            raw=raw_logic,
            language="sigma",
            normalized_conditions=[],
            field_references=[],
        ),
        log_sources=[],
        mitre_techniques=techs,
        severity=Severity.MED,
        source_format=DetectionFormat.SIGMA,
    )


_GOOD_SIGMA = """\
title: Log4Shell JNDI Injection
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains: jndi:ldap
  condition: selection
tags:
  - attack.T1190
"""

_NO_LOGSOURCE = """\
title: Missing Logsource
detection:
  selection:
    CommandLine|contains: jndi
  condition: selection
"""

_NO_DETECTION = """\
title: No Detection Block
logsource:
  product: linux
"""

_NO_CONDITION = """\
title: No Condition
logsource:
  product: linux
detection:
  selection:
    CommandLine|contains: jndi
"""

_BROAD_WILDCARD = """\
title: Broad Wildcard
logsource:
  product: linux
detection:
  selection:
    CommandLine: '*'
  condition: selection
tags:
  - attack.T1059
"""

_NETWORK_RULE = """\
title: DNS Beaconing
logsource:
  category: dns
detection:
  selection:
    QueryName|endswith: evil.com
  condition: selection
tags:
  - attack.T1071
"""

_BEHAVIOURAL_RULE = """\
title: Anomalous Process Baseline Deviation
logsource:
  product: linux
detection:
  selection:
    CommandLine|contains: unusual
  condition: selection
tags:
  - attack.T1059
"""


# ── Linter instantiation ───────────────────────────────────────────────────────

@pytest.fixture
def linter() -> StaticLinter:
    return StaticLinter()


# ── DV-L001: Missing ATT&CK tag ───────────────────────────────────────────────

class TestMissingAttackTag:

    def test_no_techniques_no_raw_tag_triggers_error(self, linter: StaticLinter) -> None:
        det = _make_detection(raw_logic=_NO_LOGSOURCE)
        findings = linter.lint(det)
        codes = [f.code for f in findings]
        assert "DV-L001" in codes

    def test_technique_in_schema_suppresses_l001(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_GOOD_SIGMA)
        findings = linter.lint(det)
        codes = [f.code for f in findings]
        assert "DV-L001" not in codes

    def test_attack_tag_in_raw_yaml_suppresses_l001(self, linter: StaticLinter) -> None:
        # technique comes from the raw tags, not the schema
        det = _make_detection(raw_logic=_GOOD_SIGMA)
        findings = linter.lint(det)
        codes = [f.code for f in findings]
        assert "DV-L001" not in codes

    def test_l001_severity_is_error(self, linter: StaticLinter) -> None:
        det = _make_detection(raw_logic=_NO_LOGSOURCE)
        findings = linter.lint(det)
        l001 = next(f for f in findings if f.code == "DV-L001")
        assert l001.severity == LintSeverity.ERROR


# ── DV-L002: Missing logsource ────────────────────────────────────────────────

class TestMissingLogsource:

    def test_no_logsource_triggers_warning(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_NO_LOGSOURCE)
        findings = linter.lint(det)
        codes = [f.code for f in findings]
        assert "DV-L002" in codes

    def test_good_rule_no_l002(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_GOOD_SIGMA)
        findings = linter.lint(det)
        codes = [f.code for f in findings]
        assert "DV-L002" not in codes

    def test_l002_severity_is_warning(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_NO_LOGSOURCE)
        findings = linter.lint(det)
        l002 = next(f for f in findings if f.code == "DV-L002")
        assert l002.severity == LintSeverity.WARNING

    def test_no_raw_yaml_skips_l002(self, linter: StaticLinter) -> None:
        # Rule has no detection_logic.raw at all — can't check logsource
        det = _make_detection(techniques=["T1190"])
        findings = linter.lint(det)
        codes = [f.code for f in findings]
        assert "DV-L002" not in codes


# ── DV-L003: No detection fields ─────────────────────────────────────────────

class TestNoDetectionFields:

    def test_missing_detection_block_triggers_l003(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_NO_DETECTION)
        findings = linter.lint(det)
        codes = [f.code for f in findings]
        assert "DV-L003" in codes

    def test_good_rule_no_l003(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_GOOD_SIGMA)
        findings = linter.lint(det)
        assert "DV-L003" not in [f.code for f in findings]

    def test_l003_severity_is_error(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_NO_DETECTION)
        findings = linter.lint(det)
        l003 = next((f for f in findings if f.code == "DV-L003"), None)
        if l003:
            assert l003.severity == LintSeverity.ERROR


# ── DV-L004: Missing condition ────────────────────────────────────────────────

class TestMissingCondition:

    def test_no_condition_triggers_l004(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_NO_CONDITION)
        findings = linter.lint(det)
        codes = [f.code for f in findings]
        assert "DV-L004" in codes

    def test_good_rule_no_l004(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_GOOD_SIGMA)
        findings = linter.lint(det)
        assert "DV-L004" not in [f.code for f in findings]

    def test_l004_severity_is_error(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_NO_CONDITION)
        findings = linter.lint(det)
        l004 = next((f for f in findings if f.code == "DV-L004"), None)
        if l004:
            assert l004.severity == LintSeverity.ERROR


# ── DV-L005: Overly broad wildcard ────────────────────────────────────────────

class TestBroadWildcard:

    def test_bare_star_triggers_l005(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1059"], raw_logic=_BROAD_WILDCARD)
        findings = linter.lint(det)
        codes = [f.code for f in findings]
        assert "DV-L005" in codes

    def test_l005_severity_is_warning(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1059"], raw_logic=_BROAD_WILDCARD)
        findings = linter.lint(det)
        l005 = next(f for f in findings if f.code == "DV-L005")
        assert l005.severity == LintSeverity.WARNING

    def test_specific_value_no_l005(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_GOOD_SIGMA)
        findings = linter.lint(det)
        assert "DV-L005" not in [f.code for f in findings]


# ── DV-L006: NETWORK_RULE ─────────────────────────────────────────────────────

class TestNetworkRule:

    def test_dns_category_triggers_network_rule(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1071"], raw_logic=_NETWORK_RULE)
        findings = linter.lint(det)
        codes = [f.code for f in findings]
        assert "NETWORK_RULE" in codes

    def test_network_rule_severity_is_info(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1071"], raw_logic=_NETWORK_RULE)
        findings = linter.lint(det)
        nr = next(f for f in findings if f.code == "NETWORK_RULE")
        assert nr.severity == LintSeverity.INFO

    def test_process_rule_no_network_rule(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_GOOD_SIGMA)
        findings = linter.lint(det)
        assert "NETWORK_RULE" not in [f.code for f in findings]


# ── DV-L007: BEHAVIOURAL_RULE ─────────────────────────────────────────────────

class TestBehaviouralRule:

    def test_anomal_keyword_in_name_triggers_behavioural(self, linter: StaticLinter) -> None:
        det = _make_detection(
            name="Anomalous Process Baseline Deviation",
            techniques=["T1059"],
            raw_logic=_BEHAVIOURAL_RULE,
        )
        findings = linter.lint(det)
        assert "BEHAVIOURAL_RULE" in [f.code for f in findings]

    def test_behavioural_keyword_in_description(self, linter: StaticLinter) -> None:
        det = _make_detection(
            name="Suspicious Command",
            description="Detects behavioral anomaly in process execution",
            techniques=["T1059"],
            raw_logic=_GOOD_SIGMA,
        )
        findings = linter.lint(det)
        assert "BEHAVIOURAL_RULE" in [f.code for f in findings]

    def test_normal_rule_no_behavioural(self, linter: StaticLinter) -> None:
        det = _make_detection(
            name="Log4Shell JNDI Injection",
            techniques=["T1190"],
            raw_logic=_GOOD_SIGMA,
        )
        findings = linter.lint(det)
        assert "BEHAVIOURAL_RULE" not in [f.code for f in findings]

    def test_behavioural_severity_is_info(self, linter: StaticLinter) -> None:
        det = _make_detection(
            name="Threshold Spike Detector",
            techniques=["T1059"],
            raw_logic=_BEHAVIOURAL_RULE,
        )
        findings = linter.lint(det)
        br = next(f for f in findings if f.code == "BEHAVIOURAL_RULE")
        assert br.severity == LintSeverity.INFO


# ── Score calculation ─────────────────────────────────────────────────────────

class TestScore:

    def test_clean_rule_scores_100(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_GOOD_SIGMA)
        findings = linter.lint(det)
        assert linter.score(findings) == 100

    def test_empty_findings_scores_100(self, linter: StaticLinter) -> None:
        assert linter.score([]) == 100

    def test_missing_attack_tag_deducts_20(self, linter: StaticLinter) -> None:
        det = _make_detection(raw_logic=_NO_LOGSOURCE)
        findings = linter.lint(det)
        score = linter.score(findings)
        assert score <= 80

    def test_score_never_goes_below_zero(self, linter: StaticLinter) -> None:
        # Rule that triggers every error check
        det = _make_detection()   # no techniques, no raw logic
        findings = linter.lint(det)
        # Inject extra findings to simulate a very bad rule
        from detection_validator.validator.linter import LintFinding, LintSeverity
        extra = [
            LintFinding(rule_id="x", severity=LintSeverity.ERROR, code="DV-L001", message=""),
            LintFinding(rule_id="x", severity=LintSeverity.ERROR, code="DV-L002", message=""),
            LintFinding(rule_id="x", severity=LintSeverity.ERROR, code="DV-L003", message=""),
            LintFinding(rule_id="x", severity=LintSeverity.ERROR, code="DV-L004", message=""),
            LintFinding(rule_id="x", severity=LintSeverity.WARNING, code="DV-L005", message=""),
            LintFinding(rule_id="x", severity=LintSeverity.WARNING, code="DV-L005", message=""),
        ]
        assert linter.score(extra) >= 0

    def test_wildcard_deduction_capped_at_15(self, linter: StaticLinter) -> None:
        from detection_validator.validator.linter import LintFinding, LintSeverity
        # 5 wildcard findings should deduct at most 15, not 50
        findings = [
            LintFinding(rule_id="x", severity=LintSeverity.WARNING, code="DV-L005", message="")
            for _ in range(5)
        ]
        score = linter.score(findings)
        assert score == 85   # 100 - 15

    def test_info_findings_do_not_affect_score(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1071"], raw_logic=_NETWORK_RULE)
        findings = linter.lint(det)
        score = linter.score(findings)
        # NETWORK_RULE is INFO — score should still be 100
        assert score == 100


# ── lint_all ──────────────────────────────────────────────────────────────────

class TestLintAll:

    def test_returns_dict_keyed_by_rule_id(self, linter: StaticLinter) -> None:
        d1 = _make_detection(name="Rule A", techniques=["T1190"], raw_logic=_GOOD_SIGMA)
        d2 = _make_detection(name="Rule B", raw_logic=_NO_LOGSOURCE)
        result = linter.lint_all([d1, d2])
        assert str(d1.id) in result
        assert str(d2.id) in result

    def test_clean_rule_has_no_error_findings(self, linter: StaticLinter) -> None:
        det = _make_detection(techniques=["T1190"], raw_logic=_GOOD_SIGMA)
        result = linter.lint_all([det])
        findings = result[str(det.id)]
        errors = [f for f in findings if f.severity == LintSeverity.ERROR]
        assert errors == []
