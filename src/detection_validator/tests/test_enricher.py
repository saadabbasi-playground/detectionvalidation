"""
Tests for enricher/engine.py.

All knowledge-base calls use lightweight MagicMock stubs — no network,
no local cache files required.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from detection_validator.enricher.engine import (
    EnrichmentResult,
    _cvss_to_severity,
    _enrich_cve_refs,
    _enrich_severity,
    _enrich_techniques,
    _extract_cve_tags,
    _technique_url,
    enrich_detection,
)
from detection_validator.normalizer.schema import (
    CanonicalDetection,
    CVEReference,
    DetectionFormat,
    DetectionLogic,
    MitreTechnique,
    Severity,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_detection(
    *,
    techniques: list[MitreTechnique] | None = None,
    cve_refs: list[CVEReference] | None = None,
    tags: list[str] | None = None,
    severity: Severity = Severity.MED,
) -> CanonicalDetection:
    return CanonicalDetection(
        name="Test Detection",
        description="A test detection for unit tests",
        detection_logic=DetectionLogic(raw="process where true", language="eql",
                                       normalized_conditions=[], field_references=[]),
        log_sources=[],
        mitre_techniques=techniques or [],
        cve_references=cve_refs or [],
        tags=tags or [],
        severity=severity,
        source_format=DetectionFormat.SIGMA,
    )


def _mock_attack_kb(technique_id: str, name: str, tactic: str) -> MagicMock:
    att = MagicMock()
    att.name = name
    att.tactic = tactic
    kb = MagicMock()
    kb.get_technique.return_value = att
    return kb


def _mock_cve_kb(cve_id: str, cvss: float, desc: str) -> MagicMock:
    record = MagicMock()
    record.cvss_score = cvss
    record.description = desc
    kb = MagicMock()
    kb.get.return_value = record
    return kb


# ── Unit: helpers ─────────────────────────────────────────────────────────────

class TestHelpers:

    def test_technique_url_base(self) -> None:
        assert _technique_url("T1190") == "https://attack.mitre.org/techniques/T1190/"

    def test_technique_url_subtechnique(self) -> None:
        assert _technique_url("T1059.004") == "https://attack.mitre.org/techniques/T1059/004/"

    def test_cvss_critical(self) -> None:
        assert _cvss_to_severity(9.0) == Severity.CRITICAL
        assert _cvss_to_severity(10.0) == Severity.CRITICAL

    def test_cvss_high(self) -> None:
        assert _cvss_to_severity(7.0) == Severity.HIGH
        assert _cvss_to_severity(8.8) == Severity.HIGH

    def test_cvss_med(self) -> None:
        assert _cvss_to_severity(4.0) == Severity.MED
        assert _cvss_to_severity(6.9) == Severity.MED

    def test_cvss_low(self) -> None:
        assert _cvss_to_severity(0.0) == Severity.LOW
        assert _cvss_to_severity(3.9) == Severity.LOW

    def test_extract_cve_tags_basic(self) -> None:
        tags = ["attack.T1190", "cve.2021.44228", "cve.2022.30190"]
        ids = _extract_cve_tags(tags)
        assert "CVE-2021-44228" in ids
        assert "CVE-2022-30190" in ids

    def test_extract_cve_tags_case_insensitive(self) -> None:
        ids = _extract_cve_tags(["CVE.2021.44228"])
        assert "CVE-2021-44228" in ids

    def test_extract_cve_tags_no_match(self) -> None:
        assert _extract_cve_tags(["attack.T1059", "tlp.white"]) == []

    def test_extract_cve_tags_empty(self) -> None:
        assert _extract_cve_tags([]) == []


# ── Unit: _enrich_techniques ──────────────────────────────────────────────────

class TestEnrichTechniques:

    def test_fills_name_and_url_and_tactic(self) -> None:
        tech = MitreTechnique(technique_id="T1190", tactic="unknown")
        detection = _make_detection(techniques=[tech])
        kb = _mock_attack_kb("T1190", "Exploit Public-Facing Application", "initial-access")
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_techniques(detection, kb, result)

        assert tech.name == "Exploit Public-Facing Application"
        assert tech.url == "https://attack.mitre.org/techniques/T1190/"
        assert tech.tactic == "initial-access"
        assert result.techniques_enriched == 1

    def test_skips_already_filled_name(self) -> None:
        tech = MitreTechnique(technique_id="T1190", tactic="initial-access",
                              name="Already Set")
        detection = _make_detection(techniques=[tech])
        kb = _mock_attack_kb("T1190", "Should Not Override", "initial-access")
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_techniques(detection, kb, result)

        assert tech.name == "Already Set"

    def test_warns_when_technique_not_in_kb(self) -> None:
        tech = MitreTechnique(technique_id="T9999", tactic="unknown")
        detection = _make_detection(techniques=[tech])
        kb = MagicMock()
        kb.get_technique.return_value = None
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_techniques(detection, kb, result)

        assert result.techniques_enriched == 0
        assert any("T9999" in w for w in result.warnings)

    def test_fills_subtechnique_url(self) -> None:
        tech = MitreTechnique(technique_id="T1059", sub_technique_id="T1059.004",
                              tactic="unknown")
        detection = _make_detection(techniques=[tech])
        kb = _mock_attack_kb("T1059.004", "Unix Shell", "execution")
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_techniques(detection, kb, result)

        assert tech.url == "https://attack.mitre.org/techniques/T1059/004/"
        assert tech.name == "Unix Shell"

    def test_no_change_when_all_fields_present(self) -> None:
        tech = MitreTechnique(technique_id="T1190", tactic="initial-access",
                              name="Exploit Public-Facing Application",
                              url="https://attack.mitre.org/techniques/T1190/")
        detection = _make_detection(techniques=[tech])
        kb = _mock_attack_kb("T1190", "Should Not Be Used", "initial-access")
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_techniques(detection, kb, result)

        assert result.techniques_enriched == 0

    def test_counts_each_changed_technique(self) -> None:
        techs = [
            MitreTechnique(technique_id="T1190", tactic="unknown"),
            MitreTechnique(technique_id="T1059", tactic="unknown"),
        ]
        detection = _make_detection(techniques=techs)
        att = MagicMock()
        att.name = "Some Technique"
        att.tactic = "execution"
        kb = MagicMock()
        kb.get_technique.return_value = att
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_techniques(detection, kb, result)

        assert result.techniques_enriched == 2


# ── Unit: _enrich_cve_refs ────────────────────────────────────────────────────

class TestEnrichCveRefs:

    def test_creates_ref_from_tag(self) -> None:
        detection = _make_detection(tags=["cve.2021.44228"])
        kb = _mock_cve_kb("CVE-2021-44228", 10.0, "Log4Shell")
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_cve_refs(detection, kb, result)

        ids = [r.cve_id for r in detection.cve_references]
        assert "CVE-2021-44228" in ids
        assert result.cve_refs_added == 1

    def test_does_not_duplicate_existing_ref(self) -> None:
        existing = CVEReference(cve_id="CVE-2021-44228")
        detection = _make_detection(
            tags=["cve.2021.44228"],
            cve_refs=[existing],
        )
        kb = _mock_cve_kb("CVE-2021-44228", 10.0, "Log4Shell")
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_cve_refs(detection, kb, result)

        assert result.cve_refs_added == 0
        assert len(detection.cve_references) == 1

    def test_fills_cvss_and_description(self) -> None:
        ref = CVEReference(cve_id="CVE-2021-44228")
        detection = _make_detection(cve_refs=[ref])
        kb = _mock_cve_kb("CVE-2021-44228", 10.0, "Apache Log4j2 RCE vulnerability")
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_cve_refs(detection, kb, result)

        assert ref.cvss_score == 10.0
        assert ref.description == "Apache Log4j2 RCE vulnerability"
        assert result.cve_refs_enriched == 1

    def test_truncates_description_to_300(self) -> None:
        ref = CVEReference(cve_id="CVE-2021-44228")
        detection = _make_detection(cve_refs=[ref])
        long_desc = "x" * 500
        kb = _mock_cve_kb("CVE-2021-44228", 7.0, long_desc)
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_cve_refs(detection, kb, result)

        assert len(ref.description) == 300

    def test_skips_when_kb_has_no_record(self) -> None:
        ref = CVEReference(cve_id="CVE-2021-44228")
        detection = _make_detection(cve_refs=[ref])
        kb = MagicMock()
        kb.get.return_value = None
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_cve_refs(detection, kb, result)

        assert ref.cvss_score is None
        assert result.cve_refs_enriched == 0

    def test_skips_already_filled_cvss(self) -> None:
        ref = CVEReference(cve_id="CVE-2021-44228", cvss_score=9.5)
        detection = _make_detection(cve_refs=[ref])
        kb = _mock_cve_kb("CVE-2021-44228", 10.0, "New desc")
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_cve_refs(detection, kb, result)

        assert ref.cvss_score == 9.5   # not overwritten


# ── Unit: _enrich_severity ────────────────────────────────────────────────────

class TestEnrichSeverity:

    def test_derives_critical_from_cvss_10(self) -> None:
        ref = CVEReference(cve_id="CVE-2021-44228", cvss_score=10.0)
        detection = _make_detection(cve_refs=[ref], severity=Severity.MED)
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_severity(detection, result)

        assert detection.severity == Severity.CRITICAL
        assert result.severity_updated is True

    def test_derives_high_from_cvss_8(self) -> None:
        ref = CVEReference(cve_id="CVE-2021-34527", cvss_score=8.8)
        detection = _make_detection(cve_refs=[ref], severity=Severity.MED)
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_severity(detection, result)

        assert detection.severity == Severity.HIGH

    def test_no_change_when_already_high(self) -> None:
        ref = CVEReference(cve_id="CVE-2021-44228", cvss_score=10.0)
        detection = _make_detection(cve_refs=[ref], severity=Severity.HIGH)
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_severity(detection, result)

        assert result.severity_updated is False

    def test_no_change_when_no_cve_scores(self) -> None:
        ref = CVEReference(cve_id="CVE-2021-44228")  # no cvss_score
        detection = _make_detection(cve_refs=[ref], severity=Severity.MED)
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_severity(detection, result)

        assert detection.severity == Severity.MED
        assert result.severity_updated is False

    def test_uses_highest_score_when_multiple_cves(self) -> None:
        refs = [
            CVEReference(cve_id="CVE-2021-44228", cvss_score=10.0),
            CVEReference(cve_id="CVE-2021-34527", cvss_score=4.0),
        ]
        detection = _make_detection(cve_refs=refs, severity=Severity.MED)
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_severity(detection, result)

        assert detection.severity == Severity.CRITICAL

    def test_no_change_when_derived_is_also_med(self) -> None:
        ref = CVEReference(cve_id="CVE-2021-00001", cvss_score=5.0)
        detection = _make_detection(cve_refs=[ref], severity=Severity.MED)
        result = EnrichmentResult(rule_id="r1", name="test")

        _enrich_severity(detection, result)

        assert result.severity_updated is False


# ── Unit: EnrichmentResult ────────────────────────────────────────────────────

class TestEnrichmentResult:

    def test_changed_false_when_nothing_enriched(self) -> None:
        r = EnrichmentResult(rule_id="x", name="y")
        assert r.changed is False

    def test_changed_true_when_techniques_enriched(self) -> None:
        r = EnrichmentResult(rule_id="x", name="y", techniques_enriched=1)
        assert r.changed is True

    def test_changed_true_when_cve_refs_added(self) -> None:
        r = EnrichmentResult(rule_id="x", name="y", cve_refs_added=1)
        assert r.changed is True

    def test_changed_true_when_severity_updated(self) -> None:
        r = EnrichmentResult(rule_id="x", name="y", severity_updated=True)
        assert r.changed is True


# ── Integration: enrich_detection ────────────────────────────────────────────

class TestEnrichDetection:

    def test_all_passes_run_by_default(self) -> None:
        tech = MitreTechnique(technique_id="T1190", tactic="unknown")
        ref = CVEReference(cve_id="CVE-2021-44228")
        detection = _make_detection(
            techniques=[tech],
            cve_refs=[ref],
            severity=Severity.MED,
        )
        attack_kb = _mock_attack_kb("T1190", "Exploit Public-Facing Application", "initial-access")
        cve_kb = _mock_cve_kb("CVE-2021-44228", 10.0, "Log4Shell")

        result = enrich_detection(detection, attack_kb=attack_kb, cve_kb=cve_kb)

        assert tech.name == "Exploit Public-Facing Application"
        assert ref.cvss_score == 10.0
        assert detection.severity == Severity.CRITICAL
        assert result.changed is True

    def test_sources_filter_skips_attack_pass(self) -> None:
        tech = MitreTechnique(technique_id="T1190", tactic="unknown")
        detection = _make_detection(techniques=[tech])
        attack_kb = _mock_attack_kb("T1190", "Should Not Be Called", "initial-access")

        result = enrich_detection(
            detection, attack_kb=attack_kb, sources={"cve", "severity"}
        )

        assert tech.name is None
        assert result.techniques_enriched == 0

    def test_skips_attack_pass_when_kb_is_none(self) -> None:
        tech = MitreTechnique(technique_id="T1190", tactic="unknown")
        detection = _make_detection(techniques=[tech])

        result = enrich_detection(detection, attack_kb=None)

        assert tech.name is None

    def test_skips_cve_pass_when_kb_is_none(self) -> None:
        detection = _make_detection(tags=["cve.2021.44228"])

        result = enrich_detection(detection, cve_kb=None)

        assert result.cve_refs_added == 0

    def test_returns_enrichment_result(self) -> None:
        detection = _make_detection()
        result = enrich_detection(detection)
        assert isinstance(result, EnrichmentResult)
        assert result.rule_id == str(detection.id)
        assert result.name == detection.name
