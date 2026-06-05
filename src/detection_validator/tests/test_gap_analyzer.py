"""
Tests for coverage/gap_analyzer.py — STIX-based gap prioritization.

All tests use an in-memory synthetic STIX bundle (no file I/O, no network).
The bundle covers just enough objects to exercise every scoring path.
"""
from __future__ import annotations

import pytest

from detection_validator.coverage.gap_analyzer import (
    GapAnalyzer,
    PriorityGap,
    _PREVALENCE_CEIL,
    _SEVERITY_BONUS,
    _TACTIC_WEIGHTS,
)
from detection_validator.mappers.attack_mapper import AttackKnowledgeBase
from detection_validator.normalizer.schema import (
    CanonicalDetection,
    DetectionFormat,
    DetectionLogic,
    MitreTechnique,
    Severity,
)


# ── Synthetic STIX bundle ─────────────────────────────────────────────────────

def _ext_ref(attack_id: str) -> list[dict]:
    return [{"source_name": "mitre-attack", "external_id": attack_id}]


def _kill_chain(tactic: str) -> list[dict]:
    return [{"kill_chain_name": "mitre-attack", "phase_name": tactic}]


def _technique(tid: str, name: str, tactic: str, is_sub: bool = False) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid.lower().replace('.', '-')}",
        "name": name,
        "description": f"Test technique {tid}",
        "external_references": _ext_ref(tid),
        "kill_chain_phases": _kill_chain(tactic),
        "x-mitre-is-subtechnique": is_sub,
    }


def _group(gid: str, name: str) -> dict:
    return {
        "type": "intrusion-set",
        "id": f"intrusion-set--{gid}",
        "name": name,
    }


def _software(sid: str, name: str) -> dict:
    return {
        "type": "malware",
        "id": f"malware--{sid}",
        "name": name,
    }


def _uses(src_id: str, tgt_id: str) -> dict:
    return {
        "type": "relationship",
        "id": f"relationship--{src_id}-{tgt_id}",
        "relationship_type": "uses",
        "source_ref": src_id,
        "target_ref": tgt_id,
    }


# Technique IDs and their STIX object IDs
_T1190 = "attack-pattern--t1190"
_T1059 = "attack-pattern--t1059"
_T1059_004 = "attack-pattern--t1059-004"
_T1546 = "attack-pattern--t1546"   # low prevalence, discovery

_G001 = "intrusion-set--g001"
_G002 = "intrusion-set--g002"
_S001 = "malware--s001"

_BUNDLE: dict = {
    "type": "bundle",
    "objects": [
        # Techniques
        _technique("T1190", "Exploit Public-Facing Application", "initial-access"),
        _technique("T1059",  "Command and Scripting Interpreter", "execution"),
        _technique("T1059.004", "Unix Shell", "execution", is_sub=True),
        _technique("T1546", "Event Triggered Execution", "persistence"),

        # Groups
        _group("g001", "APT28"),
        _group("g002", "Lazarus"),

        # Software
        _software("s001", "Cobalt Strike"),

        # T1190: used by G001, G002, S001  → prevalence=3
        _uses(_G001, _T1190),
        _uses(_G002, _T1190),
        _uses(_S001, _T1190),

        # T1059: used by G001 only → prevalence=1
        _uses(_G001, _T1059),

        # T1059.004: used by S001 → prevalence=1
        _uses(_S001, _T1059_004),

        # T1546: no uses → prevalence=0
    ],
}


# ── KB fixture ────────────────────────────────────────────────────────────────

@pytest.fixture()
def kb() -> AttackKnowledgeBase:
    k = AttackKnowledgeBase.__new__(AttackKnowledgeBase)
    k.domain = "enterprise-attack"
    k.cache_dir = None  # type: ignore[assignment]
    k.ttl_days = 7
    k._techniques = {}
    k._stix_to_attack = {}
    k._deprecated_map = {}
    k._mitigations = {}
    k._groups = {}
    k._software = {}
    k._procedure_examples = {}
    k._tactics = []
    k._data_components = []
    k._data_sources = []
    k._loaded = False
    k.load_from_bundle(_BUNDLE)
    return k


@pytest.fixture()
def analyzer(kb: AttackKnowledgeBase) -> GapAnalyzer:
    return GapAnalyzer(kb)


# ── Helpers for building detections ──────────────────────────────────────────

def _det(
    name: str,
    technique_id: str,
    tactic: str = "execution",
    severity: Severity = Severity.MED,
    sub_technique_id: str | None = None,
) -> CanonicalDetection:
    return CanonicalDetection(
        name=name,
        description="test",
        detection_logic=DetectionLogic(
            raw="", language="sigma",
            normalized_conditions=[], field_references=[],
        ),
        log_sources=[],
        mitre_techniques=[
            MitreTechnique(
                technique_id=technique_id,
                sub_technique_id=sub_technique_id,
                tactic=tactic,
            )
        ],
        severity=severity,
        source_format=DetectionFormat.SIGMA,
    )


# ── Tests: tactic weights ─────────────────────────────────────────────────────

class TestTacticWeights:

    def test_initial_access_is_max_weight(self, analyzer: GapAnalyzer) -> None:
        weights = analyzer.tactic_weights()
        assert weights["initial-access"] == 10

    def test_execution_is_max_weight(self, analyzer: GapAnalyzer) -> None:
        assert analyzer.tactic_weights()["execution"] == 10

    def test_impact_is_near_max(self, analyzer: GapAnalyzer) -> None:
        assert analyzer.tactic_weights()["impact"] >= 8

    def test_reconnaissance_is_lower(self, analyzer: GapAnalyzer) -> None:
        weights = analyzer.tactic_weights()
        assert weights["reconnaissance"] < weights["initial-access"]

    def test_discovery_lower_than_persistence(self, analyzer: GapAnalyzer) -> None:
        weights = analyzer.tactic_weights()
        assert weights["discovery"] < weights["persistence"]


# ── Tests: analyze() returns gaps ─────────────────────────────────────────────

class TestAnalyzeGaps:

    def test_empty_corpus_returns_all_techniques_as_gaps(
        self, analyzer: GapAnalyzer
    ) -> None:
        gaps = analyzer.analyze([])
        ids = {g.technique_id for g in gaps}
        assert "T1190" in ids
        assert "T1059" in ids
        assert "T1059.004" in ids

    def test_covered_technique_excluded_from_gaps(
        self, analyzer: GapAnalyzer
    ) -> None:
        det = _det("ExploitRule", "T1190", tactic="initial-access")
        gaps = analyzer.analyze([det])
        ids = {g.technique_id for g in gaps}
        assert "T1190" not in ids

    def test_uncovered_technique_appears_in_gaps(
        self, analyzer: GapAnalyzer
    ) -> None:
        det = _det("ExploitRule", "T1190", tactic="initial-access")
        gaps = analyzer.analyze([det])
        ids = {g.technique_id for g in gaps}
        assert "T1059" in ids

    def test_no_subtechniques_flag_excludes_sub_techniques(
        self, analyzer: GapAnalyzer
    ) -> None:
        gaps = analyzer.analyze([], include_subtechniques=False)
        ids = {g.technique_id for g in gaps}
        assert "T1059.004" not in ids
        assert "T1059" in ids

    def test_returns_list_of_priority_gaps(
        self, analyzer: GapAnalyzer
    ) -> None:
        gaps = analyzer.analyze([])
        assert all(isinstance(g, PriorityGap) for g in gaps)

    def test_each_gap_has_required_fields(
        self, analyzer: GapAnalyzer
    ) -> None:
        gaps = analyzer.analyze([])
        for g in gaps:
            assert g.technique_id
            assert g.name
            assert g.tactic
            assert isinstance(g.score, float)
            assert isinstance(g.prevalence, int)
            assert isinstance(g.reasons, list)
            assert len(g.reasons) >= 1


# ── Tests: scoring ─────────────────────────────────────────────────────────────

class TestScoring:

    def test_higher_prevalence_gives_higher_score(
        self, analyzer: GapAnalyzer
    ) -> None:
        # T1190 prevalence=3, T1546 prevalence=0, both uncovered
        gaps = analyzer.analyze([])
        t1190 = next(g for g in gaps if g.technique_id == "T1190")
        t1546 = next(g for g in gaps if g.technique_id == "T1546")
        # T1190 initial-access (weight 10) vs T1546 persistence (weight 8)
        # T1190 prevalence=3 vs T1546 prevalence=0
        assert t1190.score > t1546.score

    def test_initial_access_outscores_persistence_same_prevalence(
        self, analyzer: GapAnalyzer,
    ) -> None:
        # Manually verify score components
        ia_score = analyzer._score("T1190", "initial-access", prevalence=3,
                                   parent_covered=False, parent_max_severity=None)
        pe_score = analyzer._score("T1546", "persistence", prevalence=3,
                                   parent_covered=False, parent_max_severity=None)
        assert ia_score > pe_score

    def test_score_bounded_0_to_100(self, analyzer: GapAnalyzer) -> None:
        gaps = analyzer.analyze([])
        for g in gaps:
            assert 0.0 <= g.score <= 100.0

    def test_zero_prevalence_does_not_crash(self, analyzer: GapAnalyzer) -> None:
        score = analyzer._score("T1546", "persistence", prevalence=0,
                                parent_covered=False, parent_max_severity=None)
        assert score >= 0

    def test_max_prevalence_capped(self, analyzer: GapAnalyzer) -> None:
        # Prevalence at ceiling should equal full 40 pts + tactic portion
        s1 = analyzer._score("T1190", "initial-access", prevalence=_PREVALENCE_CEIL,
                              parent_covered=False, parent_max_severity=None)
        s2 = analyzer._score("T1190", "initial-access", prevalence=_PREVALENCE_CEIL * 10,
                              parent_covered=False, parent_max_severity=None)
        assert s1 == s2  # cap applied

    def test_parent_severity_critical_adds_bonus(self, analyzer: GapAnalyzer) -> None:
        score_no_parent = analyzer._score(
            "T1059.004", "execution", prevalence=1,
            parent_covered=False, parent_max_severity=None,
        )
        score_with_parent = analyzer._score(
            "T1059.004", "execution", prevalence=1,
            parent_covered=True, parent_max_severity=Severity.CRITICAL,
        )
        assert score_with_parent > score_no_parent

    def test_parent_severity_ordering(self, analyzer: GapAnalyzer) -> None:
        # critical > high > med > low
        scores = {}
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MED, Severity.LOW):
            scores[sev] = analyzer._score(
                "T1059.004", "execution", prevalence=0,
                parent_covered=True, parent_max_severity=sev,
            )
        assert scores[Severity.CRITICAL] > scores[Severity.HIGH]
        assert scores[Severity.HIGH] > scores[Severity.MED]
        assert scores[Severity.MED] > scores[Severity.LOW]

    def test_parent_not_covered_no_severity_bonus(
        self, analyzer: GapAnalyzer
    ) -> None:
        score = analyzer._score(
            "T1059.004", "execution", prevalence=0,
            parent_covered=False, parent_max_severity=Severity.CRITICAL,
        )
        # parent_max_severity is ignored when parent_covered=False
        score_no_sev = analyzer._score(
            "T1059.004", "execution", prevalence=0,
            parent_covered=False, parent_max_severity=None,
        )
        assert score == score_no_sev


# ── Tests: parent_covered logic ───────────────────────────────────────────────

class TestParentCoveredLogic:

    def test_sub_technique_marks_parent_covered_when_parent_has_rule(
        self, analyzer: GapAnalyzer
    ) -> None:
        # Cover T1059 (parent), leave T1059.004 (sub) uncovered
        det = _det("CmdInterpreter", "T1059", tactic="execution")
        gaps = analyzer.analyze([det])
        sub_gap = next((g for g in gaps if g.technique_id == "T1059.004"), None)
        assert sub_gap is not None
        assert sub_gap.parent_covered is True

    def test_sub_technique_parent_not_covered_when_no_rule(
        self, analyzer: GapAnalyzer
    ) -> None:
        gaps = analyzer.analyze([])  # nothing covered
        sub_gap = next(g for g in gaps if g.technique_id == "T1059.004")
        assert sub_gap.parent_covered is False

    def test_parent_max_severity_reflects_covering_rule(
        self, analyzer: GapAnalyzer
    ) -> None:
        det = _det("CmdInterpreter", "T1059", tactic="execution",
                   severity=Severity.HIGH)
        gaps = analyzer.analyze([det])
        sub_gap = next(g for g in gaps if g.technique_id == "T1059.004")
        assert sub_gap.parent_max_severity == Severity.HIGH

    def test_parent_max_severity_takes_highest_when_multiple_rules(
        self, analyzer: GapAnalyzer
    ) -> None:
        det1 = _det("RuleLow", "T1059", tactic="execution", severity=Severity.LOW)
        det2 = _det("RuleCrit", "T1059", tactic="execution", severity=Severity.CRITICAL)
        gaps = analyzer.analyze([det1, det2])
        sub_gap = next(g for g in gaps if g.technique_id == "T1059.004")
        assert sub_gap.parent_max_severity == Severity.CRITICAL

    def test_base_technique_has_none_parent_id(
        self, analyzer: GapAnalyzer
    ) -> None:
        gaps = analyzer.analyze([])
        t1190 = next(g for g in gaps if g.technique_id == "T1190")
        assert t1190.parent_id is None

    def test_sub_technique_has_parent_id(
        self, analyzer: GapAnalyzer
    ) -> None:
        gaps = analyzer.analyze([])
        sub = next(g for g in gaps if g.technique_id == "T1059.004")
        assert sub.parent_id == "T1059"


# ── Tests: reasons ────────────────────────────────────────────────────────────

class TestReasons:

    def test_reasons_mention_prevalence(self, analyzer: GapAnalyzer) -> None:
        gaps = analyzer.analyze([])
        t1190 = next(g for g in gaps if g.technique_id == "T1190")
        combined = " ".join(t1190.reasons).lower()
        assert "group" in combined or "software" in combined or "prevalence" in combined

    def test_reasons_mention_tactic(self, analyzer: GapAnalyzer) -> None:
        gaps = analyzer.analyze([])
        t1190 = next(g for g in gaps if g.technique_id == "T1190")
        combined = " ".join(t1190.reasons).lower()
        assert "tactic" in combined or "initial-access" in combined

    def test_reasons_mention_parent_when_covered(
        self, analyzer: GapAnalyzer
    ) -> None:
        det = _det("CmdInterpreter", "T1059", tactic="execution")
        gaps = analyzer.analyze([det])
        sub = next(g for g in gaps if g.technique_id == "T1059.004")
        combined = " ".join(sub.reasons).lower()
        assert "t1059" in combined

    def test_zero_prevalence_reason_is_explicit(
        self, analyzer: GapAnalyzer
    ) -> None:
        gaps = analyzer.analyze([])
        t1546 = next(g for g in gaps if g.technique_id == "T1546")
        combined = " ".join(t1546.reasons).lower()
        assert "no group" in combined or "prevalence" in combined or "low" in combined

    def test_reasons_is_list_of_strings(self, analyzer: GapAnalyzer) -> None:
        gaps = analyzer.analyze([])
        for g in gaps:
            assert isinstance(g.reasons, list)
            assert all(isinstance(r, str) for r in g.reasons)


# ── Tests: top_gaps ───────────────────────────────────────────────────────────

class TestTopGaps:

    def test_returns_at_most_n(self, analyzer: GapAnalyzer) -> None:
        gaps = analyzer.top_gaps([], n=2)
        assert len(gaps) <= 2

    def test_top_1_is_highest_score(self, analyzer: GapAnalyzer) -> None:
        all_gaps = analyzer.analyze([])
        top1 = analyzer.top_gaps([], n=1)
        assert top1[0].score == all_gaps[0].score

    def test_top_gaps_sorted_descending(self, analyzer: GapAnalyzer) -> None:
        gaps = analyzer.top_gaps([], n=10)
        for i in range(len(gaps) - 1):
            assert gaps[i].score >= gaps[i + 1].score


# ── Tests: sorted order ───────────────────────────────────────────────────────

class TestSortedOrder:

    def test_analyze_returns_sorted_descending(
        self, analyzer: GapAnalyzer
    ) -> None:
        gaps = analyzer.analyze([])
        for i in range(len(gaps) - 1):
            assert gaps[i].score >= gaps[i + 1].score

    def test_fully_covered_corpus_returns_empty_gaps(
        self, analyzer: GapAnalyzer
    ) -> None:
        dets = [
            _det("Rule1", "T1190", tactic="initial-access"),
            _det("Rule2", "T1059", tactic="execution"),
            _det("Rule3", "T1059", tactic="execution",
                 sub_technique_id="T1059.004"),
            _det("Rule4", "T1546", tactic="persistence"),
        ]
        gaps = analyzer.analyze(dets, include_subtechniques=True)
        assert gaps == []


# ── Tests: prevalence counts ──────────────────────────────────────────────────

class TestPrevalenceCounts:

    def test_t1190_prevalence_equals_3(self, analyzer: GapAnalyzer) -> None:
        gaps = analyzer.analyze([])
        t1190 = next(g for g in gaps if g.technique_id == "T1190")
        assert t1190.prevalence == 3   # G001 + G002 + S001

    def test_t1059_prevalence_equals_1(self, analyzer: GapAnalyzer) -> None:
        gaps = analyzer.analyze([])
        t1059 = next(g for g in gaps if g.technique_id == "T1059")
        assert t1059.prevalence == 1   # G001 only

    def test_t1546_prevalence_equals_0(self, analyzer: GapAnalyzer) -> None:
        gaps = analyzer.analyze([])
        t1546 = next(g for g in gaps if g.technique_id == "T1546")
        assert t1546.prevalence == 0
