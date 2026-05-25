"""
Tests for cve_mapper.py — CVEKnowledgeBase, CVEToTechniqueMapper, CVECoverageAnalyzer.

All external HTTP calls are mocked via unittest.mock.patch so no network is needed.
The fixture CVE is CVE-2021-44228 (Log4Shell): CVSS 10.0, EPSS ~0.97, KEV member,
CTID-mapped to T1190, CWE-917.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from detection_validator.normalizer.schema import (
    CanonicalDetection,
    DetectionFormat,
    DetectionLogic,
    MitreTechnique,
    Severity,
)
from detection_validator.mappers.cve_mapper import (
    CVECoverageAnalyzer,
    CVECoverageResult,
    CVEKnowledgeBase,
    CVERecord,
    CVETechniqueResult,
    CVEToTechniqueMapper,
    TechniqueMapping,
)
from detection_validator.mappers.cve_sources.base import CVEFetchError

# ─── Shared fixtures ──────────────────────────────────────────────────────────

CVE_LOG4SHELL = "CVE-2021-44228"
CVE_SPRING4SHELL = "CVE-2022-22965"

_NVD_LOG4SHELL: dict[str, Any] = {
    "cve_id": CVE_LOG4SHELL,
    "description": (
        "Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features used in "
        "configuration, log messages, and parameters do not protect against "
        "attacker controlled LDAP and other JNDI related endpoints."
    ),
    "cvss_score": 10.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_version": "3.1",
    "severity": "CRITICAL",
    "cwes": ["CWE-917"],
    "cpes": ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
    "published": "2021-12-10T10:15:09.143",
    "modified": "2023-11-07T03:57:36.967",
}

_KEV_CATALOG: dict[str, Any] = {
    CVE_LOG4SHELL: {
        "cve_id": CVE_LOG4SHELL,
        "vendor": "Apache",
        "product": "Log4j2",
        "name": "Apache Log4j2 Remote Code Execution Vulnerability",
        "date_added": "2021-12-10",
        "due_date": "2021-12-24",
        "short_description": "Apache Log4j2 contains a RCE vulnerability.",
        "required_action": "Apply updates per vendor instructions.",
        "notes": "",
    }
}

_CTID_CATALOG: dict[str, Any] = {
    CVE_LOG4SHELL: {"techniques": ["T1190", "T1059"]},
}

_EPSS_LOG4SHELL: dict[str, Any] = {
    "epss": 0.97542,
    "percentile": 0.99985,
    "date": "2024-01-15",
}


def _make_nvd_fetcher(nvd_data: dict | None = None) -> MagicMock:
    f = MagicMock()
    f.fetch_cve.return_value = nvd_data
    f.fetch_batch.return_value = (
        {nvd_data["cve_id"]: nvd_data} if nvd_data else {}
    )
    return f


def _make_kev_fetcher(catalog: dict | None = None) -> MagicMock:
    f = MagicMock()
    f.fetch_catalog.return_value = catalog or {}
    return f


def _make_ctid_fetcher(catalog: dict | None = None) -> MagicMock:
    f = MagicMock()
    f.fetch_catalog.return_value = catalog or {}
    return f


def _make_epss_fetcher(epss_map: dict | None = None) -> MagicMock:
    f = MagicMock()

    def _batch(cve_ids):
        return {c: epss_map[c] for c in cve_ids if c in (epss_map or {})}

    f.fetch_batch.side_effect = _batch
    return f


def _make_kb(
    nvd=None, kev=None, ctid=None, epss=None
) -> CVEKnowledgeBase:
    # Use `is None` checks so an explicitly-passed empty dict {} is respected.
    fetchers = {
        "nvd": _make_nvd_fetcher(nvd if nvd is not False else None),
        "kev": _make_kev_fetcher(_KEV_CATALOG if kev is None else kev),
        "ctid": _make_ctid_fetcher(_CTID_CATALOG if ctid is None else ctid),
        "epss": _make_epss_fetcher(
            {CVE_LOG4SHELL: _EPSS_LOG4SHELL} if epss is None else epss
        ),
    }
    if nvd is False:
        fetchers.pop("nvd")
    return CVEKnowledgeBase(fetchers=fetchers)


def _detection(
    name: str, technique_id: str, sub_technique_id: str | None = None
) -> CanonicalDetection:
    mt = MitreTechnique(
        technique_id=technique_id,
        sub_technique_id=sub_technique_id,
        tactic="initial-access",
    )
    return CanonicalDetection(
        name=name,
        detection_logic=DetectionLogic(raw=f"query for {name}"),
        mitre_techniques=[mt],
    )


# ─── CVERecord merging ────────────────────────────────────────────────────────


class TestCVEKnowledgeBase:
    def test_get_merges_all_sources(self):
        kb = _make_kb(nvd=_NVD_LOG4SHELL)
        record = kb.get(CVE_LOG4SHELL)
        assert record is not None
        assert record.cve_id == CVE_LOG4SHELL
        assert record.cvss_score == 10.0
        assert record.severity == "CRITICAL"
        assert "CWE-917" in record.cwes
        assert record.in_kev is True
        assert record.kev_date_added == "2021-12-10"
        assert "T1190" in record.ctid_techniques
        assert abs(record.epss_score - 0.97542) < 1e-4

    def test_get_returns_none_when_no_sources(self):
        kb = CVEKnowledgeBase(fetchers={})
        assert kb.get("CVE-9999-9999") is None

    def test_get_without_nvd(self):
        kb = _make_kb(nvd=False)
        record = kb.get(CVE_LOG4SHELL)
        # should still return a record from KEV/CTID/EPSS
        assert record is not None
        assert record.in_kev is True

    def test_get_caches_in_memory(self):
        kb = _make_kb(nvd=_NVD_LOG4SHELL)
        r1 = kb.get(CVE_LOG4SHELL)
        r2 = kb.get(CVE_LOG4SHELL)
        assert r1 is r2  # same object from cache
        # NVD fetch_cve called only once
        kb._fetchers["nvd"].fetch_cve.assert_called_once()

    def test_get_normalises_to_uppercase(self):
        kb = _make_kb(nvd=_NVD_LOG4SHELL)
        r1 = kb.get("cve-2021-44228")
        r2 = kb.get(CVE_LOG4SHELL)
        assert r1 is r2

    def test_get_batch_uses_single_epss_call(self):
        kb = _make_kb(nvd=_NVD_LOG4SHELL)
        kb.get_batch([CVE_LOG4SHELL])
        # fetch_batch on EPSS fetcher should have been called once
        kb._fetchers["epss"].fetch_batch.assert_called_once()

    def test_update_clears_record_cache(self):
        kb = _make_kb(nvd=_NVD_LOG4SHELL)
        kb.get(CVE_LOG4SHELL)
        assert CVE_LOG4SHELL in kb._record_cache
        kb.update()
        assert CVE_LOG4SHELL not in kb._record_cache

    def test_update_specific_cves_invalidates_only_those(self):
        kb = _make_kb(nvd=_NVD_LOG4SHELL)
        kb.get(CVE_LOG4SHELL)
        kb._record_cache["CVE-OTHER-0000"] = CVERecord(cve_id="CVE-OTHER-0000")
        kb.update(cve_ids=[CVE_LOG4SHELL])
        assert CVE_LOG4SHELL not in kb._record_cache
        assert "CVE-OTHER-0000" in kb._record_cache

    def test_kev_fetch_error_yields_partial_record(self):
        kev = MagicMock()
        kev.fetch_catalog.side_effect = CVEFetchError("network down")
        kb = CVEKnowledgeBase(fetchers={
            "nvd": _make_nvd_fetcher(_NVD_LOG4SHELL),
            "kev": kev,
            "ctid": _make_ctid_fetcher(_CTID_CATALOG),
            "epss": _make_epss_fetcher({CVE_LOG4SHELL: _EPSS_LOG4SHELL}),
        })
        record = kb.get(CVE_LOG4SHELL)
        assert record is not None
        assert record.in_kev is False   # KEV unavailable
        assert record.cvss_score == 10.0  # NVD still worked


# ─── CVEToTechniqueMapper — CTID path ─────────────────────────────────────────


class TestCTIDPath:
    def _mapper(self) -> CVEToTechniqueMapper:
        kb = _make_kb(nvd=_NVD_LOG4SHELL)
        cwe_path = Path(__file__).parents[3] / "configs" / "cwe_technique_map.yaml"
        return CVEToTechniqueMapper(kb=kb, cwe_map_path=cwe_path, use_llm=False)

    def test_ctid_techniques_returned_with_high_confidence(self):
        result = self._mapper().map_cve(CVE_LOG4SHELL)
        sources = {t.source for t in result.techniques}
        assert "ctid" in sources
        ctid_techs = [t for t in result.techniques if t.source == "ctid"]
        for t in ctid_techs:
            assert t.confidence == 0.90

    def test_t1190_in_results(self):
        result = self._mapper().map_cve(CVE_LOG4SHELL)
        ids = [t.technique_id for t in result.techniques]
        assert "T1190" in ids

    def test_sources_used_includes_ctid(self):
        result = self._mapper().map_cve(CVE_LOG4SHELL)
        assert "ctid" in result.sources_used


# ─── CVEToTechniqueMapper — CWE path ─────────────────────────────────────────


class TestCWEPath:
    def _mapper(self, ctid_catalog: dict | None = None) -> CVEToTechniqueMapper:
        # Use only T1190 in CTID so T1059 (from CWE-917) is not deduplicated away.
        ctid = ctid_catalog if ctid_catalog is not None else {
            CVE_LOG4SHELL: {"techniques": ["T1190"]}
        }
        kb = _make_kb(nvd=_NVD_LOG4SHELL, ctid=ctid)
        cwe_path = Path(__file__).parents[3] / "configs" / "cwe_technique_map.yaml"
        return CVEToTechniqueMapper(kb=kb, cwe_map_path=cwe_path, use_llm=False)

    def test_cwe_917_maps_to_t1059(self):
        # CWE-917 → T1059; CTID only has T1190 so T1059 is solely CWE-sourced
        result = self._mapper().map_cve(CVE_LOG4SHELL)
        ids = [t.technique_id for t in result.techniques]
        assert "T1059" in ids

    def test_cwe_source_label(self):
        result = self._mapper().map_cve(CVE_LOG4SHELL)
        cwe_techs = [t for t in result.techniques if t.source == "cwe"]
        assert cwe_techs, "expected at least one CWE-sourced technique"

    def test_missing_cwe_map_returns_empty(self):
        # Empty CTID and missing CWE map — nothing should be returned.
        kb = _make_kb(nvd=_NVD_LOG4SHELL, ctid={})
        mapper = CVEToTechniqueMapper(
            kb=kb,
            cwe_map_path=Path("/nonexistent/cwe_map.yaml"),
            use_llm=False,
        )
        result = mapper.map_cve(CVE_LOG4SHELL)
        assert result.techniques == []

    def test_cwe_78_maps_both_t1059_and_t1059_003(self):
        # Inject a CVE with CWE-78
        nvd_cwe78 = {**_NVD_LOG4SHELL, "cve_id": "CVE-9999-0001", "cwes": ["CWE-78"]}
        kb = _make_kb(nvd=nvd_cwe78, ctid={})
        cwe_path = Path(__file__).parents[3] / "configs" / "cwe_technique_map.yaml"
        mapper = CVEToTechniqueMapper(kb=kb, cwe_map_path=cwe_path, use_llm=False)
        result = mapper.map_cve("CVE-9999-0001")
        ids = [t.technique_id for t in result.techniques]
        assert "T1059" in ids
        assert "T1059.003" in ids


# ─── CVEToTechniqueMapper — deduplication ────────────────────────────────────


class TestDeduplication:
    def test_duplicate_technique_ids_deduplicated(self):
        """CTID and CWE both map to T1059 — only one entry should survive."""
        ctid_with_t1059 = {CVE_LOG4SHELL: {"techniques": ["T1059"]}}
        kb = _make_kb(nvd=_NVD_LOG4SHELL, ctid=ctid_with_t1059)
        cwe_path = Path(__file__).parents[3] / "configs" / "cwe_technique_map.yaml"
        mapper = CVEToTechniqueMapper(kb=kb, cwe_map_path=cwe_path, use_llm=False)
        result = mapper.map_cve(CVE_LOG4SHELL)
        t1059s = [t for t in result.techniques if t.technique_id == "T1059"]
        assert len(t1059s) == 1

    def test_highest_confidence_kept_after_dedup(self):
        """CTID confidence (0.90) should win over CWE (< 0.90) for the same ID."""
        ctid_with_t1059 = {CVE_LOG4SHELL: {"techniques": ["T1059"]}}
        kb = _make_kb(nvd=_NVD_LOG4SHELL, ctid=ctid_with_t1059)
        cwe_path = Path(__file__).parents[3] / "configs" / "cwe_technique_map.yaml"
        mapper = CVEToTechniqueMapper(kb=kb, cwe_map_path=cwe_path, use_llm=False)
        result = mapper.map_cve(CVE_LOG4SHELL)
        t1059 = next(t for t in result.techniques if t.technique_id == "T1059")
        assert t1059.confidence == 0.90
        assert t1059.source == "ctid"

    def test_unknown_cve_returns_error_result(self):
        kb = _make_kb(nvd=None)
        kb._fetchers["nvd"].fetch_cve.return_value = None
        cwe_path = Path(__file__).parents[3] / "configs" / "cwe_technique_map.yaml"
        mapper = CVEToTechniqueMapper(kb=kb, cwe_map_path=cwe_path, use_llm=False)
        result = mapper.map_cve("CVE-9999-9999")
        assert result.record is None
        assert result.techniques == []
        assert result.errors


# ─── CVECoverageAnalyzer ──────────────────────────────────────────────────────


class TestCVECoverageAnalyzer:
    def _analyzer(self) -> CVECoverageAnalyzer:
        kb = _make_kb(nvd=_NVD_LOG4SHELL)
        cwe_path = Path(__file__).parents[3] / "configs" / "cwe_technique_map.yaml"
        mapper = CVEToTechniqueMapper(kb=kb, cwe_map_path=cwe_path, use_llm=False)
        return CVECoverageAnalyzer(mapper=mapper)

    def test_full_coverage_zero_residual_risk(self):
        """All mapped techniques covered → residual_risk = 0."""
        analyzer = self._analyzer()
        # Get the techniques so we can build matching detections
        result = analyzer._mapper.map_cve(CVE_LOG4SHELL)
        detections = [
            _detection(f"det_{t.technique_id}", t.technique_id.split(".")[0])
            for t in result.techniques
        ]
        coverage = analyzer.analyze(CVE_LOG4SHELL, detections)
        assert coverage.coverage_ratio == 1.0
        assert coverage.residual_risk_score == 0.0

    def test_zero_coverage_max_residual_risk(self):
        """No detections → coverage_ratio=0 → residual = CVSS × EPSS × 1."""
        analyzer = self._analyzer()
        coverage = analyzer.analyze(CVE_LOG4SHELL, [])
        assert coverage.coverage_ratio == 0.0
        expected = round(10.0 * 0.97542 * 1.0, 4)
        assert abs(coverage.residual_risk_score - expected) < 0.01

    def test_partial_coverage(self):
        """One of two techniques covered → ratio = 0.5."""
        analyzer = self._analyzer()
        result = analyzer._mapper.map_cve(CVE_LOG4SHELL)
        techniques = result.techniques
        if len(techniques) < 2:
            pytest.skip("Need at least 2 mapped techniques for this test")
        covered_id = techniques[0].technique_id.split(".")[0]
        detections = [_detection("det1", covered_id)]
        coverage = analyzer.analyze(CVE_LOG4SHELL, detections)
        assert 0.0 < coverage.coverage_ratio < 1.0
        assert covered_id in coverage.covered_technique_ids
        # Residual risk should be reduced from the zero-coverage case
        assert coverage.residual_risk_score < round(10.0 * 0.97542, 4)

    def test_covering_detections_populated(self):
        analyzer = self._analyzer()
        detections = [_detection("log4shell-detection", "T1190")]
        coverage = analyzer.analyze(CVE_LOG4SHELL, detections)
        # T1190 should be covered
        if "T1190" in coverage.covered_technique_ids:
            assert "log4shell-detection" in coverage.covering_detections["T1190"]

    def test_sub_technique_covers_parent(self):
        """A detection with T1059.001 should count as covering T1059."""
        analyzer = self._analyzer()
        detections = [_detection("powershell-det", "T1059", "T1059.001")]
        coverage = analyzer.analyze(CVE_LOG4SHELL, detections)
        # T1059 should now be covered by the sub-technique detection
        assert "T1059" in coverage.covered_technique_ids

    def test_kev_flag_propagated(self):
        analyzer = self._analyzer()
        coverage = analyzer.analyze(CVE_LOG4SHELL, [])
        assert coverage.in_kev is True

    def test_cvss_and_epss_propagated(self):
        analyzer = self._analyzer()
        coverage = analyzer.analyze(CVE_LOG4SHELL, [])
        assert coverage.cvss_score == 10.0
        assert abs(coverage.epss_score - 0.97542) < 1e-4

    def test_analyze_corpus_sorted_by_residual_risk(self):
        """analyze_corpus returns results sorted highest risk first."""
        # Make a second CVE with lower risk
        nvd_low = {**_NVD_LOG4SHELL, "cve_id": CVE_SPRING4SHELL, "cvss_score": 5.0}
        nvd_mock = MagicMock()
        nvd_mock.fetch_cve.side_effect = lambda c: (
            _NVD_LOG4SHELL if c == CVE_LOG4SHELL else nvd_low
        )
        nvd_mock.fetch_batch.return_value = {}
        epss_map = {
            CVE_LOG4SHELL: _EPSS_LOG4SHELL,
            CVE_SPRING4SHELL: {"epss": 0.10, "percentile": 0.80, "date": "2024-01-15"},
        }
        kb = CVEKnowledgeBase(fetchers={
            "nvd": nvd_mock,
            "kev": _make_kev_fetcher(_KEV_CATALOG),
            "ctid": _make_ctid_fetcher(_CTID_CATALOG),
            "epss": _make_epss_fetcher(epss_map),
        })
        cwe_path = Path(__file__).parents[3] / "configs" / "cwe_technique_map.yaml"
        mapper = CVEToTechniqueMapper(kb=kb, cwe_map_path=cwe_path, use_llm=False)
        analyzer = CVECoverageAnalyzer(mapper=mapper)
        results = analyzer.analyze_corpus(
            [CVE_LOG4SHELL, CVE_SPRING4SHELL], detections=[]
        )
        assert results[0].cve_id == CVE_LOG4SHELL
        assert results[0].residual_risk_score >= results[1].residual_risk_score


# ─── Residual risk formula ────────────────────────────────────────────────────


class TestResidualRiskFormula:
    def test_known_values(self):
        # CVSS=10, EPSS=0.97542, coverage=0 → 10 × 0.97542 × 1 = 9.7542
        score = CVECoverageAnalyzer.residual_risk(10.0, 0.97542, 0.0)
        assert abs(score - 9.7542) < 0.001

    def test_full_coverage_zero_risk(self):
        assert CVECoverageAnalyzer.residual_risk(10.0, 1.0, 1.0) == 0.0

    def test_zero_epss_zero_risk(self):
        assert CVECoverageAnalyzer.residual_risk(10.0, 0.0, 0.0) == 0.0

    def test_half_coverage_halves_risk(self):
        full = CVECoverageAnalyzer.residual_risk(8.0, 0.5, 0.0)
        half = CVECoverageAnalyzer.residual_risk(8.0, 0.5, 0.5)
        assert abs(half - full / 2) < 0.001

    def test_coverage_ratio_clamped_above_one(self):
        # coverage_ratio > 1 should not produce negative risk
        score = CVECoverageAnalyzer.residual_risk(10.0, 1.0, 1.5)
        assert score == 0.0
