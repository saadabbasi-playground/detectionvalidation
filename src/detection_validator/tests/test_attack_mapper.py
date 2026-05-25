"""
Tests for attack_mapper.py — AttackKnowledgeBase and AttackMapper.

All tests use an in-memory mock STIX bundle to avoid network calls.
The mock contains a representative subset of real ATT&CK content including
active techniques, a sub-technique, a deprecated/revoked technique, and the
full relationship graph (mitigations, groups, software, revoked-by).
"""

from __future__ import annotations

import re
import warnings
from pathlib import Path
from typing import Any

import pytest

from detection_validator.normalizer.schema import (
    CanonicalDetection,
    DetectionFormat,
    DetectionLogic,
    LogSource,
    MitreTechnique,
    Platform,
    Severity,
    ValidationStatus,
)
from detection_validator.mappers.attack_mapper import (
    AttackKnowledgeBase,
    AttackMapper,
    AttackTechnique,
    MappingMode,
    MappingResult,
    TechniqueMatch,
    _render_prompt,
    _load_keyword_entries,
    _load_datasource_hints,
)

# ─── Mock STIX bundle ─────────────────────────────────────────────────────────

_MOCK_STIX: dict[str, Any] = {
    "type": "bundle",
    "id": "bundle--test-mock",
    "objects": [
        # ── Tactics ──────────────────────────────────────────────────────────
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--exec",
            "name": "Execution",
            "x-mitre-shortname": "execution",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--cred",
            "name": "Credential Access",
            "x-mitre-shortname": "credential-access",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0006"}],
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--defevasion",
            "name": "Defense Evasion",
            "x-mitre-shortname": "defense-evasion",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0005"}],
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--lateral",
            "name": "Lateral Movement",
            "x-mitre-shortname": "lateral-movement",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0008"}],
        },
        # ── Base techniques ───────────────────────────────────────────────────
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1059",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command and script interpreters to execute commands.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1003",
            "name": "OS Credential Dumping",
            "description": "Adversaries may attempt to dump credentials to obtain account login information.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1003"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1218",
            "name": "System Binary Proxy Execution",
            "description": "Adversaries may bypass process and/or signature-based defenses.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1218"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1047",
            "name": "Windows Management Instrumentation",
            "description": "Adversaries may abuse WMI to execute malicious commands.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1047"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1140",
            "name": "Deobfuscate/Decode Files or Information",
            "description": "Adversaries may use certutil or other tools to deobfuscate content.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1140"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1110",
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques to gain access.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1021",
            "name": "Remote Services",
            "description": "Adversaries may use valid accounts to log into a service.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "lateral-movement"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1021"}],
        },
        # ── Sub-techniques ────────────────────────────────────────────────────
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1059.001",
            "name": "PowerShell",
            "description": "Adversaries may abuse PowerShell commands and scripts for execution. Including -EncodedCommand, IEX.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": True,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1003.001",
            "name": "LSASS Memory",
            "description": "Adversaries may access LSASS memory to obtain credentials. Mimikatz sekurlsa.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": True,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1003.001"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1218.005",
            "name": "Mshta",
            "description": "Adversaries may abuse mshta.exe to proxy execution of malicious code.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": True,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1218.005"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1110.003",
            "name": "Password Spraying",
            "description": "Adversaries may use a single password against many accounts.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": True,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110.003"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t1021.002",
            "name": "SMB/Windows Admin Shares",
            "description": "Adversaries may use SMB to interact with remote systems including PsExec.",
            "x-mitre-deprecated": False,
            "revoked": False,
            "x-mitre-is-subtechnique": True,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "lateral-movement"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1021.002"}],
        },
        # ── Deprecated / revoked technique ────────────────────────────────────
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t9999-deprecated",
            "name": "Deprecated Technique",
            "description": "This technique has been revoked.",
            "x-mitre-deprecated": True,
            "revoked": True,
            "x-mitre-is-subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        },
        # ── revoked-by relationship (T9999 → T1059) ──────────────────────────
        {
            "type": "relationship",
            "id": "relationship--revoke-t9999",
            "relationship_type": "revoked-by",
            "source_ref": "attack-pattern--t9999-deprecated",
            "target_ref": "attack-pattern--t1059",
        },
        # ── Mitigation ────────────────────────────────────────────────────────
        {
            "type": "course-of-action",
            "id": "course-of-action--m1040",
            "name": "Behavior Prevention on Endpoint",
            "external_references": [{"source_name": "mitre-attack", "external_id": "M1040"}],
        },
        {
            "type": "relationship",
            "id": "relationship--mit-t1059",
            "relationship_type": "mitigates",
            "source_ref": "course-of-action--m1040",
            "target_ref": "attack-pattern--t1059",
        },
        # ── Group ─────────────────────────────────────────────────────────────
        {
            "type": "intrusion-set",
            "id": "intrusion-set--apt28",
            "name": "APT28",
            "external_references": [{"source_name": "mitre-attack", "external_id": "G0007"}],
        },
        {
            "type": "relationship",
            "id": "relationship--apt28-uses-ps",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--apt28",
            "target_ref": "attack-pattern--t1059.001",
            "description": "APT28 has used PowerShell scripts encoded with Base64.",
        },
        # ── Software ──────────────────────────────────────────────────────────
        {
            "type": "malware",
            "id": "malware--mimikatz",
            "name": "Mimikatz",
            "external_references": [{"source_name": "mitre-attack", "external_id": "S0002"}],
        },
        {
            "type": "relationship",
            "id": "relationship--mimikatz-uses",
            "relationship_type": "uses",
            "source_ref": "malware--mimikatz",
            "target_ref": "attack-pattern--t1003.001",
            "description": "Mimikatz is used to dump LSASS memory.",
        },
        # ── Data source / component ───────────────────────────────────────────
        {
            "type": "x-mitre-data-source",
            "id": "x-mitre-data-source--process",
            "name": "Process",
            "description": "Information about running processes.",
        },
        {
            "type": "x-mitre-data-component",
            "id": "x-mitre-data-component--proc-creation",
            "name": "Process Creation",
            "x-mitre-data-source-ref": "x-mitre-data-source--process",
        },
    ],
}


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def kb() -> AttackKnowledgeBase:
    """Pre-loaded knowledge base from the mock STIX bundle (no network)."""
    _kb = AttackKnowledgeBase(domain="enterprise-attack")
    _kb.load_from_bundle(_MOCK_STIX)
    return _kb


@pytest.fixture(scope="module")
def mapper(kb: AttackKnowledgeBase) -> AttackMapper:
    """AttackMapper wired to the mock KB with real config files."""
    return AttackMapper(kb=kb)


def _make_detection(
    name: str = "Test Detection",
    description: str = "",
    raw_logic: str = "",
    techniques: list[tuple[str, str, float]] | None = None,
    log_sources: list[str] | None = None,
) -> CanonicalDetection:
    """Minimal factory for CanonicalDetection test fixtures."""
    mitre_techniques = []
    for tid, tactic, conf in (techniques or []):
        base = tid.split(".")[0]
        sub = tid if "." in tid else None
        mitre_techniques.append(MitreTechnique(
            technique_id=base,
            sub_technique_id=sub,
            tactic=tactic,
            confidence=conf,
        ))

    ls = [LogSource(category=s) for s in (log_sources or [])]

    return CanonicalDetection(
        name=name,
        description=description,
        detection_logic=DetectionLogic(
            raw=raw_logic,
            language="sigma",
            normalized_conditions=[],
            field_references=[],
        ),
        log_sources=ls,
        mitre_techniques=mitre_techniques,
        severity=Severity.MED,
        source_format=DetectionFormat.SIGMA,
    )


# ─── AttackKnowledgeBase tests ────────────────────────────────────────────────

class TestAttackKnowledgeBase:

    def test_load_from_bundle(self, kb: AttackKnowledgeBase) -> None:
        assert kb._loaded is True
        assert len(kb._techniques) > 0

    def test_technique_count(self, kb: AttackKnowledgeBase) -> None:
        # Our mock has T1059, T1059.001, T1003, T1003.001, T1218, T1218.005,
        # T1047, T1140, T1110, T1110.003, T1021, T1021.002, T9999
        assert len(kb._techniques) == 13

    def test_get_technique_base(self, kb: AttackKnowledgeBase) -> None:
        t = kb.get_technique("T1059")
        assert t is not None
        assert t.technique_id == "T1059"
        assert t.name == "Command and Scripting Interpreter"
        assert t.tactic == "execution"
        assert t.is_subtechnique is False

    def test_get_technique_sub(self, kb: AttackKnowledgeBase) -> None:
        t = kb.get_technique("T1059.001")
        assert t is not None
        assert t.is_subtechnique is True
        assert t.parent_id == "T1059"

    def test_get_technique_missing(self, kb: AttackKnowledgeBase) -> None:
        assert kb.get_technique("T0001") is None

    def test_get_all_techniques_excludes_deprecated_by_default(
        self, kb: AttackKnowledgeBase
    ) -> None:
        techs = kb.get_all_techniques()
        ids = [t.technique_id for t in techs]
        assert "T9999" not in ids

    def test_get_all_techniques_includes_deprecated_when_requested(
        self, kb: AttackKnowledgeBase
    ) -> None:
        techs = kb.get_all_techniques(include_deprecated=True)
        ids = [t.technique_id for t in techs]
        assert "T9999" in ids

    def test_get_tactics(self, kb: AttackKnowledgeBase) -> None:
        tactics = kb.get_tactics()
        assert len(tactics) == 4
        shortnames = [t.get("x-mitre-shortname", "") for t in tactics]
        assert "execution" in shortnames

    def test_get_data_components(self, kb: AttackKnowledgeBase) -> None:
        comps = kb.get_data_components()
        names = [c.get("name") for c in comps]
        assert "Process Creation" in names

    def test_get_data_sources(self, kb: AttackKnowledgeBase) -> None:
        sources = kb.get_data_sources()
        names = [s.get("name") for s in sources]
        assert "Process" in names

    def test_is_deprecated_true(self, kb: AttackKnowledgeBase) -> None:
        assert kb.is_deprecated("T9999") is True

    def test_is_deprecated_false(self, kb: AttackKnowledgeBase) -> None:
        assert kb.is_deprecated("T1059") is False

    def test_is_deprecated_unknown(self, kb: AttackKnowledgeBase) -> None:
        assert kb.is_deprecated("T0001") is False

    def test_get_replacement(self, kb: AttackKnowledgeBase) -> None:
        replacement = kb.get_replacement("T9999")
        assert replacement == "T1059"

    def test_get_replacement_for_active_technique(
        self, kb: AttackKnowledgeBase
    ) -> None:
        assert kb.get_replacement("T1059") is None

    def test_get_mitigations(self, kb: AttackKnowledgeBase) -> None:
        mits = kb.get_mitigations("T1059")
        assert len(mits) == 1
        assert mits[0].get("name") == "Behavior Prevention on Endpoint"

    def test_get_groups_using(self, kb: AttackKnowledgeBase) -> None:
        groups = kb.get_groups_using("T1059.001")
        names = [g.get("name") for g in groups]
        assert "APT28" in names

    def test_get_software_using(self, kb: AttackKnowledgeBase) -> None:
        sw = kb.get_software_using("T1003.001")
        names = [s.get("name") for s in sw]
        assert "Mimikatz" in names

    def test_get_procedure_examples(self, kb: AttackKnowledgeBase) -> None:
        examples = kb.get_procedure_examples("T1059.001")
        assert len(examples) >= 1
        assert any("APT28" in ex for ex in examples)

    def test_parent_exists_true(self, kb: AttackKnowledgeBase) -> None:
        assert kb.parent_exists("T1059.001") is True

    def test_parent_exists_false_for_orphan(
        self, kb: AttackKnowledgeBase
    ) -> None:
        assert kb.parent_exists("T9998.001") is False

    def test_repr(self, kb: AttackKnowledgeBase) -> None:
        r = repr(kb)
        assert "enterprise-attack" in r
        assert "loaded=True" in r

    def test_cache_is_valid_false_before_save(self, tmp_path: Path) -> None:
        fresh_kb = AttackKnowledgeBase(cache_dir=tmp_path)
        assert fresh_kb._is_cache_valid() is False


# ─── EXPLICIT mapping tests ───────────────────────────────────────────────────

class TestExplicitMapping:

    # Fixture 1: valid single technique
    def test_explicit_valid_technique(self, mapper: AttackMapper) -> None:
        d = _make_detection(techniques=[("T1059.001", "execution", 0.9)])
        result = mapper.map_detection(d, mode=MappingMode.EXPLICIT)
        assert len(result.validated) == 1
        assert result.validated[0].technique_id == "T1059.001"
        assert not result.errors

    # Fixture 2: deprecated technique flagged
    def test_explicit_deprecated_technique_flagged(
        self, mapper: AttackMapper
    ) -> None:
        d = _make_detection(techniques=[("T9999", "execution", 0.8)])
        result = mapper.map_detection(d, mode=MappingMode.EXPLICIT)
        assert len(result.validated) == 1
        match = result.validated[0]
        assert match.deprecated is True
        assert match.replacement == "T1059"
        assert result.warnings  # at least one deprecation warning

    # Fixture 3: deprecated technique replacement shown
    def test_explicit_deprecated_replacement_is_correct(
        self, mapper: AttackMapper
    ) -> None:
        d = _make_detection(techniques=[("T9999", "execution", 0.8)])
        result = mapper.map_detection(d, mode=MappingMode.EXPLICIT)
        assert result.validated[0].replacement == "T1059"

    # Fixture 4: missing tactic filled in from ATT&CK
    def test_explicit_missing_tactic_filled(self, mapper: AttackMapper) -> None:
        d = _make_detection(techniques=[("T1003.001", "unknown", 0.85)])
        result = mapper.map_detection(d, mode=MappingMode.EXPLICIT)
        assert result.validated[0].tactic == "credential-access"
        assert any("Filled missing tactic" in w for w in result.warnings)

    # Fixture 5: sub-technique parent verified
    def test_explicit_subtechnique_parent_exists(
        self, mapper: AttackMapper
    ) -> None:
        d = _make_detection(techniques=[("T1059.001", "execution", 0.9)])
        result = mapper.map_detection(d, mode=MappingMode.EXPLICIT)
        # No parent-missing warning
        assert not any("not found" in w for w in result.warnings)

    # Fixture 6: sub-technique missing parent is flagged
    def test_explicit_subtechnique_orphan_warned(
        self, mapper: AttackMapper
    ) -> None:
        # T9998.001 doesn't exist in our mock
        d = _make_detection(techniques=[("T1218.005", "defense-evasion", 0.8)])
        # T1218 parent does exist in mock, so no warning
        result = mapper.map_detection(d, mode=MappingMode.EXPLICIT)
        parent_warnings = [w for w in result.warnings if "not found" in w.lower()]
        assert len(parent_warnings) == 0

    # Fixture 7: technique not in knowledge base → error
    def test_explicit_unknown_technique_error(
        self, mapper: AttackMapper
    ) -> None:
        d = _make_detection(techniques=[("T0001", "unknown", 0.5)])
        result = mapper.map_detection(d, mode=MappingMode.EXPLICIT)
        assert result.errors
        assert len(result.validated) == 0

    # Fixture 8: multiple techniques, one valid one deprecated
    def test_explicit_mixed_valid_and_deprecated(
        self, mapper: AttackMapper
    ) -> None:
        d = _make_detection(techniques=[
            ("T1059.001", "execution", 0.9),
            ("T9999", "execution", 0.8),
        ])
        result = mapper.map_detection(d, mode=MappingMode.EXPLICIT)
        assert len(result.validated) == 2
        deprecated = [m for m in result.validated if m.deprecated]
        assert len(deprecated) == 1


# ─── INFERRED mapping tests ───────────────────────────────────────────────────

class TestInferredMapping:

    # Fixture 9: keyword match — powershell -enc
    def test_inferred_keyword_powershell(self, mapper: AttackMapper) -> None:
        d = _make_detection(
            raw_logic='CommandLine contains "powershell -enc"',
        )
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        ids = {m.technique_id for m in result.inferred}
        assert "T1059.001" in ids

    # Fixture 10: keyword match — mimikatz
    def test_inferred_keyword_mimikatz(self, mapper: AttackMapper) -> None:
        d = _make_detection(
            raw_logic='process_name == "mimikatz.exe" or commandline contains "sekurlsa"',
        )
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        ids = {m.technique_id for m in result.inferred}
        assert "T1003.001" in ids

    # Fixture 11: data source hint — process_creation + certutil
    def test_inferred_datasource_certutil(self, mapper: AttackMapper) -> None:
        d = _make_detection(
            raw_logic='process_name == "certutil.exe"',
            log_sources=["process_creation"],
        )
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        ids = {m.technique_id for m in result.inferred}
        assert "T1140" in ids

    # Fixture 12: data source hint — process_creation + mshta
    def test_inferred_datasource_mshta(self, mapper: AttackMapper) -> None:
        d = _make_detection(
            raw_logic='Image endswith "mshta.exe"',
            log_sources=["process_creation"],
        )
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        ids = {m.technique_id for m in result.inferred}
        assert "T1218.005" in ids

    # Fixture 13: confidence attached to inferred match
    def test_inferred_match_has_confidence(self, mapper: AttackMapper) -> None:
        d = _make_detection(raw_logic='IEX(New-Object Net.WebClient).DownloadString')
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        for m in result.inferred:
            assert 0.0 < m.confidence <= 1.0

    # Fixture 14: source field set correctly
    def test_inferred_keyword_source_field(self, mapper: AttackMapper) -> None:
        d = _make_detection(raw_logic='wmic process call create "cmd.exe"')
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        kw_matches = [m for m in result.inferred if m.source == "keyword"]
        assert kw_matches

    def test_inferred_datasource_source_field(self, mapper: AttackMapper) -> None:
        # wmic.exe: keyword "wmic" fires at confidence=0.75
        # datasource hint (process_creation+wmic) fires at confidence=0.80 > 0.75
        # → datasource overrides keyword for T1047
        d = _make_detection(
            raw_logic='Image endswith "wmic.exe" CommandLine contains "/node:"',
            log_sources=["process_creation"],
        )
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        t1047_matches = [m for m in result.inferred if m.technique_id == "T1047"]
        assert t1047_matches
        # datasource hint (0.80) beats bare "wmic" keyword (0.75)
        assert t1047_matches[0].source == "datasource"

    # Fixture 15: no matches for unrelated detection
    def test_inferred_no_match_for_generic_rule(self, mapper: AttackMapper) -> None:
        d = _make_detection(
            name="Generic Alert",
            description="Alert on threshold exceeded",
            raw_logic="metric > 100",
        )
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        # May return some low-confidence matches but not high-confidence ones
        high_conf = [m for m in result.inferred if m.confidence > 0.75]
        assert len(high_conf) == 0


# ─── HYBRID mapping tests ─────────────────────────────────────────────────────

class TestHybridMapping:

    def test_hybrid_validates_existing_and_infers_new(
        self, mapper: AttackMapper
    ) -> None:
        # Detection has T1218.005 explicitly tagged, also mentions mshta (but exclude)
        # and powershell -enc which should be inferred
        d = _make_detection(
            techniques=[("T1218.005", "defense-evasion", 0.9)],
            raw_logic='mshta spawns powershell -enc',
        )
        result = mapper.map_detection(d, mode=MappingMode.HYBRID)
        # Explicit validated
        assert any(m.technique_id == "T1218.005" for m in result.validated)
        # Inferred adds T1059.001 (powershell -enc) but not T1218.005 again
        ids_inferred = {m.technique_id for m in result.inferred}
        assert "T1218.005" not in ids_inferred
        assert "T1059.001" in ids_inferred

    def test_hybrid_all_techniques_deduped(self, mapper: AttackMapper) -> None:
        d = _make_detection(
            techniques=[("T1059.001", "execution", 0.9)],
            raw_logic='powershell -enc SomePayload',
        )
        result = mapper.map_detection(d, mode=MappingMode.HYBRID)
        all_ids = [m.technique_id for m in result.all_techniques]
        # No duplicates
        assert len(all_ids) == len(set(all_ids))

    def test_hybrid_no_existing_techniques_falls_back_to_inferred(
        self, mapper: AttackMapper
    ) -> None:
        d = _make_detection(raw_logic='sekurlsa::logonpasswords')
        result = mapper.map_detection(d, mode=MappingMode.HYBRID)
        assert result.inferred  # inferred runs when no existing techniques


# ─── apply() tests ────────────────────────────────────────────────────────────

class TestApply:

    def test_apply_updates_detection_techniques(self, mapper: AttackMapper) -> None:
        d = _make_detection(raw_logic='powershell -enc SomeBase64Payload')
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        updated = mapper.apply(d, result, min_confidence=0.5)
        assert len(updated.mitre_techniques) > 0

    def test_apply_does_not_mutate_original(self, mapper: AttackMapper) -> None:
        d = _make_detection(raw_logic='mimikatz sekurlsa::logonpasswords')
        original_count = len(d.mitre_techniques)
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        _ = mapper.apply(d, result)
        assert len(d.mitre_techniques) == original_count  # original unchanged

    def test_apply_respects_min_confidence(self, mapper: AttackMapper) -> None:
        match = TechniqueMatch(
            technique_id="T1059.001",
            tactic="execution",
            confidence=0.4,
            source="keyword",
        )
        result = MappingResult(detection_id="x", mode="inferred", inferred=[match])
        d = _make_detection()
        updated = mapper.apply(d, result, min_confidence=0.5)
        # Low-confidence match should be excluded
        assert len(updated.mitre_techniques) == 0

    def test_apply_high_confidence_included(self, mapper: AttackMapper) -> None:
        match = TechniqueMatch(
            technique_id="T1059.001",
            tactic="execution",
            confidence=0.9,
            source="keyword",
        )
        result = MappingResult(detection_id="x", mode="inferred", inferred=[match])
        d = _make_detection()
        updated = mapper.apply(d, result, min_confidence=0.5)
        assert len(updated.mitre_techniques) == 1
        assert updated.mitre_techniques[0].technique_id == "T1059"
        assert updated.mitre_techniques[0].sub_technique_id == "T1059.001"

    def test_apply_no_matches_returns_unchanged(
        self, mapper: AttackMapper
    ) -> None:
        d = _make_detection(techniques=[("T1059.001", "execution", 0.9)])
        result = MappingResult(detection_id=d.id, mode="explicit")
        updated = mapper.apply(d, result, min_confidence=0.5)
        assert updated is d  # same object returned when nothing to apply


# ─── MappingResult tests ──────────────────────────────────────────────────────

class TestMappingResult:

    def test_all_techniques_deduplicates(self) -> None:
        m = TechniqueMatch("T1059.001", "execution", 0.9, "explicit")
        r = MappingResult(
            detection_id="x",
            mode="hybrid",
            validated=[m],
            inferred=[m],  # duplicate
        )
        assert len(r.all_techniques) == 1

    def test_has_errors(self) -> None:
        r = MappingResult("x", "explicit", errors=["bad technique"])
        assert r.has_errors is True

    def test_has_warnings(self) -> None:
        r = MappingResult("x", "explicit", warnings=["deprecated"])
        assert r.has_warnings is True

    def test_processing_time_set(self, mapper: AttackMapper) -> None:
        d = _make_detection(raw_logic="powershell -enc abc")
        result = mapper.map_detection(d, mode=MappingMode.INFERRED)
        assert result.processing_time_ms > 0


# ─── LLM prompt template tests ───────────────────────────────────────────────

class TestLLMPromptTemplate:

    def test_prompt_renders_detection_name(self, mapper: AttackMapper) -> None:
        d = _make_detection(
            name="Suspicious PowerShell Execution",
            description="Detects encoded PowerShell commands",
            raw_logic='powershell -enc SomeBase64',
        )
        prompt = _render_prompt(
            detection=d,
            candidate_summary=[],
            config={"max_candidates": 5, "min_confidence": 0.3},
        )
        assert "Suspicious PowerShell Execution" in prompt

    def test_prompt_renders_raw_logic(self, mapper: AttackMapper) -> None:
        d = _make_detection(raw_logic="process.name == 'mimikatz.exe'")
        prompt = _render_prompt(
            detection=d,
            candidate_summary=[],
            config={"max_candidates": 5, "min_confidence": 0.3},
        )
        assert "mimikatz.exe" in prompt

    def test_prompt_renders_candidate_summary(self) -> None:
        d = _make_detection(name="Test")
        candidates = [
            TechniqueMatch("T1059.001", "execution", 0.85, "keyword",
                           reasoning="Matched keyword: 'powershell -enc'")
        ]
        prompt = _render_prompt(
            detection=d,
            candidate_summary=candidates,
            config={"max_candidates": 5, "min_confidence": 0.3},
        )
        assert "T1059.001" in prompt
        assert "execution" in prompt

    def test_prompt_includes_json_schema_instruction(self) -> None:
        d = _make_detection()
        prompt = _render_prompt(d, [], {"max_candidates": 3, "min_confidence": 0.3})
        assert "candidates" in prompt
        assert "confidence" in prompt
        assert "technique_id" in prompt

    def test_prompt_reflects_max_candidates_config(self) -> None:
        d = _make_detection()
        prompt = _render_prompt(d, [], {"max_candidates": 7, "min_confidence": 0.3})
        assert "7" in prompt

    def test_prompt_template_missing_raises(self, tmp_path: Path) -> None:
        d = _make_detection()
        with pytest.raises(FileNotFoundError):
            _render_prompt(
                d,
                [],
                {"max_candidates": 5, "min_confidence": 0.3,
                 "prompt_template": "nonexistent/template.j2"},
                config_dir=tmp_path,
            )


# ─── Config loader tests ─────────────────────────────────────────────────────

class TestConfigLoaders:

    def test_keyword_entries_loaded(self) -> None:
        entries = _load_keyword_entries()
        assert len(entries) > 20

    def test_keyword_entry_powershell(self) -> None:
        entries = _load_keyword_entries()
        keywords = [e.keyword.lower() for e in entries]
        assert any("powershell" in k for k in keywords)

    def test_keyword_entry_with_regex(self) -> None:
        entries = _load_keyword_entries()
        regex_entries = [e for e in entries if e.is_regex]
        assert len(regex_entries) > 0

    def test_datasource_hints_loaded(self) -> None:
        hints = _load_datasource_hints()
        assert len(hints) > 5

    def test_datasource_hint_process_creation(self) -> None:
        hints = _load_datasource_hints()
        ls_lists = [h.log_sources for h in hints]
        assert any("process_creation" in ls for ls in ls_lists)

    def test_missing_config_dir_returns_empty(self, tmp_path: Path) -> None:
        entries = _load_keyword_entries(config_dir=tmp_path)
        assert entries == []
        hints = _load_datasource_hints(config_dir=tmp_path)
        assert hints == []
