"""
Mappers — MITRE ATT&CK and CVE/NVD mapping utilities.

Primary exports:

  ATT&CK
  :class:`AttackKnowledgeBase`  — cached ATT&CK STIX knowledge base
  :class:`AttackMapper`         — EXPLICIT / INFERRED / HYBRID mapping
  :class:`MappingResult`        — result of a mapping run
  :class:`TechniqueMatch`       — one validated or inferred technique binding
  :class:`MappingMode`          — mode constants
  :func:`get_knowledge_base`    — per-domain singleton accessor

  CVE
  :class:`CVEKnowledgeBase`     — multi-source CVE intelligence store
  :class:`CVEToTechniqueMapper` — CTID / CWE / LLM technique inference
  :class:`CVECoverageAnalyzer`  — detection corpus coverage + residual risk
  :class:`CVERecord`            — merged per-CVE data model
  :class:`TechniqueMapping`     — CVE → technique with provenance
  :class:`CVECoverageResult`    — coverage analysis result
"""

from __future__ import annotations

from detection_validator.mappers.attack_mapper import (
    AttackKnowledgeBase,
    AttackMapper,
    AttackTechnique,
    MappingMode,
    MappingResult,
    TechniqueMatch,
    get_knowledge_base,
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

__all__ = [
    # ATT&CK
    "AttackKnowledgeBase",
    "AttackMapper",
    "AttackTechnique",
    "MappingMode",
    "MappingResult",
    "TechniqueMatch",
    "get_knowledge_base",
    # CVE
    "CVEKnowledgeBase",
    "CVEToTechniqueMapper",
    "CVECoverageAnalyzer",
    "CVERecord",
    "TechniqueMapping",
    "CVETechniqueResult",
    "CVECoverageResult",
]
