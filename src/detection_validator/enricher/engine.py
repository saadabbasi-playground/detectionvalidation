"""
Enrichment engine — fills in missing metadata on CanonicalDetection objects.

Three enrichment passes (each independent and skippable via `sources`):

  attack  Fill mitre_techniques[].name, .url, and .tactic from the local
          ATT&CK knowledge base.  Technique names like "Exploit Public-Facing
          Application" replace bare IDs in reports and the Navigator layer.

  cve     Extract cve.YYYY.NNNNN tags that aren't yet in cve_references,
          create CVEReference entries, then fill .cvss_score and .description
          from NVD/KEV/EPSS caches.

  severity  Derive severity from the highest CVSS score across all linked CVEs
            (only applied when the current value is the MED default and at
            least one CVE score is available, to avoid overwriting explicit
            author choices).

Input/output: CanonicalDetection JSONL — same contract as dv ingest / dv map.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from detection_validator.normalizer.schema import (
    CanonicalDetection,
    CVEReference,
    Severity,
)

_CVE_TAG_RE = re.compile(r"cve\.(\d{4})\.(\d+)", re.I)
_ATTACK_URL = "https://attack.mitre.org/techniques/{id}/"


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class EnrichmentResult:
    rule_id: str
    name: str
    techniques_enriched: int = 0   # technique entries where name/tactic was filled
    cve_refs_added: int = 0        # new CVEReference entries created from tags
    cve_refs_enriched: int = 0     # existing/new refs where cvss/description filled
    severity_updated: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(
            self.techniques_enriched
            or self.cve_refs_added
            or self.cve_refs_enriched
            or self.severity_updated
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _technique_url(technique_id: str) -> str:
    if "." in technique_id:
        base, sub = technique_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MED
    return Severity.LOW


def _extract_cve_tags(tags: list[str]) -> list[str]:
    """Return CVE IDs (e.g. CVE-2021-44228) from cve.YYYY.NNNNN tags."""
    ids = []
    for tag in tags:
        m = _CVE_TAG_RE.search(tag)
        if m:
            ids.append(f"CVE-{m.group(1)}-{m.group(2)}")
    return ids


# ── Core enrichment functions ─────────────────────────────────────────────────

def _enrich_techniques(
    detection: CanonicalDetection,
    kb: Any,  # AttackKnowledgeBase
    result: EnrichmentResult,
) -> None:
    """Fill name, url, and tactic on each MitreTechnique from the ATT&CK KB."""
    for tech in detection.mitre_techniques:
        tid = tech.full_id
        att = kb.get_technique(tid)
        if att is None:
            result.warnings.append(f"Technique {tid} not found in ATT&CK KB")
            continue

        changed = False
        if not tech.name:
            tech.name = att.name
            changed = True
        if not tech.url:
            tech.url = _technique_url(tid)
            changed = True
        if not tech.tactic or tech.tactic == "unknown":
            tech.tactic = att.tactic
            changed = True
        if changed:
            result.techniques_enriched += 1


def _enrich_cve_refs(
    detection: CanonicalDetection,
    cve_kb: Any,  # CVEKnowledgeBase
    result: EnrichmentResult,
) -> None:
    """
    1. Create CVEReference entries for any cve.YYYY.NNNNN tags not yet present.
    2. Fill .cvss_score and .description on all CVEReference entries.
    """
    existing_ids = {ref.cve_id.upper() for ref in detection.cve_references}

    # Step 1 — create missing refs from tags
    for cve_id in _extract_cve_tags(detection.tags):
        upper = cve_id.upper()
        if upper not in existing_ids:
            try:
                detection.cve_references.append(CVEReference(cve_id=upper))
                existing_ids.add(upper)
                result.cve_refs_added += 1
            except Exception:
                result.warnings.append(f"Invalid CVE ID from tag: {cve_id}")

    # Step 2 — enrich all refs with NVD/KEV/EPSS data
    for ref in detection.cve_references:
        record = cve_kb.get(ref.cve_id)
        if record is None:
            continue
        changed = False
        if ref.cvss_score is None and record.cvss_score is not None:
            ref.cvss_score = record.cvss_score
            changed = True
        if not ref.description and record.description:
            ref.description = record.description[:300]
            changed = True
        if changed:
            result.cve_refs_enriched += 1


def _enrich_severity(
    detection: CanonicalDetection,
    result: EnrichmentResult,
) -> None:
    """Derive severity from the highest CVSS score, but only if still at default MED."""
    if detection.severity != Severity.MED:
        return
    scores = [
        ref.cvss_score
        for ref in detection.cve_references
        if ref.cvss_score is not None
    ]
    if not scores:
        return
    derived = _cvss_to_severity(max(scores))
    if derived != Severity.MED:
        detection.severity = derived
        result.severity_updated = True


# ── Public API ────────────────────────────────────────────────────────────────

def enrich_detection(
    detection: CanonicalDetection,
    attack_kb: Any | None = None,
    cve_kb: Any | None = None,
    sources: set[str] | None = None,
) -> EnrichmentResult:
    """
    Enrich a single detection in-place.

    sources controls which passes run (default: all available):
      "attack"   — fill technique names/urls/tactics
      "cve"      — create CVE refs from tags and fill cvss/description
      "severity" — derive severity from highest CVSS
    """
    if sources is None:
        sources = {"attack", "cve", "severity"}

    result = EnrichmentResult(rule_id=str(detection.id), name=detection.name)

    if "attack" in sources and attack_kb is not None:
        _enrich_techniques(detection, attack_kb, result)

    if "cve" in sources and cve_kb is not None:
        _enrich_cve_refs(detection, cve_kb, result)

    if "severity" in sources:
        _enrich_severity(detection, result)

    return result


def enrich_corpus(
    detections: list[CanonicalDetection],
    sources: set[str] | None = None,
) -> list[EnrichmentResult]:
    """
    Enrich a list of detections, loading knowledge bases once and sharing them.
    """
    if sources is None:
        sources = {"attack", "cve", "severity"}

    attack_kb = None
    cve_kb = None

    if "attack" in sources:
        try:
            from detection_validator.mappers.attack_mapper import AttackKnowledgeBase
            attack_kb = AttackKnowledgeBase()
            attack_kb.ensure_loaded()
        except Exception:
            attack_kb = None

    if "cve" in sources:
        try:
            from detection_validator.mappers.cve_mapper import CVEKnowledgeBase
            cve_kb = CVEKnowledgeBase()
        except Exception:
            cve_kb = None

    return [
        enrich_detection(d, attack_kb=attack_kb, cve_kb=cve_kb, sources=sources)
        for d in detections
    ]
