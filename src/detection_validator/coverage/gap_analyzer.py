"""Gap analyzer — surfaces ATT&CK techniques not covered by any detection rule.

Priority scoring uses only locally cached STIX data (no network, no CVE APIs):

  score = prevalence_pts (0-40) + tactic_pts (0-40) + parent_severity_pts (0-20)

  prevalence_pts   — groups + software that use the technique in the STIX bundle,
                     normalised to 60 uses = full 40 pts.
  tactic_pts       — tactic-tier weight (Initial Access / Execution / Impact rank
                     highest at 10/10), scaled to 40 pts.
  parent_severity_pts — only for sub-techniques whose parent IS covered: the max
                     severity of the covering rules contributes up to 20 pts.
                     (CRITICAL=20, HIGH=16, MED=10, LOW=5, INFO=2)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from detection_validator.normalizer.schema import CanonicalDetection, Severity


# ── Tactic weights (0–10, higher = more urgent) ───────────────────────────────

_TACTIC_WEIGHTS: dict[str, int] = {
    "initial-access":        10,
    "execution":             10,
    "impact":                 9,
    "persistence":            8,
    "privilege-escalation":   8,
    "defense-evasion":        7,
    "credential-access":      7,
    "lateral-movement":       7,
    "collection":             6,
    "command-and-control":    6,
    "exfiltration":           5,
    "discovery":              4,
    "reconnaissance":         3,
    "resource-development":   3,
}

_DEFAULT_TACTIC_WEIGHT = 3   # unknown / future tactics

# ── Severity → parent-severity bonus points ───────────────────────────────────

_SEVERITY_BONUS: dict[str, float] = {
    Severity.CRITICAL: 20.0,
    Severity.HIGH:     16.0,
    Severity.MED:      10.0,
    Severity.LOW:       5.0,
    Severity.INFO:      2.0,
}

# Normalisation ceiling: prevalence >= 60 → full 40 pts
_PREVALENCE_CEIL = 60


# ── Public data types ─────────────────────────────────────────────────────────

@dataclass
class PriorityGap:
    """One uncovered ATT&CK technique with a composite priority score."""
    technique_id: str       # e.g. "T1059" or "T1059.004"
    name: str
    tactic: str             # primary tactic slug
    score: float            # 0–100 composite priority
    prevalence: int         # groups + software using this in STIX
    tactic_weight: int      # raw weight 0–10
    parent_id: str | None   # non-None for sub-techniques
    parent_covered: bool    # parent has at least one detection
    parent_max_severity: str | None  # e.g. "critical" — used in score
    reasons: list[str] = field(default_factory=list)  # why this score


# ── GapAnalyzer ───────────────────────────────────────────────────────────────

class GapAnalyzer:
    """
    Identify ATT&CK coverage gaps and optionally rank them by threat impact.

    Parameters
    ----------
    kb:
        A loaded ``AttackKnowledgeBase``.  Must already have ``ensure_loaded()``
        called — this class does NOT trigger downloads.
    """

    def __init__(self, kb) -> None:
        self._kb = kb

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _covered_ids(
        self, detections: list[CanonicalDetection]
    ) -> dict[str, list[CanonicalDetection]]:
        """Map every covered technique_id (base + sub) to the covering detections."""
        result: dict[str, list[CanonicalDetection]] = {}
        for det in detections:
            for mt in det.mitre_techniques:
                # Index both base ID and sub-technique ID
                for tid in {mt.technique_id, mt.sub_technique_id} - {None}:
                    result.setdefault(tid, []).append(det)
        return result

    def _max_severity(self, dets: list[CanonicalDetection]) -> str | None:
        """Return the highest severity across a list of detections, or None."""
        _ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MED, Severity.LOW, Severity.INFO]
        for sev in _ORDER:
            if any(d.severity == sev for d in dets):
                return sev
        return None

    def _score(
        self,
        technique_id: str,
        tactic: str,
        prevalence: int,
        parent_covered: bool,
        parent_max_severity: str | None,
    ) -> float:
        prevalence_pts = min(prevalence, _PREVALENCE_CEIL) / _PREVALENCE_CEIL * 40
        tactic_weight = _TACTIC_WEIGHTS.get(tactic, _DEFAULT_TACTIC_WEIGHT)
        tactic_pts = tactic_weight / 10 * 40
        severity_pts = 0.0
        if parent_covered and parent_max_severity:
            severity_pts = _SEVERITY_BONUS.get(parent_max_severity, 0.0)
        return round(prevalence_pts + tactic_pts + severity_pts, 1)

    def _reasons(
        self,
        technique_id: str,
        tactic: str,
        prevalence: int,
        groups: int,
        software: int,
        parent_covered: bool,
        parent_id: str | None,
        parent_max_severity: str | None,
    ) -> list[str]:
        r: list[str] = []
        if prevalence == 0:
            r.append("No groups or software documented in STIX (low observed prevalence)")
        elif prevalence <= 5:
            r.append(f"Observed by {groups} group(s) and {software} software in ATT&CK STIX (prevalence={prevalence})")
        else:
            r.append(f"Used by {groups} group(s) and {software} software in ATT&CK STIX (prevalence={prevalence})")
        tactic_weight = _TACTIC_WEIGHTS.get(tactic, _DEFAULT_TACTIC_WEIGHT)
        r.append(f"Tactic '{tactic}' weight={tactic_weight}/10")
        if parent_id and parent_covered and parent_max_severity:
            r.append(
                f"Parent {parent_id} covered (max rule severity: {parent_max_severity}) — "
                "sub-technique gap adds specificity"
            )
        elif parent_id and parent_covered:
            r.append(f"Parent {parent_id} covered but covering rules have no severity set")
        elif parent_id and not parent_covered:
            r.append(f"Parent {parent_id} is also uncovered")
        return r

    # ── Public interface ──────────────────────────────────────────────────────

    def analyze(
        self,
        detections: list[CanonicalDetection],
        include_subtechniques: bool = True,
    ) -> list[PriorityGap]:
        """
        Return a ``PriorityGap`` for every ATT&CK technique not covered by
        *detections*, sorted descending by composite score.

        Parameters
        ----------
        detections:
            The current rule corpus to measure gaps against.
        include_subtechniques:
            When False, only base techniques (T1xxx, no dot) are evaluated.
        """
        covered = self._covered_ids(detections)
        all_techniques = self._kb.get_all_techniques(
            include_deprecated=False,
            include_subtechniques=include_subtechniques,
        )

        gaps: list[PriorityGap] = []
        for tech in all_techniques:
            tid = tech.technique_id
            if tid in covered:
                continue  # already covered

            groups = len(self._kb.get_groups_using(tid))
            software = len(self._kb.get_software_using(tid))
            prevalence = groups + software

            parent_id = tech.parent_id
            parent_covered = bool(parent_id and parent_id in covered)
            parent_max_severity: str | None = None
            if parent_covered and parent_id:
                parent_max_severity = self._max_severity(covered[parent_id])

            tactic = tech.tactic
            score = self._score(tid, tactic, prevalence, parent_covered, parent_max_severity)
            reasons = self._reasons(
                tid, tactic, prevalence, groups, software,
                parent_covered, parent_id, parent_max_severity,
            )

            gaps.append(PriorityGap(
                technique_id=tid,
                name=tech.name,
                tactic=tactic,
                score=score,
                prevalence=prevalence,
                tactic_weight=_TACTIC_WEIGHTS.get(tactic, _DEFAULT_TACTIC_WEIGHT),
                parent_id=parent_id,
                parent_covered=parent_covered,
                parent_max_severity=parent_max_severity,
                reasons=reasons,
            ))

        gaps.sort(key=lambda g: g.score, reverse=True)
        return gaps

    def top_gaps(
        self,
        detections: list[CanonicalDetection],
        n: int = 10,
        include_subtechniques: bool = True,
    ) -> list[PriorityGap]:
        """Return the top-*n* highest-priority gaps."""
        return self.analyze(detections, include_subtechniques=include_subtechniques)[:n]

    def tactic_weights(self) -> dict[str, int]:
        """Expose the tactic weight table (useful for testing and documentation)."""
        return dict(_TACTIC_WEIGHTS)
