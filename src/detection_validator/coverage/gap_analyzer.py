"""Gap analyzer — surfaces ATT&CK techniques not covered by any detection rule."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Gap:
    technique_id: str
    tactic: str
    risk: str  # high | medium | low based on threat-intel frequency


class GapAnalyzer:
    """Identify coverage gaps and prioritise by threat-intel frequency."""

    def analyze(self, matrix: dict, all_techniques: list) -> list[Gap]:
        raise NotImplementedError

    def top_gaps(self, n: int = 10) -> list[Gap]:
        raise NotImplementedError
