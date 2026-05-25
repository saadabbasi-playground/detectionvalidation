"""Coverage scoring — numeric and letter-grade coverage scores."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CoverageScore:
    total_techniques: int
    covered_techniques: int
    validated_techniques: int
    score_pct: float
    grade: str  # A-F

    @property
    def gap_pct(self) -> float:
        return 100.0 - self.score_pct


class CoverageScorer:
    """Compute a coverage score from a populated CoverageMatrix."""

    def score(self, matrix: dict) -> CoverageScore:
        raise NotImplementedError
