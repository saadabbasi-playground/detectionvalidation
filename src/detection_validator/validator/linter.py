"""Static linter — offline structural checks on detection rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class LintSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class LintFinding:
    rule_id: str
    severity: LintSeverity
    code: str
    message: str
    line: int | None = None


class DetectionLinter:
    """Base class for static detection rule checks."""

    def lint(self, rule) -> list[LintFinding]:
        raise NotImplementedError

    def lint_all(self, rules: list) -> dict[str, list[LintFinding]]:
        return {str(r.id): self.lint(r) for r in rules}

    def score(self, findings: list[LintFinding]) -> int:
        """Return 0-100 quality score.  Override in subclasses for custom weights."""
        raise NotImplementedError
