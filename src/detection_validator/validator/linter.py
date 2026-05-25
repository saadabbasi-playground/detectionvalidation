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
    """Static checks: missing MITRE tags, overly broad queries, deprecated fields, etc."""

    def lint(self, rule) -> list[LintFinding]:
        raise NotImplementedError

    def lint_all(self, rules: list) -> dict[str, list[LintFinding]]:
        return {r.id: self.lint(r) for r in rules}
