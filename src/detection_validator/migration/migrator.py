"""Migration orchestrator stub."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MigrationPlan:
    source_siem: str
    target_siem: str
    rules_total: int
    rules_translatable: int
    rules_needs_review: int
    rules_untranslatable: int
    confidence_scores: dict[str, float] = field(default_factory=dict)


class SIEMMigrator:
    """Orchestrate rule migration from one SIEM to another."""

    def __init__(self, source_backend, target_backend) -> None:
        self.source = source_backend
        self.target = target_backend

    def plan(self, rule_ids: list[str] | None = None) -> MigrationPlan:
        raise NotImplementedError

    def execute(self, plan: MigrationPlan, dry_run: bool = True) -> dict:
        raise NotImplementedError
