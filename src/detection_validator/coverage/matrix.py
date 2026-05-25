"""ATT&CK coverage matrix builder stub."""

from __future__ import annotations

from detection_validator.normalizer.schema import DetectionRule


class CoverageMatrix:
    """Build a per-tactic/technique coverage matrix from a rule set."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self.rules = rules
        self._matrix: dict[str, dict[str, list[str]]] = {}

    def build(self) -> dict[str, dict[str, list[str]]]:
        """Return ``{tactic: {technique_id: [rule_ids]}}``."""
        raise NotImplementedError

    def to_navigator_layer(self) -> dict:
        """Export as ATT&CK Navigator layer JSON."""
        raise NotImplementedError
