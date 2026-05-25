"""Synthetic event validator — injects crafted log events to test rules offline."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SyntheticResult:
    rule_id: str
    passed: bool
    injected_events: int
    matched_events: int
    false_positives: int


class SyntheticEventValidator:
    """Validate rules by injecting pre-crafted events without live attack execution."""

    def __init__(self, siem_backend) -> None:
        self.siem = siem_backend

    def validate_rule(self, rule, event_fixtures: list[dict] | None = None) -> SyntheticResult:
        raise NotImplementedError
