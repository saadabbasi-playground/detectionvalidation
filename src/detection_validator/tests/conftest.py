"""Pytest fixtures shared across the test suite."""

from __future__ import annotations

import pytest

from detection_validator.normalizer.schema import DetectionFormat, DetectionRule, Severity


@pytest.fixture()
def sample_rule() -> DetectionRule:
    return DetectionRule(
        id="test-rule-001",
        title="Test: PowerShell Encoded Command",
        description="Detects PowerShell execution with base64-encoded commands",
        source_format=DetectionFormat.SIGMA,
        severity=Severity.HIGH,
        tags=["attack.execution", "attack.t1059.001"],
        query="process.name:powershell AND process.args:*-EncodedCommand*",
    )


@pytest.fixture()
def sample_rules(sample_rule: DetectionRule) -> list[DetectionRule]:
    return [
        sample_rule,
        DetectionRule(
            id="test-rule-002",
            title="Test: Suspicious Network Connection",
            source_format=DetectionFormat.SIGMA,
            severity=Severity.MEDIUM,
            tags=["attack.command-and-control", "attack.t1071"],
            query="network.direction:outbound AND destination.port:(4444 OR 1337)",
        ),
    ]
