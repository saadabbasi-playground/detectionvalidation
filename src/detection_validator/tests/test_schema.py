"""Smoke tests for legacy DetectionRule + health_check."""

from __future__ import annotations

import pytest

from detection_validator.normalizer.schema import (
    DetectionFormat,
    DetectionRule,
    LegacySeverity,
)


def test_detection_rule_defaults() -> None:
    rule = DetectionRule(id="r001", title="Test Rule")
    assert rule.enabled is True
    assert rule.severity == LegacySeverity.MEDIUM
    assert rule.source_format == DetectionFormat.UNKNOWN
    assert rule.mitre == []


def test_detection_rule_from_dict() -> None:
    data = {
        "id": "r002",
        "title": "SPL Rule",
        "source_format": "spl",
        "severity": "high",
        "query": "index=main eventcode=4624",
    }
    rule = DetectionRule(**data)
    assert rule.source_format == DetectionFormat.SPL
    assert rule.severity == LegacySeverity.HIGH


def test_health_check_importable() -> None:
    from detection_validator import health_check

    health_check()
