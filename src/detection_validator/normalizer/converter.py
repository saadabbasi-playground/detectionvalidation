"""Format-to-schema converters stub."""

from __future__ import annotations

from typing import Any

from detection_validator.normalizer.schema import DetectionFormat, DetectionRule


class SigmaConverter:
    """Convert a parsed Sigma dict into a ``DetectionRule``."""

    def convert(self, raw: dict[str, Any]) -> DetectionRule:
        raise NotImplementedError


class SPLConverter:
    """Convert a parsed SPL saved-search dict into a ``DetectionRule``."""

    def convert(self, raw: dict[str, Any]) -> DetectionRule:
        raise NotImplementedError


class KQLConverter:
    """Convert a parsed KQL query into a ``DetectionRule``."""

    def convert(self, raw: dict[str, Any]) -> DetectionRule:
        raise NotImplementedError


def auto_convert(raw: dict[str, Any], fmt: DetectionFormat = DetectionFormat.UNKNOWN) -> DetectionRule:
    """Detect format and delegate to the appropriate converter."""
    raise NotImplementedError
