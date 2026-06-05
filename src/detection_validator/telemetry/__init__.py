"""Telemetry abstraction layer for detection validation."""

from detection_validator.telemetry.base import (
    LiveLocalSource,
    NotAvailable,
    ReplaySource,
    SourceDescription,
    SourceRegistry,
    TelemetryBatch,
    TelemetryEvent,
    TelemetrySource,
    registry,
)
from detection_validator.telemetry.indexer import bulk_index, index_name_for
from detection_validator.telemetry.normalizer import normalize_events, normalize_otrf_event

__all__ = [
    "NotAvailable",
    "TelemetryEvent",
    "TelemetryBatch",
    "SourceDescription",
    "TelemetrySource",
    "SourceRegistry",
    "ReplaySource",
    "LiveLocalSource",
    "registry",
    "bulk_index",
    "index_name_for",
    "normalize_events",
    "normalize_otrf_event",
]
