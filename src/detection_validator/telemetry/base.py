"""TelemetrySource abstraction for replay and live event capture.

Sources are interchangeable: the validator calls ``ensure(technique_id, platform)``
and receives a ``TelemetryBatch`` regardless of whether the events came from a
pre-recorded PCAP/log replay or a live local capture agent.

Sysmon/ECS-aligned event fields mirror what ``query_gen.py`` targets when it
emits detection queries, so the same field names work end-to-end.

Note: docs/telemetry-schema.md does not exist in the repo — the canonical field
list is defined by ``TelemetryEvent`` below.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal


# ── Exceptions ────────────────────────────────────────────────────────────────


class NotAvailable(Exception):
    """Raised when a TelemetrySource cannot satisfy an ensure() request.

    Always constructed with a human-readable ``reason``; never a bare raise.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ── Core data types ───────────────────────────────────────────────────────────


@dataclass
class TelemetryEvent:
    """A single normalized event from any telemetry source.

    The Sysmon-style process fields (Image, CommandLine, …) match the field
    names that OpenSearch/Elastic/Splunk query_gen output targets via ECS
    mappings, keeping field names consistent end-to-end.
    """

    # Mandatory tracking fields
    technique_id: str
    source_fidelity: Literal["replay", "live"]
    timestamp: datetime

    # Sysmon / ECS process fields
    Image: str | None = None
    CommandLine: str | None = None
    ParentImage: str | None = None
    ParentCommandLine: str | None = None
    ProcessId: int | None = None
    User: str | None = None

    # Windows event log fields
    EventID: int | None = None
    Channel: str | None = None
    Computer: str | None = None

    # Arbitrary extra fields (e.g. network, file events)
    extra: dict = field(default_factory=dict)


@dataclass
class TelemetryBatch:
    """A collection of events produced by a single ensure() call."""

    technique_id: str
    source_name: str
    fidelity: Literal["replay", "live"]
    events: list[TelemetryEvent] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self):
        return iter(self.events)


# ── Source description ────────────────────────────────────────────────────────


@dataclass
class SourceDescription:
    """Static capabilities declared by a TelemetrySource."""

    name: str
    fidelity: Literal["replay", "live"]
    supported_platforms: list[str]


# ── Abstract interface ────────────────────────────────────────────────────────


class TelemetrySource(ABC):
    """Uniform interface for all telemetry providers."""

    @abstractmethod
    def describe(self) -> SourceDescription:
        """Return static capability metadata for this source."""

    @abstractmethod
    def ensure(self, technique_id: str, platform: str) -> TelemetryBatch:
        """Make telemetry available for *technique_id* on *platform*.

        Returns a ``TelemetryBatch`` whose events are tagged with
        ``technique_id`` and normalized to the ECS/Sysmon-aligned schema.

        Raises ``NotAvailable`` with a specific reason when the source cannot
        produce events (unsupported platform, missing replay file, agent not
        running, etc.).
        """


# ── Source registry ───────────────────────────────────────────────────────────


class SourceRegistry:
    """Named registry for TelemetrySource instances.

    Sources registered here are selectable via ``--source <name>`` in the CLI.
    """

    def __init__(self) -> None:
        self._sources: dict[str, TelemetrySource] = {}

    def register(self, name: str, source: TelemetrySource) -> None:
        """Register *source* under *name*. Overwrites any prior entry."""
        if not isinstance(source, TelemetrySource):
            raise TypeError(f"{source!r} is not a TelemetrySource")
        self._sources[name] = source

    def get(self, name: str) -> TelemetrySource:
        """Return the source registered under *name*.

        Raises ``KeyError`` with the available names when *name* is unknown.
        """
        try:
            return self._sources[name]
        except KeyError:
            available = ", ".join(sorted(self._sources)) or "<none>"
            raise KeyError(
                f"Unknown telemetry source {name!r}. Available: {available}"
            ) from None

    def list_sources(self) -> list[str]:
        """Return sorted list of registered source names."""
        return sorted(self._sources)


# ── Stub implementations ──────────────────────────────────────────────────────

# ReplaySource is imported from replay.py so the real implementation is used
# everywhere. The import is at module bottom to avoid a circular dependency
# (replay.py imports from this file).


class LiveLocalSource(TelemetrySource):
    """Stub live-capture source — hooks into a local capture agent.

    Implementation is deferred; currently only declares capabilities.
    Call ``ensure()`` to receive ``NotAvailable`` until the agent is wired in.
    """

    def describe(self) -> SourceDescription:
        return SourceDescription(
            name="live-local",
            fidelity="live",
            supported_platforms=["linux"],
        )

    def ensure(self, technique_id: str, platform: str) -> TelemetryBatch:
        raise NotAvailable(
            f"LiveLocalSource capture agent is not running "
            f"(technique={technique_id}, platform={platform})"
        )


# ── Real ReplaySource (import deferred to avoid circular dependency) ──────────

from detection_validator.telemetry.replay import ReplaySource  # noqa: E402


# ── Default global registry ───────────────────────────────────────────────────

registry = SourceRegistry()
registry.register("replay", ReplaySource())
registry.register("live-local", LiveLocalSource())
