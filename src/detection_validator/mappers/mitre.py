"""MITRE ATT&CK mapper — resolves technique IDs to full ATT&CK metadata."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TechniqueInfo:
    id: str
    name: str
    tactic: str
    url: str
    sub_techniques: list[str] = field(default_factory=list)


class MitreMapper:
    """Map ATT&CK technique IDs to structured metadata.

    Data is loaded lazily from the intel cache (``detection_validator.intel.mitre``).
    """

    def __init__(self) -> None:
        self._cache: dict[str, TechniqueInfo] = {}

    def load(self) -> None:
        """Populate the internal cache from the local intel store."""
        raise NotImplementedError

    def get(self, technique_id: str) -> TechniqueInfo | None:
        """Return metadata for *technique_id* or None if unknown."""
        raise NotImplementedError

    def tactic_for(self, technique_id: str) -> str | None:
        """Return the primary tactic name for a technique ID."""
        info = self.get(technique_id)
        return info.tactic if info else None

    def all_techniques(self) -> list[TechniqueInfo]:
        """Return every known technique."""
        raise NotImplementedError
