"""Abstract base class for SIEM adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class SIEMBackend(ABC):
    """Uniform interface every SIEM adapter must implement."""

    name: str = "base"

    @abstractmethod
    def connect(self) -> None:
        """Establish and verify connectivity to the SIEM."""

    @abstractmethod
    def health_check(self) -> bool:
        """Return True if the backend is reachable and healthy."""

    @abstractmethod
    def deploy_rule(self, rule: Any) -> str:
        """Deploy a detection rule; return the backend-assigned rule ID."""

    @abstractmethod
    def delete_rule(self, rule_id: str) -> None:
        """Remove a deployed rule by ID."""

    @abstractmethod
    def query(self, query_string: str, time_range: str = "last 1h") -> list[dict]:
        """Execute a raw query and return matching events."""

    @abstractmethod
    def search_for_alerts(self, rule_id: str, time_range: str = "last 1h") -> list[dict]:
        """Return alerts fired by *rule_id* within *time_range*."""

    @abstractmethod
    def translate_rule(self, rule: Any) -> str:
        """Convert a canonical DetectionRule to the backend's native query syntax."""
