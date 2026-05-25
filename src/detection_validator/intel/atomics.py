"""Atomic Red Team test index cache."""

from __future__ import annotations

from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "detection-validator" / "atomics"
ART_INDEX_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml"


class AtomicsIntel:
    """Index of available Atomic Red Team tests, keyed by ATT&CK technique ID."""

    def __init__(self, cache_dir: Path = CACHE_DIR) -> None:
        self.cache_dir = cache_dir

    def refresh(self, force: bool = False) -> None:
        raise NotImplementedError

    def tests_for_technique(self, technique_id: str) -> list[dict]:
        """Return ART test definitions for *technique_id*."""
        raise NotImplementedError

    def all_techniques_with_tests(self) -> list[str]:
        raise NotImplementedError
