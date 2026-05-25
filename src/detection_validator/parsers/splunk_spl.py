"""Splunk SPL / savedsearches.conf parser stub."""

from __future__ import annotations

from pathlib import Path


class SplunkSPLParser:
    """Parse Splunk SPL saved-search definitions."""

    def parse_file(self, path: Path) -> list[dict]:
        """Parse a savedsearches.conf file into a list of search dicts."""
        raise NotImplementedError

    def parse_spl(self, spl: str) -> dict:
        """Parse a raw SPL query string."""
        raise NotImplementedError
