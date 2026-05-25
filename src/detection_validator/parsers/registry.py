"""
ParserRegistry — discovers the right parser for a given file.

Priority order:
  1. SplunkSecurityContentParser  (before SigmaParser — both .yml but SSC has ``search:`` + ``mitre_attack_id:``)
  2. SigmaParser                  (.yml/.yaml with detection: + logsource:)
  3. KQLParser                    (.kql or Sentinel .yml with query:)
  4. SplunkParser                 (.conf or .spl)
  5. ElasticEQLParser             (.toml or Elastic .json)
  6. YARAParser                   (.yar/.yara or content with ``rule ``)
  7. GenericYAMLParser            (catch-all for .yml/.yaml)

Usage::

    from detection_validator.parsers.registry import ParserRegistry

    registry = ParserRegistry()
    detection = registry.parse_file(Path("rule.yml"))
    detections = list(registry.parse_directory(Path("detections/")))
"""

from __future__ import annotations

import logging
import warnings
from pathlib import Path
from typing import Iterator

from detection_validator.normalizer.schema import CanonicalDetection
from detection_validator.parsers.base import BaseParser, ParseError, PartialParseWarning
from detection_validator.parsers.elastic_eql import ElasticEQLParser
from detection_validator.parsers.generic_yaml import GenericYAMLParser
from detection_validator.parsers.kql import KQLParser
from detection_validator.parsers.sigma import SigmaParser
from detection_validator.parsers.splunk import SplunkParser
from detection_validator.parsers.splunk_security_content import SplunkSecurityContentParser
from detection_validator.parsers.yara_parser import YARAParser

logger = logging.getLogger(__name__)

# File extensions that are definitely not detection rules
_SKIP_EXTENSIONS = frozenset({
    ".md", ".txt", ".rst", ".html", ".pdf",
    ".png", ".jpg", ".gif", ".svg",
    ".py", ".go", ".js", ".ts",
    ".sh", ".bat", ".ps1",
    ".lock", ".sum",
})


class ParserRegistry:
    """
    Central registry of all available detection parsers.

    Parsers are tried in priority order; the first one whose ``can_parse()``
    returns True is used.  ``GenericYAMLParser`` is always last and accepts
    any YAML file.
    """

    def __init__(self, extra_parsers: list[BaseParser] | None = None) -> None:
        self._parsers: list[BaseParser] = [
            SplunkSecurityContentParser(),
            SigmaParser(),
            KQLParser(),
            SplunkParser(),
            ElasticEQLParser(),
            YARAParser(),
            GenericYAMLParser(),
        ]
        if extra_parsers:
            # Insert before GenericYAMLParser catch-all
            self._parsers = self._parsers[:-1] + extra_parsers + [self._parsers[-1]]

    # ── Public interface ──────────────────────────────────────────────────────

    def find_parser(self, file_path: Path) -> BaseParser | None:
        """Return the first parser that can handle *file_path*, or None."""
        if file_path.suffix.lower() in _SKIP_EXTENSIONS:
            return None
        for parser in self._parsers:
            try:
                if parser.can_parse(file_path):
                    return parser
            except Exception:
                logger.debug("Parser %s raised during can_parse(%s)", parser.name, file_path)
        return None

    def parse_file(self, path: Path) -> CanonicalDetection:
        """
        Auto-detect format and parse *path*.

        Raises ``ParseError`` if no parser claims the file or parsing fails.
        """
        parser = self.find_parser(path)
        if parser is None:
            raise ParseError(f"No parser found for file", path=path)
        logger.debug("Parsing %s with %s", path, parser.name)
        return parser.parse_file(path)

    def parse_directory(
        self,
        directory: Path,
        recursive: bool = True,
        strict: bool = False,
    ) -> Iterator[CanonicalDetection]:
        """
        Yield ``CanonicalDetection`` objects for all parseable files under *directory*.

        Parameters
        ----------
        directory:
            Root directory to scan.
        recursive:
            If True (default), descend into subdirectories.
        strict:
            If True, raise on first parse error instead of logging and continuing.
        """
        glob = directory.rglob("*") if recursive else directory.glob("*")
        for path in sorted(glob):
            if not path.is_file():
                continue
            if path.suffix.lower() in _SKIP_EXTENSIONS:
                continue

            parser = self.find_parser(path)
            if parser is None:
                continue

            try:
                yield parser.parse_file(path)
            except ParseError as exc:
                if strict:
                    raise
                logger.warning("ParseError for %s: %s", path, exc)
            except Exception as exc:
                if strict:
                    raise ParseError(f"Unexpected error", path=path, cause=exc) from exc
                logger.warning("Unexpected error parsing %s: %s", path, exc)

    def parse_content(
        self,
        content: str,
        source_path: Path | None = None,
        hint_format: str | None = None,
    ) -> CanonicalDetection:
        """
        Parse *content* string, optionally with a *source_path* hint.

        *hint_format* may be a parser name to skip auto-detection.
        """
        if hint_format:
            for parser in self._parsers:
                if parser.name == hint_format:
                    return parser.parse(content, source_path=source_path)
            raise ParseError(f"Unknown parser hint: {hint_format!r}")

        if source_path:
            return self.parse_file(source_path) if source_path.exists() else self._parse_from_content(content, source_path)
        return self._parse_from_content(content, source_path)

    def _parse_from_content(self, content: str, source_path: Path | None) -> CanonicalDetection:
        """Try parsers in order using content only (no filesystem access)."""
        # For content-only parsing, use suffix hint if available
        path_hint = source_path or Path("unknown.yml")
        for parser in self._parsers:
            try:
                if parser.can_parse(path_hint):
                    return parser.parse(content, source_path=source_path)
            except (ParseError, Exception):
                continue
        # Last resort: GenericYAMLParser
        return self._parsers[-1].parse(content, source_path=source_path)

    @property
    def parsers(self) -> list[BaseParser]:
        """All registered parsers in priority order."""
        return list(self._parsers)

    def __repr__(self) -> str:
        names = [p.name for p in self._parsers]
        return f"<ParserRegistry parsers={names}>"
