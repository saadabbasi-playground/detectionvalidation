"""
Generic YAML parser with configurable field mapping.

Reads a field-mapping spec from ``configs/custom_format_map.yaml`` (or a
path supplied at runtime) and translates arbitrary YAML detection formats
into ``CanonicalDetection``.

Field map format (YAML)::

    field_map:
      id: rule_id
      name: title
      description: desc
      author: author
      severity: risk_level
      query: detection.search
      techniques: tags.attack
      platforms: os
    defaults:
      source_format: custom
      severity: medium
"""

from __future__ import annotations

import re
import warnings
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from detection_validator.normalizer.schema import (
    CanonicalDetection,
    DetectionFormat,
    LogSource,
    Platform,
    Severity,
    ValidationStatus,
)
from detection_validator.parsers.base import (
    BaseParser,
    ParseError,
    PartialParseWarning,
    cves_to_models,
    extract_cves_from_text,
    extract_techniques_from_text,
    make_detection_logic,
    normalise_severity,
    techniques_to_models,
)

_DEFAULT_FIELD_MAP: dict[str, str] = {
    "id": "id",
    "name": "name",
    "description": "description",
    "author": "author",
    "severity": "severity",
    "query": "query",
    "techniques": "techniques",
    "platforms": "platforms",
    "tags": "tags",
    "false_positives": "false_positives",
    "version": "version",
}

_DEFAULT_FORMAT_MAP_PATH = Path("configs/custom_format_map.yaml")

_PLATFORM_ALIASES: dict[str, Platform] = {
    "windows": Platform.WINDOWS,
    "win": Platform.WINDOWS,
    "linux": Platform.LINUX,
    "macos": Platform.MACOS,
    "mac": Platform.MACOS,
    "osx": Platform.MACOS,
    "cloud": Platform.CLOUD,
    "aws": Platform.CLOUD,
    "azure": Platform.CLOUD,
    "gcp": Platform.CLOUD,
    "network": Platform.NETWORK,
    "containers": Platform.CONTAINERS,
    "docker": Platform.CONTAINERS,
    "k8s": Platform.CONTAINERS,
}


def _load_format_map(path: Path | None) -> tuple[dict[str, str], dict[str, Any]]:
    """Load and return (field_map, defaults) from the YAML config."""
    if path is None:
        path = _DEFAULT_FORMAT_MAP_PATH
    if not path.exists():
        return _DEFAULT_FIELD_MAP.copy(), {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return _DEFAULT_FIELD_MAP.copy(), {}
    field_map = {**_DEFAULT_FIELD_MAP, **(data.get("field_map") or {})}
    defaults = data.get("defaults") or {}
    return field_map, defaults


def _deep_get(obj: Any, dotted_key: str) -> Any:
    """Traverse nested dicts using dot-separated key path."""
    parts = dotted_key.split(".")
    cur = obj
    for part in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _coerce_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    if isinstance(val, str):
        return [v.strip() for v in re.split(r"[,;]", val) if v.strip()]
    return [str(val)]


def _coerce_platforms(val: Any) -> list[Platform]:
    raw_list = _coerce_list(val)
    platforms: list[Platform] = []
    for raw in raw_list:
        p = _PLATFORM_ALIASES.get(raw.lower().strip())
        if p:
            platforms.append(p)
    return platforms


class GenericYAMLParser(BaseParser):
    """
    Fallback YAML parser that uses a configurable field mapping.

    When no other parser claims a ``.yml``/``.yaml`` file, this parser applies
    a field-map config (``configs/custom_format_map.yaml``) to extract fields
    and build a ``CanonicalDetection``.
    """

    name = "generic_yaml"
    supported_extensions = (".yml", ".yaml")

    def __init__(self, format_map_path: Path | None = None) -> None:
        self._format_map_path = format_map_path
        self._field_map, self._defaults = _load_format_map(format_map_path)

    def reload_map(self, path: Path | None = None) -> None:
        """Reload the field mapping from disk."""
        self._format_map_path = path or self._format_map_path
        self._field_map, self._defaults = _load_format_map(self._format_map_path)

    def can_parse(self, file_path: Path) -> bool:
        """Accept any YAML file — this is a catch-all fallback."""
        return file_path.suffix.lower() in (".yml", ".yaml")

    def parse(
        self,
        content: str,
        source_path: Path | None = None,
    ) -> CanonicalDetection:
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise ParseError("Invalid YAML", path=source_path, cause=exc) from exc
        if not isinstance(data, dict):
            raise ParseError("YAML did not produce a mapping", path=source_path)

        fm = self._field_map
        defs = self._defaults

        def get(canonical_key: str) -> Any:
            mapped = fm.get(canonical_key, canonical_key)
            return _deep_get(data, mapped)

        rule_id = str(get("id") or uuid4())
        name = str(get("name") or (source_path.stem if source_path else "generic_rule"))
        description = str(get("description") or "")
        author_raw = get("author") or defs.get("author", "unknown")
        author: str | list[str] = (
            [a.strip() for a in author_raw.split(",")]
            if isinstance(author_raw, str) and "," in author_raw
            else author_raw or "unknown"
        )
        version = str(get("version") or "1.0")

        severity_raw = get("severity") or defs.get("severity")
        severity = normalise_severity(str(severity_raw) if severity_raw else None)

        query_raw = get("query") or ""
        query = str(query_raw) if query_raw else ""

        technique_vals = _coerce_list(get("techniques"))
        cve_vals = _coerce_list(get("cves") or get("cve"))
        platform_vals = get("platforms")
        tags_raw = _coerce_list(get("tags"))
        fp_raw = _coerce_list(get("false_positives"))

        combined = f"{name} {description} {query} {' '.join(technique_vals)}"
        all_techs = list(dict.fromkeys(
            technique_vals + extract_techniques_from_text(combined)
        ))
        all_cves = list(dict.fromkeys(
            cve_vals + extract_cves_from_text(combined)
        ))

        platforms = _coerce_platforms(platform_vals)

        source_format_raw = defs.get("source_format", "custom")
        try:
            source_format = DetectionFormat(source_format_raw)
        except ValueError:
            source_format = DetectionFormat.CUSTOM

        logic = make_detection_logic(
            raw=query or content[:500],
            language=defs.get("language", "unknown"),
            field_refs=[],
            conditions=[query.strip().splitlines()[0]] if query.strip() else [],
        )

        if not query:
            warnings.warn(
                f"Generic YAML rule has no query field [{source_path}]",
                PartialParseWarning,
                stacklevel=2,
            )

        return CanonicalDetection(
            id=rule_id,
            name=name,
            description=description,
            author=author,
            version=version,
            severity=severity,
            source_format=source_format,
            platforms=platforms,
            tags=tags_raw,
            detection_logic=logic,
            log_sources=[],
            mitre_techniques=techniques_to_models(all_techs),
            cve_references=cves_to_models(all_cves),
            data_components=[],
            false_positive_notes=fp_raw,
            cim_models=[],
            validation_status=ValidationStatus.UNTESTED,
        )
