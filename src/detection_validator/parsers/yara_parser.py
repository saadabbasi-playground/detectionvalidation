"""
YARA rule parser.

Uses the ``yara-python`` library for validation and metadata extraction when
available; falls back to regex-based parsing when it is not installed.

YARA rules look like::

    rule SuspiciousPowerShell : powershell execution {
        meta:
            description = "Detects suspicious PowerShell usage"
            author = "Detection Team"
            severity = "high"
            technique = "T1059.001"
            reference = "CVE-2021-34527"
        strings:
            $cmd = "IEX" nocase
            $enc = "-EncodedCommand" nocase
        condition:
            any of them
    }
"""

from __future__ import annotations

import re
import warnings
from pathlib import Path
from uuid import uuid4

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

try:
    import yara  # type: ignore[import-untyped]

    HAS_YARA = True
except ImportError:
    HAS_YARA = False

# ── Regex-based YARA parsing ──────────────────────────────────────────────────

# Match rule NAME and optional TAGS: `rule Name : tag1 tag2 {`
_RULE_HEADER_RE = re.compile(
    r"^\s*(?:private\s+|global\s+)?rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{",
    re.MULTILINE,
)

# Match meta key = "value" or key = number
_META_KV_RE = re.compile(
    r'^\s*(\w+)\s*=\s*(?:"([^"]*)"|(\d+))',
    re.MULTILINE,
)

# Extract the meta section content
_META_SECTION_RE = re.compile(r"\bmeta\s*:(.*?)(?:strings\s*:|condition\s*:)", re.DOTALL)

# Extract the condition section
_CONDITION_RE = re.compile(r"\bcondition\s*:(.*?)(?=\n\s*\}|\Z)", re.DOTALL)

# Extract strings section
_STRINGS_SECTION_RE = re.compile(r"\bstrings\s*:(.*?)(?:condition\s*:)", re.DOTALL)
_STRING_DEF_RE = re.compile(r"^\s*(\$\w+)\s*=\s*(.+)$", re.MULTILINE)


def _parse_meta_section(rule_text: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    m = _META_SECTION_RE.search(rule_text)
    if not m:
        return meta
    for kv in _META_KV_RE.finditer(m.group(1)):
        key = kv.group(1)
        val = kv.group(2) if kv.group(2) is not None else kv.group(3)
        meta[key] = val or ""
    return meta


def _parse_condition(rule_text: str) -> str:
    m = _CONDITION_RE.search(rule_text)
    return m.group(1).strip() if m else ""


def _parse_string_names(rule_text: str) -> list[str]:
    m = _STRINGS_SECTION_RE.search(rule_text)
    if not m:
        return []
    return [sm.group(1) for sm in _STRING_DEF_RE.finditer(m.group(1))]


def _yara_regex_parse(content: str, source_path: Path | None) -> CanonicalDetection:
    """Parse a YARA rule file using regex (no yara-python required)."""
    headers = list(_RULE_HEADER_RE.finditer(content))
    if not headers:
        raise ParseError("No YARA rule definitions found", path=source_path)

    if len(headers) > 1:
        warnings.warn(
            f"YARA file has {len(headers)} rules; parsing first only [{source_path}]",
            PartialParseWarning,
            stacklevel=2,
        )

    m = headers[0]
    rule_name = m.group(1)
    rule_tags_raw = (m.group(2) or "").split()

    meta = _parse_meta_section(content)
    condition = _parse_condition(content)
    string_names = _parse_string_names(content)

    description = meta.get("description", "")
    author = meta.get("author", "unknown")
    severity = normalise_severity(meta.get("severity") or meta.get("level"))

    # Techniques from meta fields and rule body
    tech_text = " ".join([
        meta.get("technique", ""),
        meta.get("mitre_technique", ""),
        meta.get("tags", ""),
        rule_name,
        description,
    ])
    technique_ids = extract_techniques_from_text(tech_text)

    cve_text = " ".join([
        meta.get("reference", ""),
        meta.get("cve", ""),
        description,
    ])
    cve_ids = extract_cves_from_text(cve_text)

    logic = make_detection_logic(
        raw=content,
        language="yara",
        field_refs=string_names,
        conditions=[condition] if condition else [],
    )

    rule_id = meta.get("id") or str(uuid4())

    # YARA rules are primarily for file/memory scanning — platform is broad
    platform_hint = meta.get("platform", "").lower()
    platforms: list[Platform] = []
    if "windows" in platform_hint:
        platforms.append(Platform.WINDOWS)
    elif "linux" in platform_hint:
        platforms.append(Platform.LINUX)
    elif "macos" in platform_hint or "mac" in platform_hint:
        platforms.append(Platform.MACOS)

    return CanonicalDetection(
        id=rule_id,
        name=rule_name,
        description=description,
        author=author,
        version=meta.get("version", "1.0"),
        severity=severity,
        source_format=DetectionFormat.YARA,
        platforms=platforms,
        tags=rule_tags_raw,
        detection_logic=logic,
        log_sources=[],
        mitre_techniques=techniques_to_models(technique_ids),
        cve_references=cves_to_models(cve_ids),
        data_components=[],
        false_positive_notes=[],
        cim_models=[],
        # YARA rules score low on portability (format-specific)
        portability_score=20.0,
        validation_status=ValidationStatus.UNTESTED,
    )


def _yara_lib_parse(content: str, source_path: Path | None) -> CanonicalDetection:
    """Parse using yara-python for syntax validation + metadata extraction."""
    try:
        rules = yara.compile(source=content)
    except yara.SyntaxError as exc:
        raise ParseError(f"YARA syntax error: {exc}", path=source_path, cause=exc) from exc

    # yara-python doesn't give us metadata directly from source text,
    # so we still use regex for extraction; yara validates syntax.
    return _yara_regex_parse(content, source_path)


class YARAParser(BaseParser):
    """
    Parse YARA detection rules.

    Validates syntax with yara-python when installed; always extracts
    metadata, strings, and conditions via regex parsing.
    """

    name = "yara"
    supported_extensions = (".yar", ".yara")

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() in self.supported_extensions:
            return True
        # Content sniff: look for `rule ` keyword
        return self._sniff(file_path, ["rule "])

    def parse(
        self,
        content: str,
        source_path: Path | None = None,
    ) -> CanonicalDetection:
        if HAS_YARA:
            return _yara_lib_parse(content, source_path)
        return _yara_regex_parse(content, source_path)
