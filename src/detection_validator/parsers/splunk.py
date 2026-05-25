"""
Splunk parser — handles both savedsearches.conf stanzas and bare .spl files.

savedsearches.conf stanzas look like::

    [Rule Name]
    search = index=main EventCode=4624 ...
    action.email.to = ...
    alert.severity = 3

Bare .spl files contain a single SPL query (may span multiple lines).
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
    extract_cves_from_text,
    extract_techniques_from_text,
    make_detection_logic,
    normalise_severity,
    cves_to_models,
    techniques_to_models,
)

# Splunk alert_severity 1-5 numeric → Severity
_SPLUNK_SEVERITY_NUM: dict[str, Severity] = {
    "1": Severity.INFO,
    "2": Severity.LOW,
    "3": Severity.MED,
    "4": Severity.HIGH,
    "5": Severity.CRITICAL,
}

# Common SPL field names that hint at CIM models
_CIM_FIELD_HINTS: dict[str, str] = {
    "process_name": "Endpoint.Processes",
    "process": "Endpoint.Processes",
    "dest": "Network_Traffic",
    "src": "Network_Traffic",
    "bytes_in": "Network_Traffic",
    "bytes_out": "Network_Traffic",
    "user": "Authentication",
    "action": "Authentication",
    "file_name": "Endpoint.Filesystem",
    "registry_key_name": "Endpoint.Registry",
    "dns_query": "Network_Resolution",
}

# Regex to find `index=X` or `sourcetype=X`
_INDEX_RE = re.compile(r"\bindex\s*=\s*(\S+)", re.IGNORECASE)
_SOURCETYPE_RE = re.compile(r"\bsourcetype\s*=\s*(\S+)", re.IGNORECASE)
_EVENTCODE_RE = re.compile(r"\bEventCode\s*=\s*(\d+)", re.IGNORECASE)

# Match INI section headers [Name]
_SECTION_RE = re.compile(r"^\[([^\]]+)\]", re.MULTILINE)
# Match key = value pairs (value may span lines via continuation)
_KV_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9_.]*)\s*=\s*(.*)", re.MULTILINE)


def _parse_conf_stanzas(content: str) -> list[dict[str, str]]:
    """Parse a savedsearches.conf into a list of stanza dicts."""
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    current_key: str | None = None

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            current_key = None
            continue
        m = _SECTION_RE.match(stripped)
        if m:
            current = {"__name__": m.group(1)}
            current_key = None
            stanzas.append(current)
            continue
        if current is None:
            continue
        kv = _KV_RE.match(stripped)
        if kv:
            current_key = kv.group(1)
            current[current_key] = kv.group(2).rstrip("\\").strip()
        elif current_key and line.startswith((" ", "\t")):
            # continuation line
            current[current_key] = current[current_key] + " " + stripped.rstrip("\\").strip()
        else:
            current_key = None

    return [s for s in stanzas if "__name__" in s and s["__name__"] != "default"]


def _infer_severity_from_stanza(stanza: dict[str, str]) -> Severity:
    """Try alert.severity (numeric 1-5) then custom tags/description."""
    num = stanza.get("alert.severity", "").strip()
    if num in _SPLUNK_SEVERITY_NUM:
        return _SPLUNK_SEVERITY_NUM[num]
    # try text from dispatchAs / description
    desc = stanza.get("description", "") or stanza.get("action.email.subject", "")
    return normalise_severity(desc if desc else None)


def _spl_to_logic(spl: str) -> tuple[str, list[str], list[str]]:
    """
    Extract field references and table/index log sources from SPL.

    Returns (raw_spl, field_refs, conditions).
    """
    # Extract `| fields X, Y` and `| eval X` references
    field_re = re.compile(r"\|\s*fields\s+([\w,\s]+)", re.IGNORECASE)
    eval_re = re.compile(r"\|\s*eval\s+(\w+)\s*=", re.IGNORECASE)
    where_re = re.compile(r"\|\s*where\s+(.+?)(?:\||$)", re.IGNORECASE | re.DOTALL)
    stats_by_re = re.compile(r"\bby\s+([\w,\s]+)", re.IGNORECASE)

    field_refs: list[str] = []
    for m in field_re.finditer(spl):
        field_refs.extend(f.strip() for f in m.group(1).split(","))
    for m in eval_re.finditer(spl):
        field_refs.append(m.group(1))
    for m in stats_by_re.finditer(spl):
        field_refs.extend(f.strip() for f in m.group(1).split(","))

    conditions: list[str] = []
    for m in where_re.finditer(spl):
        cond = m.group(1).strip()
        if cond:
            conditions.append(cond)

    # first line / main search is a condition too
    first_line = spl.strip().splitlines()[0] if spl.strip() else ""
    if first_line:
        conditions.insert(0, first_line[:200])

    return spl, list(dict.fromkeys(field_refs)), conditions


def _infer_cim_models(spl: str) -> list[str]:
    """Guess CIM data models referenced in the SPL query."""
    models: set[str] = set()
    # `datamodel:Network_Traffic.Network_Traffic`
    dm_re = re.compile(r"datamodel[:\s]+(\w+)", re.IGNORECASE)
    for m in dm_re.finditer(spl):
        models.add(m.group(1))
    # field-name hints
    for field, model in _CIM_FIELD_HINTS.items():
        if re.search(rf"\b{re.escape(field)}\b", spl, re.IGNORECASE):
            models.add(model)
    return sorted(models)


def _logsource_from_spl(spl: str) -> list[LogSource]:
    sources: list[LogSource] = []
    for m in _INDEX_RE.finditer(spl):
        sources.append(LogSource(product=f"index={m.group(1)}"))
    for m in _SOURCETYPE_RE.finditer(spl):
        sources.append(LogSource(service=m.group(1)))
    return sources[:3]  # cap to 3 distinct sources


def _stanza_to_detection(stanza: dict[str, str], source_path: Path | None) -> CanonicalDetection:
    name = stanza.get("__name__", "")
    if not name:
        raise ParseError("Savedsearches stanza has no name", path=source_path)

    spl = stanza.get("search", "").strip()
    description = stanza.get("description", "")
    severity = _infer_severity_from_stanza(stanza)

    raw_spl, field_refs, conditions = _spl_to_logic(spl)
    logic = make_detection_logic(
        raw=raw_spl or "(empty)",
        language="spl",
        field_refs=field_refs,
        conditions=conditions,
    )

    combined_text = f"{name} {description} {spl}"
    technique_ids = extract_techniques_from_text(combined_text)
    cve_ids = extract_cves_from_text(combined_text)

    mitre_techniques = techniques_to_models(technique_ids)
    cve_references = cves_to_models(cve_ids)
    cim_models = _infer_cim_models(spl)
    log_sources = _logsource_from_spl(spl)

    return CanonicalDetection(
        id=str(uuid4()),
        name=name,
        description=description,
        author=stanza.get("action.email.to", "unknown"),
        version="1.0",
        severity=severity,
        source_format=DetectionFormat.SPLUNK_SPL,
        platforms=[Platform.WINDOWS],
        tags=[],
        detection_logic=logic,
        log_sources=log_sources,
        mitre_techniques=mitre_techniques,
        cve_references=cve_references,
        data_components=[],
        false_positive_notes=[],
        cim_models=cim_models,
        validation_status=ValidationStatus.UNTESTED,
    )


def _spl_file_to_detection(spl: str, source_path: Path | None) -> CanonicalDetection:
    name = source_path.stem if source_path else "spl_rule"
    raw_spl, field_refs, conditions = _spl_to_logic(spl)
    logic = make_detection_logic(
        raw=raw_spl or "(empty)",
        language="spl",
        field_refs=field_refs,
        conditions=conditions,
    )

    technique_ids = extract_techniques_from_text(spl)
    cve_ids = extract_cves_from_text(spl)

    return CanonicalDetection(
        id=str(uuid4()),
        name=name,
        description="",
        author="unknown",
        version="1.0",
        severity=Severity.MED,
        source_format=DetectionFormat.SPLUNK_SPL,
        platforms=[],
        tags=[],
        detection_logic=logic,
        log_sources=_logsource_from_spl(spl),
        mitre_techniques=techniques_to_models(technique_ids),
        cve_references=cves_to_models(cve_ids),
        data_components=[],
        false_positive_notes=[],
        cim_models=_infer_cim_models(spl),
        validation_status=ValidationStatus.UNTESTED,
    )


class SplunkParser(BaseParser):
    """
    Parse Splunk SPL detection rules from:

    - ``savedsearches.conf`` — INI-style stanza files (returns first stanza)
    - ``*.spl`` / ``*.spl.conf`` — raw SPL query files
    """

    name = "splunk"
    supported_extensions = (".conf", ".spl")

    def can_parse(self, file_path: Path) -> bool:
        suffix = file_path.suffix.lower()
        if suffix == ".conf":
            return self._sniff(file_path, ["search =", "["], required_all=True)
        if suffix == ".spl":
            return True
        return False

    def parse(
        self,
        content: str,
        source_path: Path | None = None,
    ) -> CanonicalDetection:
        suffix = source_path.suffix.lower() if source_path else ""

        if suffix == ".spl" or not content.lstrip().startswith("["):
            # Bare SPL file
            return _spl_file_to_detection(content.strip(), source_path)

        # savedsearches.conf — return the first non-default stanza
        stanzas = _parse_conf_stanzas(content)
        if not stanzas:
            raise ParseError(
                "No stanzas found in savedsearches.conf",
                path=source_path,
            )

        if len(stanzas) > 1:
            warnings.warn(
                f"savedsearches.conf has {len(stanzas)} stanzas; parsing first only [{source_path}]",
                PartialParseWarning,
                stacklevel=2,
            )

        return _stanza_to_detection(stanzas[0], source_path)

    def parse_all(self, content: str, source_path: Path | None = None) -> list[CanonicalDetection]:
        """Parse all stanzas in a savedsearches.conf and return a list."""
        stanzas = _parse_conf_stanzas(content)
        return [_stanza_to_detection(s, source_path) for s in stanzas]
