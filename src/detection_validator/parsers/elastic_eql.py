"""
Elastic detection rule parser — handles TOML and JSON rule formats.

TOML rules follow the Elastic detection-rules repo layout::

    [rule]
    name = "Suspicious Process Execution"
    description = "Detects ..."
    severity = "high"
    type = "eql"
    query = '''
    process where process.name == "cmd.exe"
    '''
    [rule.threat]
    [[rule.threat.technique]]
    id = "T1059"

JSON rules (exported from Kibana) have the same fields under a ``rule`` key.
"""

from __future__ import annotations

import json
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
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

_ELASTIC_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MED,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}

# EQL event category → Platform
_EQL_CATEGORY_PLATFORM: dict[str, Platform] = {
    "process": Platform.WINDOWS,
    "file": Platform.WINDOWS,
    "registry": Platform.WINDOWS,
    "network": Platform.NETWORK,
    "authentication": Platform.CLOUD,
    "cloud": Platform.CLOUD,
}

# EQL top-level keywords for field extraction
_EQL_FIELD_RE = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)\s*(?:==|!=|like|regex|:)", re.IGNORECASE)
_EQL_CATEGORY_RE = re.compile(r"^\s*(\w+)\s+where\b", re.MULTILINE)
_EQL_SEQUENCE_RE = re.compile(r"^\s*sequence\b", re.MULTILINE | re.IGNORECASE)


def _parse_toml_content(content: str, source_path: Path | None) -> dict:
    if tomllib is None:
        raise ParseError(
            "TOML parsing requires Python 3.11+ (tomllib) or the 'tomli' package",
            path=source_path,
        )
    try:
        return tomllib.loads(content)
    except Exception as exc:
        raise ParseError(f"Invalid TOML: {exc}", path=source_path, cause=exc) from exc


def _parse_json_content(content: str, source_path: Path | None) -> dict:
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid JSON: {exc}", path=source_path, cause=exc) from exc


def _extract_elastic_rule(data: dict) -> dict:
    """Normalise Kibana export (may wrap rule under 'rule' key)."""
    if "rule" in data and isinstance(data["rule"], dict):
        return data["rule"]
    return data


def _extract_threat_info(rule: dict) -> tuple[list[str], str]:
    """Return (technique_ids, first_tactic_slug) from rule.threat[]."""
    technique_ids: list[str] = []
    tactic = "unknown"

    threats = rule.get("threat") or []
    if not isinstance(threats, list):
        threats = [threats]

    for threat in threats:
        if not isinstance(threat, dict):
            continue
        tactic_obj = threat.get("tactic") or {}
        if isinstance(tactic_obj, dict):
            tactic_name = tactic_obj.get("name") or tactic_obj.get("id") or ""
            if tactic_name and tactic == "unknown":
                tactic = tactic_name.lower().replace(" ", "-")

        for tech in threat.get("technique") or []:
            if not isinstance(tech, dict):
                continue
            tech_id = tech.get("id") or ""
            if tech_id:
                technique_ids.append(tech_id)
            for sub in tech.get("subtechnique") or []:
                sub_id = sub.get("id") if isinstance(sub, dict) else ""
                if sub_id:
                    technique_ids.append(sub_id)

    return technique_ids, tactic


def _extract_eql_field_refs(query: str) -> list[str]:
    return list(dict.fromkeys(m.group(1) for m in _EQL_FIELD_RE.finditer(query)))


def _eql_to_platforms(query: str) -> list[Platform]:
    platforms: set[Platform] = set()
    for m in _EQL_CATEGORY_RE.finditer(query):
        cat = m.group(1).lower()
        if cat in _EQL_CATEGORY_PLATFORM:
            platforms.add(_EQL_CATEGORY_PLATFORM[cat])
    return list(platforms)


def _is_sequence(query: str) -> bool:
    return bool(_EQL_SEQUENCE_RE.search(query))


def _rule_dict_to_detection(rule: dict, source_path: Path | None) -> CanonicalDetection:
    rule_id = str(rule.get("rule_id") or rule.get("id") or uuid4())
    name = rule.get("name") or (source_path.stem if source_path else "elastic_rule")
    description = rule.get("description", "")
    severity = _ELASTIC_SEVERITY.get((rule.get("severity") or "").lower(), Severity.MED)
    rule_type = rule.get("type", "query")

    query = rule.get("query") or rule.get("eql_query", "")

    technique_ids, tactic = _extract_threat_info(rule)
    extra_techs = extract_techniques_from_text(f"{description} {query}")
    all_techs = list(dict.fromkeys(technique_ids + extra_techs))

    cve_ids = extract_cves_from_text(f"{description} {query}")
    if "cve" in rule:
        cve_ids = list(dict.fromkeys(cve_ids + [rule["cve"]]))

    language = rule_type if rule_type in ("eql", "esql", "kql", "lucene") else "eql"

    field_refs = _extract_eql_field_refs(query) if query else []
    condition_prefix = "sequence" if _is_sequence(query) else ""
    first_line = query.strip().splitlines()[0] if query.strip() else ""
    conditions = [c for c in [condition_prefix, first_line] if c]

    logic = make_detection_logic(
        raw=query,
        language=language,
        field_refs=field_refs,
        conditions=conditions,
    )

    platforms = _eql_to_platforms(query) if query else []

    # Data sources / index patterns
    index_patterns: list[str] = rule.get("index") or []
    log_sources = [LogSource(service=idx) for idx in index_patterns[:5]]
    data_components = list(index_patterns[:5])

    author_raw = rule.get("author") or []
    if isinstance(author_raw, list):
        author: str | list[str] = author_raw if len(author_raw) > 1 else (author_raw[0] if author_raw else "unknown")
    else:
        author = str(author_raw) or "unknown"

    tags: list[str] = []
    for t in (rule.get("tags") or []):
        if not re.match(r"^T\d{4}", str(t)):
            tags.append(str(t))

    return CanonicalDetection(
        id=rule_id,
        name=name,
        description=description,
        author=author,
        version=str(rule.get("version", "1")),
        severity=severity,
        source_format=DetectionFormat.ELASTIC_EQL,
        platforms=platforms,
        tags=tags,
        detection_logic=logic,
        log_sources=log_sources,
        mitre_techniques=techniques_to_models(all_techs, tactic=tactic),
        cve_references=cves_to_models(cve_ids),
        data_components=data_components,
        false_positive_notes=list(rule.get("false_positives") or []),
        cim_models=[],
        validation_status=ValidationStatus.UNTESTED,
    )


class ElasticEQLParser(BaseParser):
    """
    Parse Elastic detection rules from TOML or JSON files.

    Handles both EQL and other Elastic rule types (query, threshold, etc.).
    """

    name = "elastic_eql"
    supported_extensions = (".toml", ".json")

    def can_parse(self, file_path: Path) -> bool:
        suffix = file_path.suffix.lower()
        if suffix == ".toml":
            return self._sniff(file_path, ["[rule]", "query ="])
        if suffix == ".json":
            return self._sniff(file_path, ['"rule_id"', '"query"'])
        return False

    def parse(
        self,
        content: str,
        source_path: Path | None = None,
    ) -> CanonicalDetection:
        suffix = source_path.suffix.lower() if source_path else ""

        if suffix == ".toml":
            data = _parse_toml_content(content, source_path)
        elif suffix == ".json":
            data = _parse_json_content(content, source_path)
        elif content.lstrip().startswith("{"):
            data = _parse_json_content(content, source_path)
        elif content.lstrip().startswith("["):
            data = _parse_toml_content(content, source_path)
        else:
            raise ParseError(
                "ElasticEQLParser: cannot determine format (expected TOML or JSON)",
                path=source_path,
            )

        rule = _extract_elastic_rule(data)
        if not rule.get("name") and not rule.get("query"):
            raise ParseError("Elastic rule has no 'name' or 'query'", path=source_path)

        return _rule_dict_to_detection(rule, source_path)
