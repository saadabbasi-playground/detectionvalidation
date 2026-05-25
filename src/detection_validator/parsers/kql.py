"""
KQL parser — handles both bare .kql files and Sentinel YAML analytics rules.

Sentinel YAML analytics rules look like::

    id: <guid>
    name: Suspicious PowerShell
    description: |
      Detects ...
    severity: High
    requiredDataConnectors:
      - connectorId: SecurityEvents
    tactics:
      - Execution
    relevantTechniques:
      - T1059.001
    query: |
      SecurityEvent
      | where EventID == 4688

Bare .kql files contain a single KQL query (may be multi-line).
"""

from __future__ import annotations

import re
import warnings
from pathlib import Path
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

# Sentinel YAML severity → canonical Severity
_SENTINEL_SEVERITY: dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MED,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}

# ATT&CK tactic name → slug
_TACTIC_NAME_TO_SLUG: dict[str, str] = {
    "initialaccess": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilegeescalation": "privilege-escalation",
    "defenseevasion": "defense-evasion",
    "credentialaccess": "credential-access",
    "discovery": "discovery",
    "lateralmovement": "lateral-movement",
    "collection": "collection",
    "commandandcontrol": "command-and-control",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "reconnaissance": "reconnaissance",
    "resourcedevelopment": "resource-development",
}

# KQL table names → LogSource hints
_TABLE_LOGSOURCE: dict[str, tuple[str, str]] = {
    "securityevent": ("windows", "Security"),
    "windowsevent": ("windows", "Windows"),
    "sysmon": ("windows", "Sysmon"),
    "processcreate": ("windows", "Sysmon"),
    "networkcommunication": ("windows", "Sysmon"),
    "deviceprocessevents": ("windows", "Defender"),
    "devicenetworkevents": ("windows", "Defender"),
    "devicefilecreatedevents": ("windows", "Defender"),
    "auditlogs": ("azure", "AuditLogs"),
    "signinlogs": ("azure", "SignInLogs"),
    "azureactivity": ("azure", "AzureActivity"),
    "commonalertsschema": ("azure", "Sentinel"),
    "dnsevents": ("network", "DNS"),
    "networksessions": ("network", "NetworkSessions"),
}


def _tactic_to_slug(raw: str) -> str:
    key = re.sub(r"[^a-z]", "", raw.lower())
    return _TACTIC_NAME_TO_SLUG.get(key, raw.lower())


def _extract_kql_tables(query: str) -> list[str]:
    """Return KQL table names referenced in the query (first identifier per line)."""
    tables: list[str] = []
    for line in query.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("|") or stripped.startswith("//"):
            continue
        m = re.match(r"^([A-Za-z][A-Za-z0-9_]*)", stripped)
        if m and m.group(1).lower() not in {"let", "where", "project", "extend", "summarize"}:
            tables.append(m.group(1))
    return list(dict.fromkeys(tables))


def _kql_tables_to_log_sources(tables: list[str]) -> list[LogSource]:
    sources: list[LogSource] = []
    for table in tables:
        key = table.lower()
        if key in _TABLE_LOGSOURCE:
            product, service = _TABLE_LOGSOURCE[key]
            sources.append(LogSource(product=product, service=service, category=table))
        else:
            sources.append(LogSource(category=table))
    return sources


def _kql_tables_to_platforms(tables: list[str]) -> list[Platform]:
    platforms: set[Platform] = set()
    for table in tables:
        key = table.lower()
        if key in _TABLE_LOGSOURCE:
            product, _ = _TABLE_LOGSOURCE[key]
            if product == "windows":
                platforms.add(Platform.WINDOWS)
            elif product in ("azure",):
                platforms.add(Platform.CLOUD)
            elif product == "network":
                platforms.add(Platform.NETWORK)
    return list(platforms)


def _extract_kql_field_refs(query: str) -> list[str]:
    """Extract field names from `| where`, `| project`, `| extend` clauses."""
    fields: list[str] = []
    project_re = re.compile(r"\|\s*project\s+([\w,\s]+?)(?:\||$)", re.IGNORECASE | re.DOTALL)
    extend_re = re.compile(r"\|\s*extend\s+(\w+)\s*=", re.IGNORECASE)
    where_field_re = re.compile(r"\b([A-Z][A-Za-z0-9]+)\s*(?:==|!=|=~|!~|in|has|contains|startswith|matches)", re.IGNORECASE)

    for m in project_re.finditer(query):
        fields.extend(f.strip() for f in m.group(1).split(","))
    for m in extend_re.finditer(query):
        fields.append(m.group(1))
    for m in where_field_re.finditer(query):
        fields.append(m.group(1))

    return list(dict.fromkeys(fields))


def _parse_sentinel_yaml(content: str) -> dict:
    """Load Sentinel analytics rule YAML; raise ParseError on bad YAML."""
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ParseError("Invalid YAML in Sentinel analytics rule", cause=exc) from exc
    if not isinstance(data, dict):
        raise ParseError("Sentinel YAML did not produce a mapping")
    return data


def _is_sentinel_yaml(content: str) -> bool:
    """Heuristic: file has both 'query:' and ('severity:' or 'tactics:')."""
    return "query:" in content and ("severity:" in content or "tactics:" in content)


def _sentinel_yaml_to_detection(data: dict, source_path: Path | None) -> CanonicalDetection:
    rule_id = str(data.get("id") or uuid4())
    name = data.get("name") or (source_path.stem if source_path else "kql_rule")
    description = data.get("description", "")
    severity_raw = data.get("severity", "")
    severity = _SENTINEL_SEVERITY.get(severity_raw.lower() if severity_raw else "", Severity.MED)

    query: str = data.get("query", "")

    # Tactics & techniques
    tactics_raw: list[str] = data.get("tactics") or []
    tactic_slug = _tactic_to_slug(tactics_raw[0]) if tactics_raw else "unknown"
    techniques_raw: list[str] = data.get("relevantTechniques") or data.get("techniques") or []
    technique_ids = extract_techniques_from_text(" ".join(techniques_raw + [description, query]))
    cve_ids = extract_cves_from_text(f"{description} {query}")

    mitre_techniques = techniques_to_models(technique_ids, tactic=tactic_slug)
    cve_references = cves_to_models(cve_ids)

    tables = _extract_kql_tables(query)
    log_sources = _kql_tables_to_log_sources(tables)
    platforms = _kql_tables_to_platforms(tables)
    field_refs = _extract_kql_field_refs(query)

    logic = make_detection_logic(
        raw=query,
        language="kql",
        field_refs=field_refs,
        conditions=[query.strip().splitlines()[0]] if query.strip() else [],
    )

    connectors = data.get("requiredDataConnectors") or []
    data_components = [c.get("connectorId", "") for c in connectors if isinstance(c, dict)]

    author = data.get("author") or data.get("metadata", {}).get("author", "unknown")

    return CanonicalDetection(
        id=rule_id,
        name=name,
        description=description,
        author=author,
        version=str(data.get("version", "1.0")),
        severity=severity,
        source_format=DetectionFormat.KQL,
        platforms=platforms or [Platform.CLOUD],
        tags=[],
        detection_logic=logic,
        log_sources=log_sources,
        mitre_techniques=mitre_techniques,
        cve_references=cve_references,
        data_components=data_components,
        false_positive_notes=[],
        cim_models=[],
        validation_status=ValidationStatus.UNTESTED,
    )


def _bare_kql_to_detection(query: str, source_path: Path | None) -> CanonicalDetection:
    name = source_path.stem if source_path else "kql_rule"
    tables = _extract_kql_tables(query)
    log_sources = _kql_tables_to_log_sources(tables)
    platforms = _kql_tables_to_platforms(tables)
    field_refs = _extract_kql_field_refs(query)
    technique_ids = extract_techniques_from_text(query)
    cve_ids = extract_cves_from_text(query)

    logic = make_detection_logic(
        raw=query,
        language="kql",
        field_refs=field_refs,
        conditions=[query.strip().splitlines()[0]] if query.strip() else [],
    )

    return CanonicalDetection(
        id=str(uuid4()),
        name=name,
        description="",
        author="unknown",
        version="1.0",
        severity=Severity.MED,
        source_format=DetectionFormat.KQL,
        platforms=platforms or [],
        tags=[],
        detection_logic=logic,
        log_sources=log_sources,
        mitre_techniques=techniques_to_models(technique_ids),
        cve_references=cves_to_models(cve_ids),
        data_components=[],
        false_positive_notes=[],
        cim_models=[],
        validation_status=ValidationStatus.UNTESTED,
    )


class KQLParser(BaseParser):
    """
    Parse KQL detection rules from:

    - Sentinel YAML analytics rules (``.yml``/``.yaml`` with ``query:`` key)
    - Bare KQL query files (``.kql``)
    """

    name = "kql"
    supported_extensions = (".kql", ".yml", ".yaml")

    def can_parse(self, file_path: Path) -> bool:
        suffix = file_path.suffix.lower()
        if suffix == ".kql":
            return True
        if suffix in (".yml", ".yaml"):
            return self._sniff(file_path, ["query:", "severity:"])
        return False

    def parse(
        self,
        content: str,
        source_path: Path | None = None,
    ) -> CanonicalDetection:
        suffix = source_path.suffix.lower() if source_path else ""

        if suffix == ".kql":
            return _bare_kql_to_detection(content.strip(), source_path)

        if _is_sentinel_yaml(content):
            data = _parse_sentinel_yaml(content)
            return _sentinel_yaml_to_detection(data, source_path)

        # Fall back to treating it as a bare KQL query
        warnings.warn(
            f"KQL file does not look like Sentinel YAML; treating as bare query [{source_path}]",
            PartialParseWarning,
            stacklevel=2,
        )
        return _bare_kql_to_detection(content.strip(), source_path)
