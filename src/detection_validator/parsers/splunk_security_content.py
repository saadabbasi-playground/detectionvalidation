"""
Splunk Security Content (SSC) parser.

Splunk security_content YAML files follow the layout::

    name: Suspicious PowerShell via Run Services
    id: 6f1d5f60-...
    version: 3
    description: |
      Detects ...
    search: >-
      | tstats `security_content_summariesonly` count ...
    how_to_implement: ...
    known_false_positives: ...
    tags:
      analytic_story:
        - Malicious PowerShell
      mitre_attack_id:
        - T1059.001
      cve:
        - CVE-2021-34527
      kill_chain_phases:
        - Exploitation
      required_fields:
        - process_name
      security_domain: endpoint

The distinguishing features are the ``search`` field and the ``tags`` block
with ``mitre_attack_id`` and ``analytic_story``.
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
from detection_validator.parsers.splunk import _logsource_from_spl, _spl_to_logic, _infer_cim_models

_SSC_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MED,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}

_DOMAIN_PLATFORM: dict[str, list[Platform]] = {
    "endpoint": [Platform.WINDOWS, Platform.LINUX, Platform.MACOS],
    "network": [Platform.NETWORK],
    "cloud": [Platform.CLOUD],
    "containers": [Platform.CONTAINERS],
}


def _parse_ssc_yaml(content: str, source_path: Path | None) -> dict:
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ParseError("Invalid SSC YAML", path=source_path, cause=exc) from exc
    if not isinstance(data, dict):
        raise ParseError("SSC YAML did not produce a mapping", path=source_path)
    return data


def _ssc_severity(data: dict) -> Severity:
    # SSC uses tags.severity or top-level severity
    tags = data.get("tags") or {}
    severity_raw = (
        data.get("severity")
        or (tags.get("severity") if isinstance(tags, dict) else None)
        or ""
    )
    return _SSC_SEVERITY_MAP.get(str(severity_raw).strip().lower(), Severity.MED)


def _ssc_platforms(data: dict) -> list[Platform]:
    tags = data.get("tags") or {}
    if not isinstance(tags, dict):
        return []
    domain = (tags.get("security_domain") or "endpoint").lower()
    return _DOMAIN_PLATFORM.get(domain, [Platform.WINDOWS])


class SplunkSecurityContentParser(BaseParser):
    """
    Parse Splunk Security Content YAML detection files.

    SSC files are distinguished from plain Sigma rules by having a ``search``
    key (SPL query) and a ``tags`` block with ``mitre_attack_id``.
    """

    name = "splunk_security_content"
    supported_extensions = (".yml", ".yaml")

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() not in (".yml", ".yaml"):
            return False
        return self._sniff(file_path, ["search:", "mitre_attack_id:"])

    def parse(
        self,
        content: str,
        source_path: Path | None = None,
    ) -> CanonicalDetection:
        data = _parse_ssc_yaml(content, source_path)

        name = data.get("name") or (source_path.stem if source_path else "ssc_rule")
        rule_id = str(data.get("id") or uuid4())
        description = data.get("description", "")
        version = str(data.get("version", "1"))

        spl = (data.get("search") or "").strip()
        if not spl:
            warnings.warn(
                f"SSC rule has empty 'search' field [{source_path}]",
                PartialParseWarning,
                stacklevel=2,
            )

        severity = _ssc_severity(data)
        platforms = _ssc_platforms(data)

        tags_block = data.get("tags") or {}
        if isinstance(tags_block, dict):
            mitre_ids: list[str] = tags_block.get("mitre_attack_id") or []
            cve_raw: list[str] = tags_block.get("cve") or []
            required_fields: list[str] = tags_block.get("required_fields") or []
            analytic_story: list[str] = tags_block.get("analytic_story") or []
            kill_chain: list[str] = tags_block.get("kill_chain_phases") or []
        else:
            mitre_ids = []
            cve_raw = []
            required_fields = []
            analytic_story = []
            kill_chain = []

        # Supplement with text scanning
        combined = f"{name} {description} {spl}"
        all_techs = list(dict.fromkeys(
            mitre_ids + extract_techniques_from_text(combined)
        ))
        all_cves = list(dict.fromkeys(
            cve_raw + extract_cves_from_text(combined)
        ))

        tactic = kill_chain[0].lower().replace(" ", "-") if kill_chain else "unknown"

        raw_spl, field_refs, conditions = _spl_to_logic(spl)
        if required_fields:
            field_refs = list(dict.fromkeys(field_refs + required_fields))

        logic = make_detection_logic(
            raw=raw_spl or "(empty)",
            language="spl",
            field_refs=field_refs,
            conditions=conditions,
        )

        log_sources = _logsource_from_spl(spl)
        cim_models = _infer_cim_models(spl)

        fp_raw = data.get("known_false_positives") or ""
        false_positives = [fp_raw.strip()] if fp_raw.strip() and fp_raw.strip().lower() != "none" else []

        author_raw = data.get("author") or ""
        author: str | list[str] = (
            [a.strip() for a in author_raw.split(",")]
            if isinstance(author_raw, str) and "," in author_raw
            else author_raw or "unknown"
        )

        remaining_tags = [s for s in analytic_story]

        return CanonicalDetection(
            id=rule_id,
            name=name,
            description=description,
            author=author,
            version=version,
            severity=severity,
            source_format=DetectionFormat.SPLUNK_SPL,
            platforms=platforms,
            tags=remaining_tags,
            detection_logic=logic,
            log_sources=log_sources,
            mitre_techniques=techniques_to_models(all_techs, tactic=tactic),
            cve_references=cves_to_models(all_cves),
            data_components=required_fields,
            false_positive_notes=false_positives,
            cim_models=cim_models,
            validation_status=ValidationStatus.UNTESTED,
        )
