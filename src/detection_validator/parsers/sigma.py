"""
Sigma rule parser — converts Sigma YAML to CanonicalDetection.

Uses pySigma when available; falls back to plain YAML parsing for field
extraction without conversion.
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

try:
    from sigma.rule import SigmaRule
    from sigma.types import SigmaDetectionItem

    HAS_SIGMA = True
except ImportError:  # pragma: no cover
    HAS_SIGMA = False

# Sigma level → Severity
_SIGMA_LEVEL_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MED,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "unknown": Severity.MED,
}

# Sigma logsource product/service → Platform
_PRODUCT_PLATFORM_MAP: dict[str, Platform] = {
    "windows": Platform.WINDOWS,
    "linux": Platform.LINUX,
    "macos": Platform.MACOS,
    "aws": Platform.CLOUD,
    "azure": Platform.CLOUD,
    "gcp": Platform.CLOUD,
    "okta": Platform.CLOUD,
    "m365": Platform.CLOUD,
    "office365": Platform.CLOUD,
    "kubernetes": Platform.CONTAINERS,
    "docker": Platform.CONTAINERS,
}


def _parse_sigma_yaml(content: str) -> dict[str, Any]:
    """Load and return raw Sigma YAML as a dict; raises ParseError on invalid YAML."""
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ParseError("Invalid YAML in Sigma rule", cause=exc) from exc
    if not isinstance(data, dict):
        raise ParseError("Sigma rule YAML did not produce a mapping")
    return data


def _extract_field_refs_from_detection(detection: dict[str, Any]) -> list[str]:
    """Recursively collect field name keys from a Sigma detection dict."""
    fields: list[str] = []
    keywords = {"condition", "keywords"}
    for key, val in detection.items():
        if key in keywords:
            continue
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    fields.extend(_extract_field_refs_from_detection(item))
        elif isinstance(val, dict):
            fields.extend(val.keys())
        else:
            fields.append(key)
    return fields


def _sigma_level_to_severity(level: str | None) -> Severity:
    if level is None:
        return Severity.MED
    return _SIGMA_LEVEL_MAP.get(level.strip().lower(), Severity.MED)


def _logsource_to_log_source(logsource: dict[str, Any]) -> LogSource:
    product = logsource.get("product", "")
    service = logsource.get("service", "")
    category = logsource.get("category", "")
    return LogSource(
        product=product or None,
        service=service or None,
        category=category or None,
    )


def _logsource_to_platforms(logsource: dict[str, Any]) -> list[Platform]:
    product = (logsource.get("product") or "").lower()
    platform = _PRODUCT_PLATFORM_MAP.get(product)
    return [platform] if platform else []


def _parse_tags(
    tags: list[str],
) -> tuple[list[str], list[str], list[str], list[str]]:
    """
    Split Sigma tags into:
      technique_ids, cve_ids, cim_models, remaining_tags
    """
    technique_ids: list[str] = []
    cve_ids: list[str] = []
    cim_models: list[str] = []
    remaining: list[str] = []

    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower.startswith("attack.t") or re.match(r"attack\.t\d{4}", tag_lower):
            # e.g. attack.t1059.001 or attack.T1059
            raw = tag[len("attack.") :] if tag_lower.startswith("attack.") else tag
            technique_ids.append(raw)
        elif tag_lower.startswith("cve.") or tag_lower.startswith("cve-"):
            cve_ids.append(tag)
        elif tag_lower.startswith("cim."):
            cim_models.append(tag[4:])  # strip "cim." prefix
        else:
            remaining.append(tag)

    return technique_ids, cve_ids, cim_models, remaining


def _extract_tactic_from_tags(tags: list[str]) -> str:
    """Return the first tactic slug found in tags, or 'unknown'."""
    for tag in tags:
        tag_lower = tag.lower()
        if re.match(r"attack\.ta\d{4}", tag_lower):
            # e.g. attack.ta0002 — skip; we want the name form
            continue
        if tag_lower.startswith("attack.") and not re.match(r"attack\.t\d{4}", tag_lower):
            slug = tag_lower[len("attack."):]
            return slug
    return "unknown"


class SigmaParser(BaseParser):
    """
    Parse Sigma rules from YAML files or strings.

    Uses pySigma library when installed; falls back to plain YAML parsing
    for field extraction only (no format conversion).
    """

    name = "sigma"
    supported_extensions = (".yml", ".yaml")

    def can_parse(self, file_path: Path) -> bool:
        if file_path.suffix.lower() not in self.supported_extensions:
            return False
        return self._sniff(file_path, ["detection:", "logsource:"], required_all=True)

    def parse(
        self,
        content: str,
        source_path: Path | None = None,
    ) -> CanonicalDetection:
        data = _parse_sigma_yaml(content)

        # ── Mandatory field check ───────────────────────────────────────────
        title = data.get("title") or data.get("name", "")
        if not title:
            warnings.warn(
                f"Sigma rule missing 'title' field [{source_path}]",
                PartialParseWarning,
                stacklevel=2,
            )
            title = source_path.stem if source_path else "unknown"

        # ── IDs ─────────────────────────────────────────────────────────────
        rule_id = data.get("id") or str(uuid4())
        if not re.match(r"^[0-9a-f-]{36}$", rule_id, re.IGNORECASE):
            rule_id = str(uuid4())

        # ── Metadata ────────────────────────────────────────────────────────
        description = data.get("description", "")
        author_raw = data.get("author", "")
        author: str | list[str] = (
            [a.strip() for a in author_raw.split(",")]
            if isinstance(author_raw, str) and "," in author_raw
            else author_raw or "unknown"
        )
        version = str(data.get("version", "1.0"))
        status = data.get("status", "")

        # ── Severity ────────────────────────────────────────────────────────
        severity = _sigma_level_to_severity(data.get("level"))

        # ── Tags ────────────────────────────────────────────────────────────
        tags_raw: list[str] = data.get("tags") or []
        technique_ids, cve_ids, cim_models, remaining_tags = _parse_tags(tags_raw)
        tactic = _extract_tactic_from_tags(tags_raw)

        # Also scan description and title for stray technique IDs
        extra_techs = extract_techniques_from_text(f"{title} {description}")
        all_tech_ids = list(dict.fromkeys(technique_ids + extra_techs))

        extra_cves = extract_cves_from_text(f"{title} {description}")
        all_cve_ids = list(dict.fromkeys(cve_ids + extra_cves))

        mitre_techniques = techniques_to_models(all_tech_ids, tactic=tactic)
        cve_references = cves_to_models(all_cve_ids)

        # ── Log source ──────────────────────────────────────────────────────
        logsource_raw: dict[str, Any] = data.get("logsource") or {}
        log_sources = [_logsource_to_log_source(logsource_raw)] if logsource_raw else []
        platforms = _logsource_to_platforms(logsource_raw)

        # ── Detection logic ─────────────────────────────────────────────────
        detection_raw: dict[str, Any] = data.get("detection") or {}
        raw_detection_str = yaml.dump({"detection": detection_raw}, default_flow_style=False)
        field_refs = _extract_field_refs_from_detection(detection_raw)
        condition = detection_raw.get("condition", "")
        conditions = [condition] if condition else []

        logic = make_detection_logic(
            raw=raw_detection_str,
            language="sigma",
            field_refs=field_refs,
            conditions=conditions,
        )

        # ── False positives ─────────────────────────────────────────────────
        fp_raw = data.get("falsepositives") or []
        false_positives = [str(fp) for fp in fp_raw if fp and str(fp).strip().lower() != "none"]

        # ── Data model (data_model / data_component) ─────────────────────────
        data_components: list[str] = []
        if logsource_raw.get("category"):
            data_components.append(logsource_raw["category"])

        return CanonicalDetection(
            id=rule_id,
            name=title,
            description=description,
            author=author,
            version=version,
            severity=severity,
            source_format=DetectionFormat.SIGMA,
            platforms=platforms,
            tags=remaining_tags,
            detection_logic=logic,
            log_sources=log_sources,
            mitre_techniques=mitre_techniques,
            cve_references=cve_references,
            data_components=data_components,
            false_positive_notes=false_positives,
            cim_models=cim_models,
            validation_status=ValidationStatus.UNTESTED,
        )
