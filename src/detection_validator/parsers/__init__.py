"""
Detection rule parsers.

Provides a :class:`ParserRegistry` that auto-detects the format of any
detection rule file and returns a normalised :class:`CanonicalDetection`.

Supported formats:
  - Sigma YAML (``detection:`` + ``logsource:``)
  - Splunk SPL / savedsearches.conf
  - KQL — bare queries and Sentinel YAML analytics rules
  - YARA / YARA-L  (``.yar``, ``.yara``)
  - Elastic EQL / detection-rules  (``.toml``, ``.json``)
  - Splunk Security Content YAML  (``search:`` + ``mitre_attack_id:``)
  - Generic YAML fallback (configurable field mapping)
"""

from __future__ import annotations

from detection_validator.parsers.base import (
    BaseParser,
    ParseError,
    PartialParseWarning,
    normalise_cve_id,
    normalise_severity,
    normalise_technique_id,
)
from detection_validator.parsers.elastic_eql import ElasticEQLParser
from detection_validator.parsers.generic_yaml import GenericYAMLParser
from detection_validator.parsers.kql import KQLParser
from detection_validator.parsers.registry import ParserRegistry
from detection_validator.parsers.sigma import SigmaParser
from detection_validator.parsers.splunk import SplunkParser
from detection_validator.parsers.splunk_security_content import SplunkSecurityContentParser
from detection_validator.parsers.yara_parser import YARAParser

__all__ = [
    "BaseParser",
    "ParseError",
    "PartialParseWarning",
    "ParserRegistry",
    "SigmaParser",
    "SplunkParser",
    "KQLParser",
    "YARAParser",
    "ElasticEQLParser",
    "SplunkSecurityContentParser",
    "GenericYAMLParser",
    "normalise_technique_id",
    "normalise_cve_id",
    "normalise_severity",
]
