"""
detection-validator — multi-SIEM detection validation platform.

Validates detection rules across Splunk, OpenSearch, Elastic, Microsoft Sentinel,
Google Chronicle, and Wazuh by running Atomic Red Team and synthetic attack scenarios,
mapping coverage to MITRE ATT&CK, and reporting gaps.
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "detection-validator contributors"


def health_check() -> None:
    """Lightweight health probe used by container HEALTHCHECK instructions."""
    # Verify core sub-packages are importable
    from detection_validator import parsers, normalizer, validator  # noqa: F401

    print("ok")
